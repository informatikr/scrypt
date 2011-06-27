{-# LANGUAGE ForeignFunctionInterface, RecordWildCards, NamedFieldPuns #-}

-- |Scrypt is a sequential memory-hard key derivation function. This module
--  provides bindings to a fast C implementation of scrypt, written by Colin
--  Percival. For more information see <http://www.tarsnap.com/scrypt.html>.
module Crypto.Scrypt ( 
    -- *Parameters to the @scrypt@ function
     ScryptParams, params
    -- * The @scrypt@ key derivation function
    , Pass(..), Salt(..), PassHash(..)
    , scrypt, scrypt', getSalt
    ) where

import Control.Applicative ((<$>))
import Data.ByteString (ByteString, useAsCStringLen, packCStringLen, hGet)
import Data.Maybe
import Foreign
import Foreign.C
import System.IO


newtype Pass = Pass { unPass :: ByteString } deriving (Show)
newtype Salt = Salt { unSalt :: ByteString } deriving (Show)
newtype PassHash = PassHash { unHash :: ByteString } deriving (Show,Eq)

-- |Encapsulates the three tuning parameters to the 'scrypt' function: @N@,
--  @r@ and @p@. The parameters affect running time and memory usage:
--
--  /Memory usage/ is approximately @128*r*N@ bytes. Note that the
--  'params' function takes @log_2(N)@ as a parameter. As an example, the
--  default parameters used by 'scrypt''
--  
--  @   log_2(N) = 14, r = 8 and p = 1@
--
--  lead to 'scrypt' using @128 * 8 * 2^14 = 16M@ bytes of memory.
--
--  /Running time/ is proportional to all of @N@, @r@ and @p@. However
--  @p@ only as an insignificant influence on memory usage an can thus be
--  used to tune the running time of 'scrypt'.
--
data ScryptParams = Params { logN, r, p, bufLen :: Integer}

instance Show ScryptParams where
    show Params{..} = concat [ "ScryptParams "
        , "{ logN=", show logN
        , ", r="   , show r
        , ", p="   , show p
        , " }"
        ]

-- |Constructor function for the 'ScryptParams' data type
params :: Integer
       -- ^ @log_2(N)@. Scrypt's @N@ parameter must be a power of two greater
       -- than one, thus it's logarithm to base two must be greater than zero. 
       -> Integer
       -- ^ The parameter @r@, must be greater than zero.
       -> Integer
       -- ^ The parameter @p@, must be greater than zero. @r@ and @p@
       --   must satisfy @r*p < 2^30@.
       -> Maybe ScryptParams
       -- ^ Returns 'Just' the parameter object for valid arguments,
       --   otherwise 'Nothing'.
params logN r p | valid     = Just ps
                | otherwise = Nothing
  where
    ps    = Params { logN, r, p, bufLen = 64 }
    valid = and [ logN > 0, r > 0, p > 0
                , r*p < 2^(30 :: Int)
                , bufLen ps <= 2^(32 :: Int)-1 * 32
                ]

-- |Calculates a 64-byte hash from the given password, salt and parameters.
scrypt :: ScryptParams -> Salt -> Pass -> PassHash
scrypt Params{..} (Salt salt) (Pass pass) =
    PassHash <$> unsafePerformIO $
        useAsCStringLen salt $ \(saltPtr, saltLen) ->
        useAsCStringLen pass $ \(passPtr, passLen) ->
        allocaBytes (fromIntegral bufLen) $ \bufPtr -> do
            throwErrnoIfMinus1_ "crypto_scrypt" $ crypto_scrypt
                (castPtr passPtr) (fromIntegral passLen)
                (castPtr saltPtr) (fromIntegral saltLen)
                (2^logN) (fromIntegral r) (fromIntegral p)
                bufPtr (fromIntegral bufLen)
            packCStringLen (castPtr bufPtr, fromIntegral bufLen)

foreign import ccall unsafe crypto_scrypt
    :: Ptr Word8 -> CSize         -- password
    -> Ptr Word8 -> CSize         -- salt
    -> Word64 -> Word32 -> Word32 -- N, r, p
    -> Ptr Word8 -> CSize         -- result buffer
    -> IO CInt

-- |Note the prime symbol (\'). Calls 'scrypt' with default parameters as
--  recommended in the scrypt paper:
--
--  @   N = 2^14, r = 8, p = 1 @
--
--  Equivalent to @'scrypt' ('fromJust' ('params' 14 8 1))@.
scrypt' :: Salt -> Pass -> PassHash
scrypt' = scrypt $ fromJust (params 14 8 1)

-- |Reads a 32-byte random salt from @\/dev\/urandom@.
getSalt :: IO Salt
getSalt = Salt <$> withBinaryFile "/dev/urandom" ReadMode (flip hGet 32)
