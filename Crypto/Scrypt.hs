{-# LANGUAGE ForeignFunctionInterface, OverloadedStrings,
    RecordWildCards, NamedFieldPuns #-}

-- |Scrypt is a sequential memory-hard key derivation function. This module
--  provides bindings to a fast C implementation of scrypt, written by Colin
--  Percival. For more information see <http://www.tarsnap.com/scrypt.html>.
module Crypto.Scrypt ( 
    -- *Parameters to the @scrypt@ function
     ScryptParams, scryptParams
    -- * Password Storage
    , EncryptedPass(..), encryptPass, verifyPass
    -- * Low-level bindings to the @scrypt@ key derivation function
    , Pass(..), Salt(..), PassHash(..)
    , scrypt, scrypt'
    ) where

import Control.Applicative
import Control.Monad
import Data.ByteString.Base64 (encode)
import qualified Data.ByteString.Base64 as Base64
import Data.ByteString.Char8 hiding (map, concat)
import Data.Maybe
import Foreign
import Foreign.C
import System.IO


newtype Pass          = Pass     { unPass :: ByteString } deriving (Show, Eq)
newtype Salt          = Salt     { unSalt :: ByteString } deriving (Show, Eq)
newtype PassHash      = PassHash { unHash :: ByteString } deriving (Show,Eq)
newtype EncryptedPass =
    EncryptedPass { unEncryptedPass  :: ByteString } deriving (Show, Eq)

------------------------------------------------------------------------------
-- Scrypt Parameters
--

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
data ScryptParams = Params { logN, r, p, bufLen :: Integer} deriving (Eq)

instance Show ScryptParams where
    show Params{..} = concat [ "ScryptParams "
        , "{ logN=", show logN
        , ", r="   , show r
        , ", p="   , show p
        , " }"
        ]

-- |Constructor function for the 'ScryptParams' data type
scryptParams
    :: Integer
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
scryptParams logN r p | valid     = Just ps
                      | otherwise = Nothing
  where
    ps    = Params { logN, r, p, bufLen = 64 }
    valid = and [ logN > 0, r > 0, p > 0
                , r*p < 2^(30 :: Int)
                , bufLen ps <= 2^(32 :: Int)-1 * 32
                ]

------------------------------------------------------------------------------
-- Password Storage API
--
encryptPass :: ScryptParams -> Pass -> IO EncryptedPass
encryptPass params pass = do
    salt <- Salt <$> withBinaryFile "/dev/urandom" ReadMode (`hGet` 32)
    return $ combine params salt (scrypt params salt pass)

verifyPass
    :: ScryptParams
    -> Pass
    -> EncryptedPass
    -> (Bool, Maybe EncryptedPass)
verifyPass newParams candidate encrypted =
    maybe (False, Nothing) verify (separate encrypted)
  where
    verify (params,salt,hash) =
        let valid   = scrypt params salt candidate == hash
            newHash = scrypt newParams salt candidate
            newEncr = if not valid || params == newParams
                        then Nothing
                        else Just (combine newParams salt newHash)
        in (valid, newEncr)

combine :: ScryptParams -> Salt -> PassHash -> EncryptedPass
combine Params{..} (Salt salt) (PassHash passHash) =
    EncryptedPass $ intercalate "|"
        [showBS logN, showBS r, showBS p, encode salt, encode passHash]
  where
    showBS = pack . show

separate :: EncryptedPass -> Maybe (ScryptParams, Salt, PassHash)
separate = go . split '|' . unEncryptedPass
  where
    go [logN', r', p', salt', hash'] = do
        [salt,hash] <- sequence (map decode [salt', hash'])
        params      <- join $
            scryptParams <$> readI logN' <*> readI r' <*> readI p'        
        return (params, Salt salt, PassHash hash)
    go _    = Nothing

    readI x = fst <$> readInteger x
    decode  = either (const Nothing) Just . Base64.decode

------------------------------------------------------------------------------
-- Low-level API
--

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
scrypt' = scrypt $ fromJust (scryptParams 14 8 1)
