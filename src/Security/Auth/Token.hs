module Security.Auth.Token (
  EncryptionKey,
  generateInitVector,
  generateStringKey,
  InitVector,
  mkEncryptionKey,
  mkEncryptionKey',
  mkInitVector,
  mkToken,
  mkToken',
  readToken,
  Token
  ) where

import           Crypto.Cipher.AES       (AES128)
import           Crypto.Cipher.Types     (Cipher (cipherInit), IV, cbcDecrypt,
                                          cbcEncrypt, cipherInit, makeIV)
import           Crypto.Error            (CryptoFailable, onCryptoFailure)
import           Data.Aeson              (decode, encode)
import qualified Data.ByteString         as B
import           Data.ByteString.Char8   as BC
import           Data.ByteString.Char8   (pack, splitAt, unpack)
import qualified Data.ByteString.Lazy    as LB
import           Data.Maybe              (fromJust)
import           GHC.Word                (Word8)
import           Security.Auth.Principal
import           System.Entropy          (getEntropy)

-- | Contains the encrypted data from 'Principal'.
newtype Token = Token { tokenBytes :: B.ByteString }

-- | Used to encrypt/decrypt tokens.
newtype EncryptionKey = EncryptionKey { aes128 :: AES128 }

-- | Random bytes to seed individual encryptions.
newtype InitVector = InitVector { ivBytes :: B.ByteString }

blockSize = 16
ivSize    = 16
keySize   = 16

word8ToInt :: Word8 -> Int
word8ToInt = fromIntegral . toInteger

word8FromInt :: Int -> Word8
word8FromInt = fromInteger . toInteger

-- Append bytes (PKCS7 style) to the plaintext to match the requirement regarding input lengt of the encryption algorithm.
pad :: B.ByteString -> B.ByteString
pad bs =
  B.concat [bs, padWords]
  where
      remainder = B.length bs `mod` blockSize
      pads      = if remainder == 0 then blockSize else blockSize - remainder
      padWord   = word8FromInt pads
      padWords  = B.replicate pads padWord

-- Undo the work of 'pad'
unpad :: B.ByteString -> B.ByteString
unpad bs =
    B.take (B.length bs - pads) bs
    where
      pads = word8ToInt (B.last bs)

mkEncryptionKey :: B.ByteString -> Either String EncryptionKey
mkEncryptionKey key =
  onCryptoFailure (Left . show) (Right . EncryptionKey) (cipherInit key)

mkEncryptionKey' :: String -> Either String EncryptionKey
mkEncryptionKey' s =
  onCryptoFailure (Left . show) (Right . EncryptionKey) cipherOrFail
  where
    bs           = BC.pack s
    cipherOrFail = cipherInit bs

mkInitVector :: B.ByteString -> Either String InitVector
mkInitVector bs =
  let maybeIV = makeIV bs :: Maybe (IV AES128)
  in case maybeIV of
    Just _  -> Right (InitVector bs)
    Nothing -> Left "Failed to make an IV from the given byte string."

generateInitVector :: IO InitVector
generateInitVector =
  InitVector <$> getEntropy ivSize

generateStringKey :: IO String
generateStringKey =
  BC.unpack <$> getEntropy keySize

mkToken :: EncryptionKey -> InitVector -> Principal -> Token
mkToken (EncryptionKey aes) (InitVector iv) p =
  Token $ B.concat [cipherText, iv]
  where
    plainText  = LB.toStrict (encode p)
    iv'        = fromJust $ makeIV iv
    cipherText = cbcEncrypt aes iv' (pad plainText)

mkToken' :: EncryptionKey -> Principal -> IO Token
mkToken' key p = do
  iv <- generateInitVector
  pure $ mkToken key iv p

readToken :: EncryptionKey -> Token -> Either String Principal
readToken (EncryptionKey aes) (Token token) = do
  let (cipherText, iv) = B.splitAt (B.length token - ivSize) token
  let plainText = unpad (cbcDecrypt aes (fromJust $ makeIV iv) cipherText)
  case decode (LB.fromStrict plainText) of
    Just p  -> Right p
    Nothing -> Left "Failed to read token. Wrong encryption key perhaps?"
