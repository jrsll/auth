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
import           Security.Auth.Principal
import           System.Entropy          (getEntropy)

newtype Token = Token { tokenBytes :: B.ByteString }

newtype EncryptionKey = EncryptionKey { aes128 :: AES128 }

newtype InitVector = InitVector { ivBytes :: B.ByteString }

blockSize = 16
ivSize    = 16
keySize   = 16
padEnd    = B.pack [1]
padWord   = 0

-- Add a sequence of bytes to the sequence to match the required input lengt to the encryption algorithm.
pad :: B.ByteString -> B.ByteString
pad bs =
  B.concat [padWords, padEnd, bs]
  where
      rest     = B.length bs `mod` blockSize
      n        = 15 - rest
      padWords = B.replicate n padWord

-- Undo the work of 'pad'
unpad :: B.ByteString -> B.ByteString
unpad bs =
  B.tail $ B.dropWhile (== padWord) bs

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

mkToken'  :: EncryptionKey -> Principal -> IO Token
mkToken' key p = do
  iv <- generateInitVector
  pure $ mkToken key iv p

readToken :: EncryptionKey -> Token -> Either String Principal
readToken (EncryptionKey aes) (Token token) = do
  let (cipherText, iv) = B.splitAt (B.length token - ivSize) token
  (InitVector iv') <- mkInitVector iv
  let plainText = unpad (cbcDecrypt aes (fromJust $ makeIV iv) cipherText)
  case decode (LB.fromStrict plainText) of
    Just p  -> Right p
    Nothing -> Left "Failed to decipher token."
