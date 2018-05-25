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
import qualified Data.ByteString.Base64  as B64
import           Data.ByteString.Char8   as BC
import           Data.ByteString.Char8   (pack, splitAt, unpack)
import qualified Data.ByteString.Lazy    as LB
import           Data.Maybe              (fromJust)
import           GHC.Word                (Word8)
import           Security.Auth.Principal
import           System.Entropy          (getEntropy)

-- | Contains the encrypted data from 'Principal'.
newtype Token = Token { tokenBytes :: B.ByteString }

instance Show Token where
  show t =
    BC.unpack (B64.encode $ tokenBytes t)

-- | Used to encrypt/decrypt tokens.
data EncryptionKey = EncryptionKey
  { keyBytes :: B.ByteString
  , aes128   :: AES128 }

-- | Random bytes to seed individual encryptions.
data InitVector = InitVector
  { ivBytes :: B.ByteString
  , iv128   :: IV AES128 }

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

mkAES128 :: B.ByteString -> Either String AES128
mkAES128 key =
  onCryptoFailure (Left . show) Right (cipherInit key)

mkEncryptionKey :: B.ByteString -> Either String EncryptionKey
mkEncryptionKey x =
  EncryptionKey x <$> mkAES128 x

-- | Make an encryption key from a base64 encoded string
mkEncryptionKey' :: String -> Either String EncryptionKey
mkEncryptionKey' s = do
  let bs64 = BC.pack s
  bs <- B64.decode bs64
  mkEncryptionKey bs

mkInitVector :: B.ByteString -> Either String InitVector
mkInitVector bs =
  let maybeIV = makeIV bs :: Maybe (IV AES128)
  in case maybeIV of
    Just iv -> Right (InitVector bs iv)
    Nothing -> Left "Failed to make an IV from the given byte string."

generateInitVector :: IO InitVector
generateInitVector = do
  bs <- getEntropy ivSize
  let maybeIv = makeIV bs
  pure $ InitVector bs (fromJust maybeIv)

generateStringKey :: IO String
generateStringKey =
  BC.unpack . B64.encode <$> getEntropy keySize

mkToken :: EncryptionKey -> InitVector -> Principal -> Token
mkToken (EncryptionKey _ aes) (InitVector ivBs iv) p =
  Token $ B.concat [cipherText, ivBs]
  where
    plainText  = LB.toStrict (encode p)
    iv'        = fromJust $ makeIV iv
    cipherText = cbcEncrypt aes iv' (pad plainText)

mkToken' :: EncryptionKey -> Principal -> IO Token
mkToken' key p = do
  iv <- generateInitVector
  pure $ mkToken key iv p

readToken :: EncryptionKey -> Token -> Either String Principal
readToken (EncryptionKey _ aes) (Token token) = do
  let (cipherText, iv) = B.splitAt (B.length token - ivSize) token
  let plainText = unpad (cbcDecrypt aes (fromJust $ makeIV iv) cipherText)
  case decode (LB.fromStrict plainText) of
    Just p  -> Right p
    Nothing -> Left "Failed to read token. Wrong encryption key perhaps?"
