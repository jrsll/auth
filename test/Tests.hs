module Main where

import           Control.Monad           (when)
import           Data.Time               (UTCTime (..), secondsToDiffTime)
import           Data.Time.Calendar      (Day (..))
import           Security.Auth.Principal
import           Security.Auth.Token
import           System.Exit             (exitFailure)
import           Test.HUnit

testTokenRoundtrip strKey iv = TestCase $
    case roundtripResult of
        Right p' -> assertEqual "principal altered during roundtrip" p p'
        Left err -> assertFailure $ "token could not be read: " ++ err
    where
        expires         = UTCTime (ModifiedJulianDay 0) (secondsToDiffTime 0)
        p               = Principal expires [("userId", "123")]
        roundtripResult = do key <- mkEncryptionKey' strKey
                             let token = mkToken key iv p
                             readToken key token

main :: IO ()
main = do
    strKey <- generateStringKey
    iv     <- generateInitVector
    counts <- runTestTT $ testTokenRoundtrip strKey iv
    when (failures counts > 0 || errors counts > 0) exitFailure
    pure ()
