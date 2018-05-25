module Main where

import           Control.Monad           (when)
import           Data.Time.Clock         (getCurrentTime)
import           Security.Auth.Principal
import           Security.Auth.Token
import           System.Exit             (exitFailure)
import           Test.HUnit

testTokenRoundtrip time strKey iv = TestCase $
    case roundtripResult of
        Right p' -> assertEqual "principal altered during roundtrip" p p'
        Left err -> assertFailure $ "token could not be read: " ++ err
    where
        expires         = time
        p               = Principal expires [("userId", "123")]
        roundtripResult = do key <- mkEncryptionKey' strKey
                             let token = mkToken key iv p
                             readToken key token

main :: IO ()
main = do
    time   <- getCurrentTime
    strKey <- generateStringKey
    iv     <- generateInitVector
    counts <- runTestTT $ testTokenRoundtrip time strKey iv
    when (failures counts > 0 || errors counts > 0) exitFailure
    pure ()
