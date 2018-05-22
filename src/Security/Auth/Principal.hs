{-# LANGUAGE DeriveGeneric #-}

module Security.Auth.Principal where

import           Data.Aeson   (FromJSON, ToJSON (toEncoding), defaultOptions,
                               genericToEncoding)
import           Data.Time    (UTCTime)
import           GHC.Generics

-- | Type representing the contents of an auth token.
data Principal = Principal {
    expires :: UTCTime            -- ^ The time at which the principal ceases to be valid.
  , claims  :: [(String, String)] -- ^ Properties used to determine permissions for the authenticated user.
  } deriving (Generic, Show, Eq)

instance FromJSON Principal

instance ToJSON Principal where
  toEncoding = genericToEncoding defaultOptions
