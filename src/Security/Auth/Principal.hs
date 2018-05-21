{-# LANGUAGE DeriveGeneric #-}

module Security.Auth.Principal where

import           Data.Aeson   (FromJSON, ToJSON (toEncoding), decode,
                               defaultOptions, encode, genericToEncoding)
import           Data.Time    (UTCTime)
import           GHC.Generics

-- | Role

data Role =
    Admin
  | Guest
  deriving (Generic, Show, Eq)

-- | Claim

data Claim =
    UserId String
  | Role Role
  deriving (Generic, Show, Eq)

-- | Principal

data Principal = Principal {
    expires :: UTCTime
  , claims  :: [Claim]
  } deriving (Generic, Show, Eq)


-- Instances

instance FromJSON Principal
instance ToJSON Principal where
  toEncoding = genericToEncoding defaultOptions

instance FromJSON Claim
instance ToJSON Claim where
  toEncoding = genericToEncoding defaultOptions

instance FromJSON Role
instance ToJSON Role where
  toEncoding = genericToEncoding defaultOptions
