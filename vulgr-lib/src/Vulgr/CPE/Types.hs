{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
module Vulgr.CPE.Types where

import Control.Monad.Catch
import Data.Aeson
import Data.Conduit
import qualified Data.Text as T
import Data.Time.LocalTime
import Data.XML.Types
import GHC.Generics
import Text.XML.Stream.Parse

import Debug.Trace

data CpeList = CpeList
    { generator :: CpeListGenerator
    , cpeItems  :: [CpeItem]
    } deriving (Eq, Generic, Show)

instance FromJSON CpeList
instance ToJSON CpeList

data CpeListGenerator = CpeListGenerator
    { cpeListGenProductName    :: T.Text
    , cpeListGenProductVersion :: T.Text
    , cpeListGenSchemaVersion  :: T.Text
    , cpeListGenTimestamp      :: LocalTime
    } deriving (Eq, Generic, Show)

instance FromJSON CpeListGenerator
instance ToJSON CpeListGenerator

data CpeItem = CpeItem
    { cpeItemName  :: T.Text
    , cpeItemTitle :: [T.Text]
    , cpeItemMeta  :: CpeItemMeta
    , cpeItemRefs  :: Maybe [CpeItemReference]
    } deriving (Eq, Generic, Show)

instance FromJSON CpeItem
instance ToJSON CpeItem

data CpeItemMeta = CpeItemMeta
    { cpeItemMetaNvdId  :: T.Text
    , cpeItemMetaStatus :: T.Text
    , cpeItemMetaModDate:: T.Text
    } deriving (Eq, Generic, Show)

instance FromJSON CpeItemMeta
instance ToJSON CpeItemMeta

data CpeItemReference = CpeItemReference
    { cpeItemRefHref :: T.Text -- TODO: type safe URL!
    , cpeItemRefVal  :: T.Text
    } deriving (Eq, Generic, Show)

instance FromJSON CpeItemReference
instance ToJSON CpeItemReference


-- | Parse a cpe-list.
parseCpeList :: MonadThrow m => Consumer Event m (Maybe [CpeItem])
parseCpeList = tagIgnoreAttrs "{http://cpe.mitre.org/dictionary/2.0}cpe-list" $ do
    _ <- ignoreTreeName "{http://cpe.mitre.org/dictionary/2.0}generator"
    many parseCpeItem


-- | Parse a cpe-item.
-- This parser is completely hacked together from looking at a single cpe dictionary.
-- TODO : Update to correspond to the full cpe dictionary schema.
parseCpeItem :: MonadThrow m => Consumer Event m (Maybe CpeItem)
parseCpeItem = tagName "{http://cpe.mitre.org/dictionary/2.0}cpe-item" cpeItemAttrParser $ \name -> do
    title <- many $ tagName "{http://cpe.mitre.org/dictionary/2.0}title" ignoreAttrs $ \_ -> content
    _     <- ignoreTreeName "{http://cpe.mitre.org/dictionary/2.0}references"
    _     <- ignoreTreeName "{http://cpe.mitre.org/dictionary/2.0}notes"
    _     <- ignoreTreeName "{http://cpe.mitre.org/dictionary/2.0}check"
    meta  <- force "no meta:item-metadata tag" $
        tagName "{http://scap.nist.gov/schema/cpe-dictionary-metadata/0.2}item-metadata" (metaDataAttrParser) $
            \(nvdId, status, modDate) -> do
                return $ CpeItemMeta nvdId status modDate
    return $ CpeItem name title meta Nothing
  where
    -- Only parse name for now
    cpeItemAttrParser = requireAttr "name"
        <* ignoreAttrs
    metaDataAttrParser = (,,)
        <$> requireAttr "nvd-id"
        <*> requireAttr "status"
        <*> requireAttr "modification-date"
        <*  ignoreAttrs





