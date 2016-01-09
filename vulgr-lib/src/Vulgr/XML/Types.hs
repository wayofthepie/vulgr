{-# LANGUAGE
    DeriveGeneric
    #-}

module Vulgr.XML.Types where

import qualified Data.Text as T
import Data.Time



data NvdEntry = NvdEntry
    { entryVulnConf         :: VulnConf
    , entryVulnSoftList     :: VulnSoftList
    , entryCveId            :: CveId
    , entryPublishedTime    :: LocalTime
    , entryLastModifiedTime :: LocalTime
    , entryCvss             :: Cvss
    , entryCwe              :: Cwe
    , entryReferences       :: References
    , entrySummary          :: T.Text
    } deriving (Eq, Show)


-- Represents the vulnerable-configuration tag.
data VulnConf = VulnConf
    { vulnConfId          :: T.Text
    , vulnConfLogicalTest :: LogicalTest
    } deriving (Eq, Show)

data LogicalTest = LogicalTest
    { logicalTestOp       :: T.Text
    , logicalTestNegate   :: Bool
    , logicalTestFactRefs :: [FactRef]
    } deriving (Eq, Show)

data FactRef = FactRef
    { factRefName :: T.Text
    } deriving (Eq, Show)


data VulnSoftList = VulnSoftList
    { vulnSoftList :: [Product]
    } deriving (Eq, Show)

data Product = Product
    { product :: T.Text
    } deriving (Eq, Show)

data CveId = CveId
    { cveId :: T.Text
    } deriving (Eq, Show)

data Cvss = Cvss
    { cvssBaseMetrics :: CvssBaseMetrics
    } deriving (Eq, Show)

-- TODO : Investigate these, can likely type them
data CvssBaseMetrics = CvssBaseMetrics
    { cvssBmScore :: T.Text
    , cvssBmAccessVector :: T.Text
    , cvssBmAccessComplexity :: T.Text
    , cvssBmConfidentiality :: T.Text
    , cvssBmIntegImpact :: T.Text
    , cvssBmAvailImpact :: T.Text
    , cvssBmSource :: T.Text
    , cvssBmGeneratedAt :: T.Text
    } deriving (Eq, Show)

data Cwe = Cwe
    { cweId :: T.Text
    } deriving (Eq, Show)

data References = References
    { refsLang :: T.Text
    , refsRefType :: T.Text
    , refsSource :: T.Text
    , refsRefs :: [Reference]
    } deriving (Eq, Show)

data Reference = Reference
    { refHref :: T.Text
    , refLang :: T.Text
    } deriving (Eq, Show)
