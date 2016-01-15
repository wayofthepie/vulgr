{-# LANGUAGE TemplateHaskell #-}

module Vulgr.Cve where

import Data.Aeson.TH
import qualified Data.Text as T

data Cve = Cve
    { cveId :: T.Text
    , summary :: T.Text
    , product :: T.Text -- in cpe form...?
    , cvssScore:: T.Text
    } deriving (Eq, Show)

$(deriveJSON defaultOptions ''Cve)


