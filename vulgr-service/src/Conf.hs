{-# LANGUAGE DeriveGeneric #-}

module Conf (
    Conf (Conf)
    , neo4jHost
    , neo4jPort
    , neo4jUser
    , neo4jPassword
    , readConfFile
    ) where

import qualified Data.Text as T
import qualified Data.Text as T
import Data.Yaml
import GHC.Generics
import System.FilePath ()

data Conf = Conf
    { n4jHost     :: T.Text
    , n4jPort     :: Int
    , n4jUser     :: T.Text
    , n4jPassword :: T.Text
    , vListenPort :: Int
    } deriving (Eq, Generic, Show)

neo4jHost = n4jHost
neo4jPort = n4jPort
neo4jUser = n4jUser
neo4jPassword = n4jPassword
vulgrListenPort = vListenPort

instance FromJSON Conf

readConfFile :: FilePath -> IO (Either ParseException Conf)
readConfFile filep = decodeFileEither filep
