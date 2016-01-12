{-# LANGUAGE DeriveGeneric #-}
module Conf where

import qualified Data.Text as T
import Data.Yaml
import GHC.Generics
import System.FilePath (FilePath)

data Conf = Conf
    { neo4jHost      :: T.Text
    , neo4jPort      :: Int
    , neo4jUser      :: T.Text
    , neo4jPassword :: T.Text
    } deriving (Eq, Generic, Show)

instance FromJSON Conf

parseConfFile :: FilePath -> IO (Either ParseException Conf)
parseConfFile filep = decodeFileEither filep
