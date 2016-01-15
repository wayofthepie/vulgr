{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.Monad.Reader
import Database.Neo4j as Neo
import qualified Data.Text.Encoding as T
import Data.Yaml
import Network.Wai
import Network.Wai.Handler.Warp
import Servant
import System.Environment

import Conf

import Vulgr.API

main :: IO ()
main = do
    args <- getArgs
    case args of
        [filePath] -> startOrFail filePath
        _          -> error "Please specify location of conf file."

  where
    startOrFail filePath = do
        eitherConf <- readConfFile filePath
        case eitherConf of
            Right conf   -> startApp conf
            Left pexcept -> error (prettyPrintParseException pexcept)

-- | Start vulgr using the give config.
startApp :: Conf -> IO ()
startApp (Conf host port user password listenPort) = do
    conn <- Neo.newAuthConnection (txt2Bs host) port (txt2Bs user, txt2Bs password)
    run listenPort $ app conn
  where
    txt2Bs = T.encodeUtf8

