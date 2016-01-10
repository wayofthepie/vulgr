{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.Monad.Reader
import Control.Monad.Trans.Either
import Database.Neo4j as Neo
import Network.Wai
import Network.Wai.Handler.Warp
import Servant

import Lib

main :: IO ()
main = startApp


startApp :: IO ()
startApp = do
    conn <- Neo.newAuthConnection "192.168.1.3" 7474 ("neo4j", "zantetsuken")
    run 8080 $ app conn

app :: Neo.Connection -> Application
app conn = serve api (readerServer conn)

readerServerT :: ServerT API App
readerServerT = getCve :<|> postCves

runAppT :: Neo.Connection -> App a -> EitherT ServantErr IO a
runAppT conn action = liftIO $ runReaderT (runApp action) conn

readerServer :: Neo.Connection -> Server API
readerServer conn = enter (Nat $ (runAppT conn)) readerServerT


