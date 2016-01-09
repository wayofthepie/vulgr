{-# LANGUAGE DataKinds       #-}
{-# LANGUAGE RankNTypes       #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeOperators   #-}
module Lib
    ( startApp
    ) where

import Control.Monad.Trans.Either
import Control.Monad.Reader
import Data.Aeson
import Data.Aeson.TH
import Data.ByteString.Char8 as BS
import qualified Data.Text as T
import Data.Proxy
import Database.Neo4j as Neo
import Network.Wai
import Network.Wai.Handler.Warp
import Servant

import Debug.Trace

data Component = Component
    { summary :: T.Text
    , product :: T.Text -- in cpe form...?
    , cvssScore:: T.Text
    } deriving (Eq, Show)

$(deriveJSON defaultOptions ''Component)

type ReaderAPI = "components" :> ReqBody '[JSON] [Component] :> Post '[JSON] [Component]

startApp :: IO ()
startApp = run 8080 app

app :: Application
app = serve readerAPI readerServer

api :: Proxy ReaderAPI
api = Proxy

readerServerT :: ServerT ReaderAPI (Reader String)
readerServerT = postComponents

readerServer :: Server ReaderAPI
readerServer = enter readerToEither readerServerT

postComponents :: [Component] -> Reader String [Component]
postComponents cs = do
    s <- ask
    return (traceShow s $ cs)

readerToEither :: Reader String :~> EitherT ServantErr IO
readerToEither = Nat readerToEither'

readerToEither' :: forall a. Reader String a -> EitherT ServantErr IO a
readerToEither' r = return (runReader r "hi")

readerAPI :: Proxy ReaderAPI
readerAPI = Proxy


{-
-- Custom monad for this server
connReaderToEither' :: forall a. Neo.Hostname -> Neo.Port -> Reader Neo.Connection a -> EitherT ServantErr IO a
connReaderToEither' host port r = do
    conn <- newAuthConnection host port ("tets","test")
    return (lift $ runReader r conn)
-}
