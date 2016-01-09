{-# LANGUAGE DataKinds       #-}
{-# LANGUAGE GeneralizedNewtypeDeriving  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes       #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeOperators   #-}
module Lib
    ( startApp
    ) where

import Control.Monad.Reader
import Control.Monad.Trans (lift)
import Control.Monad.Trans.Either
import Data.Aeson
import Data.Aeson.TH
import Data.ByteString.Char8 as BS
import qualified Data.HashMap.Strict as M
import qualified Data.Text as T
import Data.Proxy
import Database.Neo4j as Neo
import Database.Neo4j.Transactional.Cypher as T
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

type API = "components" :> ReqBody '[JSON] [Component] :> Post '[JSON] [T.Text]

newtype App a = App { runApp :: ReaderT Neo.Connection IO a }
    deriving (Monad, Functor, Applicative, MonadReader Neo.Connection, MonadIO)


startApp :: IO ()
startApp = do
    conn <- Neo.newAuthConnection "192.168.1.3" 7474 ("", "")
    run 8080 $ app conn

app :: Neo.Connection -> Application
app conn = serve readerAPI (readerServer conn)

api :: Proxy API
api = Proxy

readerServerT :: ServerT API App
readerServerT = postComponents

runAppT :: Neo.Connection -> App a -> EitherT ServantErr IO a
runAppT conn action = liftIO $ runReaderT (runApp action) conn

readerServer :: Neo.Connection -> Server API
readerServer conn = enter (Nat $ (runAppT conn)) readerServerT

readerAPI :: Proxy API
readerAPI = Proxy

postComponents :: [Component] -> App [T.Text]
postComponents cs = do
    conn <- ask
    liftIO $ createComponent conn

createComponent :: Neo.Connection -> IO [T.Text]
createComponent conn = flip Neo.runNeo4j conn $ do
    res <- T.runTransaction $ do
        result <- T.cypher "CREATE (fudge : FUDGE {cveId:{cveId}})" $ M.fromList [(T.pack "cveId", T.newparam ("CVE-2016-1283" :: T.Text))]
        return result
    case res of
        Right r -> return $ T.cols r
        Left _  -> return $ [T.pack "ERROR!!"]

{-
-- Custom monad for this server
connReaderToEither' :: forall a. Neo.Hostname -> Neo.Port -> Reader Neo.Connection a -> EitherT ServantErr IO a
connReaderToEither' host port r = do
    conn <- newAuthConnection host port ("tets","test")
    return (lift $ runReader r conn)
-}
