{-# LANGUAGE BangPatterns #-}
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
import qualified Data.ByteString.Char8 as BS
import qualified Data.HashMap.Strict as M
import Data.Monoid
import qualified Data.Text as T
import Data.Proxy
import Database.Neo4j as Neo
import Database.Neo4j.Transactional.Cypher as TC
import Network.Wai
import Network.Wai.Handler.Warp
import Servant

import Prelude hiding (product)

import Debug.Trace

data Cve = Cve
    { cveId :: T.Text
    , summary :: T.Text
    , product :: T.Text -- in cpe form...?
    , cvssScore:: T.Text
    } deriving (Eq, Show)

$(deriveJSON defaultOptions ''Cve)

type API =
    "cves" :> ReqBody '[JSON] [Cve] :> Post '[JSON] T.Text
 --   :<|> "cves" :> Get '[JSON] [Cve]

newtype App a = App { runApp :: ReaderT Neo.Connection IO a }
    deriving (Monad, Functor, Applicative, MonadReader Neo.Connection, MonadIO)


startApp :: IO ()
startApp = do
    !conn <- Neo.newAuthConnection "192.168.1.3" 7474 ("neo4j", "zantetsuken")
    traceShow "Started..." $ run 8080 $ app conn

app :: Neo.Connection -> Application
app conn = serve readerAPI (readerServer conn)

api :: Proxy API
api = Proxy

readerServerT :: ServerT API App
readerServerT = postCves -- :<|> getCves

runAppT :: Neo.Connection -> App a -> EitherT ServantErr IO a
runAppT conn action = liftIO $ runReaderT (runApp action) conn

readerServer :: Neo.Connection -> Server API
readerServer conn = enter (Nat $ (runAppT conn)) readerServerT

readerAPI :: Proxy API
readerAPI = Proxy


-- | Post to /cves
postCves :: [Cve] -> App T.Text
postCves cs = do
    conn <- ask
    liftIO $ createCve conn cs

createCve :: Neo.Connection -> [Cve] -> IO T.Text
createCve conn cves = do
    eitherResults <- n4jTransaction conn $ do
        mapM cveNodeCypher cves-- TC.cypher "CREATE (fudge : FUDGE {cveId:{cveId}})" $ M.fromList [(T.pack "cveId", TC.newparam ("CVE-2016-1283" :: T.Text))]
    return $ case eitherResults of
        Right _ -> "Success"
        Left e  -> fst e
  where
    cve2map cve = M.fromList [
        (T.pack "cveId", TC.newparam (cveId cve))
        , (T.pack "summary", TC.newparam (summary cve))
        , (T.pack "product", TC.newparam (product cve))
        , (T.pack "cvssScore", TC.newparam (cvssScore cve))
        ]
    cveNodeCypher cve = TC.cypher ("CREATE ( n:CVE { cveId : {cveId}, summary : {summary}, " <>
        "product : {product}, cvssScore : {cvssScore} } )") (cve2map cve)


{-
getCves :: App [Cves]
getCves = flip
-}

-- Helpers
n4jTransaction :: Neo.Connection -> Transaction a -> IO (Either TC.TransError a)
n4jTransaction conn action = flip Neo.runNeo4j conn $ do
    TC.runTransaction $ do
        action


{-
-- Custom monad for this server
connReaderToEither' :: forall a. Neo.Hostname -> Neo.Port -> Reader Neo.Connection a -> EitherT ServantErr IO a
connReaderToEither' host port r = do
    conn <- newAuthConnection host port ("tets","test")
    return (lift $ runReader r conn)
-}
