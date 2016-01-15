{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DataKinds       #-}
{-# LANGUAGE GeneralizedNewtypeDeriving  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes       #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeOperators   #-}

module Vulgr.API
    ( module Vulgr.Cve
    , module Vulgr.CPE.Types
    , API
    , App (..)
    , api
    , app
    , getCve
    , postCves
    ) where

import Control.Lens.Operators
import Control.Monad.Reader
import Control.Monad.Trans.Either
import Data.Aeson
import Data.Aeson.Lens
import qualified Data.HashMap.Strict as M
import Data.Maybe
import Data.Monoid
import qualified Data.Text as T
import Data.Proxy
import Database.Neo4j as Neo
import Database.Neo4j.Transactional.Cypher as TC
import Network.Wai
import Servant

import Prelude hiding (product)

import Debug.Trace

import Vulgr.Cve
import Vulgr.CPE.Types
import Vulgr.Neo4j


type API =
    "cves" :> Capture "cveId" T.Text :> Get '[JSON] [Cve]
    :<|> "cves" :> ReqBody '[JSON] [Cve] :> Post '[JSON] T.Text
    :<|> "cpes" :> ReqBody '[JSON] [CpeItem] :> Post '[JSON] T.Text

newtype App a = App { runApp :: ReaderT Neo.Connection IO a }
    deriving (Monad, Functor, Applicative, MonadReader Neo.Connection, MonadIO)

api :: Proxy API
api = Proxy

app :: Neo.Connection -> Application
app conn = serve api (readerServer conn)

readerServerT :: ServerT API App
readerServerT =
    getCve
    :<|> postCves
    :<|> postCpes

runAppT :: Neo.Connection -> App a -> EitherT ServantErr IO a
runAppT conn action = liftIO $ runReaderT (runApp action) conn

readerServer :: Neo.Connection -> Server API
readerServer conn = enter (Nat (runAppT conn)) readerServerT


-- | Post to /cves
postCves :: [Cve] -> App T.Text
postCves cs = traceShow "Called post..." $ do
    conn <- ask
    liftIO $ createCve conn cs

createCve :: Neo.Connection -> [Cve] -> IO T.Text
createCve conn cves = do
    eitherResults <- n4jTransaction conn $ mapM uniqCveNodeCypher cves
    return $ case eitherResults of
        Right _ -> "Success"
        Left e  -> fst e

uniqCveNodeCypher :: Cve -> TC.Transaction TC.Result
uniqCveNodeCypher cve =
    TC.cypher ("MERGE ( n:CVE { cveId : {cveId}, summary : {summary}, " <>
        "product : {product}, cvssScore : {cvssScore} } )") (traceShow (cve2map cve) $ cve2map cve)
  where
    cve2map cve = M.fromList [
        (T.pack "cveId", TC.newparam (cveId cve))
        , (T.pack "summary", TC.newparam (summary cve))
        , (T.pack "product", TC.newparam (product cve))
        , (T.pack "cvssScore", TC.newparam (cvssScore cve))
        ]


-- | Get the nodes corresponding to a Cve ID.
-- Note that this can be more than one node, Cve ID's are enforced
-- through this API as a unique constraint however it is not
-- enforced in Neo4j, and I cannot find a way to do this...
getCve :: T.Text -> App [Cve]
getCve cveid = do
    conn <- ask
    eitherResult <- liftIO $ n4jTransaction conn $
        TC.cypher "MATCH (n: CVE {cveId : {cveId}}) RETURN n" $ M.fromList [("cveId", TC.newparam cveid)]
    case eitherResult of
        Right result -> return (jsonToCve $ vals result)
        Left e -> return [] -- TODO : This function should return an Either.
  where
    -- Turn a list of lists of Value's into a list of Cve's.
    jsonToCve :: [[Value]] -> [Cve]
    jsonToCve lvals = catMaybes . concat $
        fmap (fmap (\obj -> obj ^? _JSON :: Maybe Cve)) lvals


-- | Post to /cpes.
postCpes :: [CpeItem] -> App T.Text
postCpes cpes = traceShow "Post cpes ..." $ do
    conn <- ask
    liftIO $ createCpes conn cpes

createCpes :: Neo.Connection -> [CpeItem] -> IO T.Text
createCpes conn cpes = do
    eitherResults <- n4jTransaction conn $ mapM uniqCpeNodeCypher cpes
    return $ case eitherResults of
        Right _ -> "Success"
        Left e  -> fst e

uniqCpeNodeCypher :: CpeItem -> TC.Transaction TC.Result
uniqCpeNodeCypher cpe =
    TC.cypher ("MERGE ( n:CPE { cpeName : {cpeName}, title : {cpeTitle} } )") (cpe2map cpe)
  where
    cpe2map cpe = M.fromList [
        (T.pack "cpeName", TC.newparam (cpeItemName cpe))
        , (T.pack "cpeTitle", TC.newparam (cpeItemTitle cpe))
        ]


