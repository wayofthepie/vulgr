{-# Language FlexibleContexts #-}
{-# Language OverloadedStrings #-}

module Main where

import Control.Monad.IO.Class
import Control.Monad.Trans.Resource
import Control.Monad.Trans.Either
import Data.Conduit
import Data.List
import Data.List.Split
import Data.Proxy
import qualified Data.Text as T
import Servant.API.Alternative
import Servant.Client
import Servant.Common.BaseUrl
import Text.XML
import Text.XML.Cursor
import Text.XML.Stream.Parse hiding (content)

import Prelude hiding (readFile)

import Vulgr.API


main :: IO ()
main = putStrLn "cli"

getCve :<|> postCves :<|> postCpes = client api (BaseUrl Http "localhost" 8080)

loadCpesFromFile :: IO [Either ServantError T.Text]
loadCpesFromFile = do
    maybeCpes <- runResourceT $ parseFile def "/var/tmp/official-cpe-dictionary_v2.2-20141029-004153.xml" $$ parseCpeList
    case maybeCpes of
        Just cpes -> sequence $ fmap (runEitherT . postCpes) $ chunksOf 550 cpes
        Nothing   -> error "error!"


-- | Parse nvd details
parseNvdXml :: FilePath -> IO ([Cve])
parseNvdXml fp = do
    doc <- readFile def fp
    let cursor = fromDocument doc
    return $ cves cursor
  where
    cves cur = cur $/ element "{http://scap.nist.gov/schema/feed/vulnerability/2.0}entry" >=>
        \c -> zipWith4 Cve
            (attribute "id" c)  -- cveId
            (c $/ element "{http://scap.nist.gov/schema/vulnerability/0.4}summary"
                &/ content) -- summary
            (c $/ element "{http://scap.nist.gov/schema/vulnerability/0.4}vulnerable-software-list"
                &/ element "{http://scap.nist.gov/schema/vulnerability/0.4}product"
                &/ content) -- product
            (c $/ element "{http://scap.nist.gov/schema/vulnerability/0.4}cvss"
                &/ element "{http://scap.nist.gov/schema/cvss-v2/0.2}base_metrics"
                &/ element "{http://scap.nist.gov/schema/cvss-v2/0.2}score"
                &/ content) -- score


