{-# Language OverloadedStrings #-}

module Main where

import Data.List
import Data.Proxy
import Servant.API.Alternative
import Servant.Client
import Servant.Common.BaseUrl
import Text.XML
import Text.XML.Cursor

import Prelude hiding (readFile)

import Lib (API, Cve(..))


main :: IO ()
main = putStrLn "cli"

api :: Proxy API
api = Proxy

getCve :<|> postCves = client api (BaseUrl Http "localhost" 8080)



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


