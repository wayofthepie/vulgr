module Main where

import Data.Proxy
import Servant.Client
import Servant.Common.BaseUrl

import Lib (API)


main :: IO ()
main = putStrLn "cli"

api :: Proxy API
api = Proxy

postCves = client api (BaseUrl Http "localhost" 8080)


