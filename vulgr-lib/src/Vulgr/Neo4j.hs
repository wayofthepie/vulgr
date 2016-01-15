module Vulgr.Neo4j where

import Database.Neo4j as Neo
import Database.Neo4j.Transactional.Cypher as TC

n4jTransaction :: Neo.Connection -> Transaction a -> IO (Either TC.TransError a)
n4jTransaction conn action = flip Neo.runNeo4j conn $
    TC.runTransaction action


