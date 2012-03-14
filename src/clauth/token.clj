(ns clauth.token
    (:require [crypto.random])
    (:import [org.apache.commons.codec.binary Base32]))


(def tokens 
  "In memory token store"
  (atom {})) 

(defn generate-token 
  "generate a unique token"
  [] (.encodeAsString (new Base32) (crypto.random/bytes 20)))

(defn create-token 
  "create a unique token and store it in the token store"
  [ attrs ]
  (let [token (generate-token)
        record (assoc attrs :token token)]
    (do 
      (swap! tokens assoc token record)
      record)))
  
