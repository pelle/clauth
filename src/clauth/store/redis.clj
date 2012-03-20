(ns clauth.store.redis
  (:use [clauth.store])
  (:require [redis.core :as redis])
  (:require [cheshire.core]))


(defn namespaced-keys 
  "get namespaced list of keys"
  [namespace] 
  (redis/keys (str namespace "/*")))

(defn all-in-namespace
  "get all items in namespace"
  [namespace]
  (let [ks (remove nil? (namespaced-keys namespace))]
    (if (not-empty ks) (apply redis/mget ks)))) 
    

(defrecord RedisStore [namespace] 
  Store 
  (fetch [this t] (if-let [j (redis/get (str namespace "/" t))]
                          (cheshire.core/parse-string j true)))
                            
  (store [this key_param item]
    (do
      (redis/set (str namespace "/" (key_param item)) (cheshire.core/generate-string item))
      item)
    )
  (entries [this] (map #( cheshire.core/parse-string % true) (all-in-namespace namespace) ))
  (reset-store! [this] (redis/flushdb)))

(defn create-redis-store 
  "Create a redis store"
  ([namespace]
    (RedisStore. namespace)))

