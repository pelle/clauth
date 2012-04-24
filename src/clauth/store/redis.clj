(ns clauth.store.redis
  (:use [clauth.store])
  (:require [redis.core :as redis]
            [cheshire.core]))


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
  (revoke! [this t] (redis/del (str namespace "/" t)))       
  (store! [this key_param item]
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

(def redis-server    
  (if-let [ redis_url ( or (get (System/getenv) "REDIS_URL") (get (System/getenv) "REDISTOGO_URL"))]
    (let [ uri (new java.net.URI redis_url)
           host (.getHost uri)
           port (.getPort uri)
           password ( last (clojure.string/split (.getUserInfo uri) #":"))]
      { :host host
        :port port
        :password password })
    {
      :host "127.0.0.1"
      :port 6379
      :db 14 }))

(defmacro with-redis
  "Evaluates body in the context of a new connection to either local Redis server or server specified in REDIS_URL or REDISTOGO_URL"
  
  [ & body]
  `(redis/with-server redis-server ~@body))


(defn wrap-redis [app]
  (fn [req]
      (with-redis
        (app req))))
