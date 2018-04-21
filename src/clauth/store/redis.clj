(ns clauth.store.redis
  (:require [clauth.store :refer [Store]]
            [taoensso.carmine :as car :refer (wcar)]))

(def server1-conn
  (if-let [redis_url (or (get (System/getenv) "REDIS_URL")
                         (get (System/getenv) "REDISTOGO_URL"))]
    (let [uri (new java.net.URI redis_url)
          host (.getHost uri)
          port (.getPort uri)]
      ;; auth is optional
      (if-let [user-info (.getUserInfo uri)]
        (let [password (last (clojure.string/split user-info #":"))]
          {:pool {} 
           :spec {:host host
                   :port port
                   :password password}})
        {:pool {} 
         :spec {:host host
                 :port port}}))
    {:pool {}
     :spec {:host "127.0.0.1"
            :port 6379
            :db 14}}))

(defmacro wcar*
  "Evaluates body in the context of a new connection to either local Redis
   server or server specified in REDIS_URL or REDISTOGO_URL"
  [& body]
  `(car/wcar ~'server-conn ~@body))

(defn namespaced-keys
  "get namespaced list of keys"
  [namespace server-conn]
  (wcar* (car/keys (str namespace "/*"))))

(defn all-in-namespace
  "get all items in namespace"
  [namespace server-conn]
  (let [ks (remove nil? (namespaced-keys namespace server-conn))]
    (if (not-empty ks) (wcar* (apply car/mget ks))
      [])))

(defrecord RedisStore [namespace server-conn]
  Store
  (fetch [this t] (wcar* (car/get (str namespace "/" t))))
  (revoke! [this t] (wcar* (car/del (str namespace "/" t))))
  (store! [this key_param item]
      (wcar* (car/set (str namespace "/" (key_param item)) item))
    item)
  (entries [this] (all-in-namespace namespace server-conn))
  (reset-store! [this] (wcar* (car/flushdb))))

(defn create-redis-store
  "Create a redis store"
  ([namespace]
  (RedisStore. namespace server1-conn))
  ([namespace server-conn]
  (RedisStore. namespace server-conn)))
