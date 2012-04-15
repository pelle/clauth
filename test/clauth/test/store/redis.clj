(ns clauth.test.store.redis
  (:require [redis.core :as redis])
  (:use [clauth.store]
        [clauth.token]
        [clauth.client]
        [clauth.user]
        [clauth.store.redis]
        [clojure.test]))


  (deftest redis-store-implementaiton
    (redis/with-server
     {:host "127.0.0.1"
      :port 6379
      :db 15
     }

    (let [st (create-redis-store "testing")]
      (reset-store! st)
      (is (= 0 (count (entries st))))
      (is (= [] (entries st)))
      (is (nil? (fetch st "item")))

      (let [item (store st :key {:key  "item" :hello "world"})]
        (is (= 1 (count (entries st))))
        (is (= item (fetch st "item")))
        (is (= [item] (entries st)))
        (do
          (reset-store! st)
          (is (= 0 (count (entries st))))
          (is (= [] (entries st)))
          (is (nil? (fetch st "item"))))))))

 
  (deftest token-store-implementation
    (redis/with-server
     {:host "127.0.0.1"
      :port 6379
      :db 15
     }
     (reset! token-store (create-redis-store "tokens"))
     (reset-token-store!)
     (is (= 0 (count (tokens))) "starts out empty")
     (let 
        [record (oauth-token "my-client" "my-user")]
        (is (nil? (fetch-token (:token record))))
        (do
          (store-token record)
          (is (= record (fetch-token (:token record))))
          (is (= 1 (count (tokens))) "added one"))))
     (reset! token-store (create-memory-store)))

  (deftest client-store-implementation
    (redis/with-server
     {:host "127.0.0.1"
      :port 6379
      :db 15
     }
     (reset! client-store (create-redis-store "clients"))
     (reset-client-store!)
     (is (= 0 (count (clients))) "starts out empty")
     (let 
        [ record (client-app)]
        (is (nil? (fetch-client (:client-id record))))
        (do
          (store-client record)
          (is (= record (fetch-client (:client-id record))))
          (is (= 1 (count (clients))) "added one"))))
      (reset! client-store (create-memory-store)))


   (deftest user-store-implementation
    (redis/with-server
     {:host "127.0.0.1"
      :port 6379
      :db 15
     }
     (reset! user-store (create-redis-store "users"))
     (reset-user-store!)
     (is (= 0 (count (users))) "starts out empty")
     (let 
        [ record (new-user "john@example.com" "password")]
        (is (nil? (fetch-user "john@example.com")))
        (do
          (store-user record)
          (is (= record (fetch-user "john@example.com")))
          (is (= 1 (count (users))) "added one"))))
      (reset! user-store (create-memory-store)))

