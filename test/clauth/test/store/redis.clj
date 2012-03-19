(ns clauth.test.store.redis
  (:use [clauth.store])
  (:use [clauth.store.redis])
  (:require [redis.core :as redis])
  (:use [clojure.test])
  )


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

 