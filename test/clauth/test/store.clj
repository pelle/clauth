(ns clauth.test.store
  (:use [clauth.token])
  (:use [clauth.store])
  (:use [clojure.test])
  )


 (deftest token-creation
   (clauth.store/reset-memory-store!)
   (is (= 0 (count (tokens @token-store))) "starts out empty")
   (let 
      [record (oauth-token "my-client" "my-user")]
      (is (nil? (find-token @token-store (:token record))))
      (do
        (store-token @token-store record)
        (is (= record (find-token @token-store (:token record))))
        (is (= 1 (count (tokens @token-store))) "added one"))))
