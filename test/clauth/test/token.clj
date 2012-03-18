(ns clauth.test.token
  (:use [clauth.token])
  (:use [clojure.test])
  (:require [clj-time.core :as time]))

   (deftest token-records
     (let 
        [record (oauth-token "my-client" "user")]
        (is (= "my-client" ( :client record )) "should have client")
        (is (= "user" ( :subject record )) "should have client")
        (is (not (nil? (:token record  ))) "should include token field")
        (is (is-valid? record) "should be valid by default")))

   (deftest token-creation
     (reset-token-store!)
     (is (= 0 (count (tokens))) "starts out empty")
     (let 
        [record (create-token "my-client" "my-user")]
        (is (= "my-client" ( :client record )) "should have client")
        (is (= "my-user" ( :subject record )) "should have subject")
        (is (not (nil? (:token record ))) "should include token field")
        (is (= 1 (count (tokens ))) "added one")
        (is (= record (first (tokens ))) "added one")
        (is (= record (find-valid-token (:token record))))))

   (deftest token-validity
      (is (is-valid? {}) "by default it's valid")
      (is (not (is-valid? nil)) "nil is always false")
      (is (is-valid? {:expires (time/plus (time/now) (time/days 1))}) "valid if expiry date is in the future")
      (is (not (is-valid? {:expires (time/date-time 2012 3 13)})) "expires if past expiry date")
    )

   (deftest token-store-implementation
     (reset-token-store!)
     (is (= 0 (count (tokens))) "starts out empty")
     (let 
        [record (oauth-token "my-client" "my-user")]
        (is (nil? (fetch-token (:token record))))
        (do
          (store-token record)
          (is (= record (fetch-token (:token record))))
          (is (= 1 (count (tokens))) "added one"))))
