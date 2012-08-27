(ns clauth.test.token
  (:require [clojure.test :refer :all]
            [clauth.token :as base]
            [clj-time.core :as time]))

(deftest token-records
  (let [record (base/oauth-token "my-client" "user")]
    (is (= "my-client" (:client record)) "should have client")
    (is (= "user" (:subject record)) "should have client")
    (is (not (nil? (:token record))) "should include token field")
    (is (base/is-valid? record) "should be valid by default")))

(deftest token-creation
  (base/reset-token-store!)
  (is (= 0 (count (base/tokens))) "starts out empty")
  (let [record (base/create-token "my-client" "my-user")]
    (is (= "my-client" (:client record)) "should have client")
    (is (= "my-user" (:subject record)) "should have subject")
    (is (not (nil? (:token record))) "should include token field")
    (is (= 1 (count (base/tokens))) "added one")
    (is (= record (first (base/tokens))) "added one")
    (is (= record (base/find-valid-token (:token record))))))

(deftest token-validity
  (is (base/is-valid? {}) "by default it's valid")
  (is (not (base/is-valid? nil)) "nil is always false")
  (is (base/is-valid? {:expires (time/plus (time/now) (time/days 1))})
      "valid if expiry date is in the future")
  (is (not (base/is-valid? {:expires (time/date-time 2012 3 13)}))
      "expires if past expiry date"))

(deftest token-store-implementation
  (base/reset-token-store!)
  (is (= 0 (count (base/tokens))) "starts out empty")
  (let [record (base/oauth-token "my-client" "my-user")]
    (is (nil? (base/fetch-token (:token record))))
    (do (base/store-token record)
        (is (= record (base/fetch-token (:token record))))
        (is (= 1 (count (base/tokens))) "added one"))
    (do (base/revoke-token record)
        (is (= nil (base/fetch-token (:token record))))
        (is (= 0 (count (base/tokens))) "revoked one"))))
