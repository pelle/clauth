(ns clauth.test.auth-code
  (:require [clojure.test :refer :all]
            [clauth
             [auth-code :as base]
             [token :as token]]
            [clj-time.core :as time]))

(deftest auth-code-records
  (let [record (base/oauth-code "my-client" "user" "http://test.com/redirect")]
    (is (= "my-client" (:client record)) "should have client")
    (is (= "user" (:subject record)) "should have subject")
    (is (= "http://test.com/redirect" (:redirect-uri record))
        "should have redirect-uri")
    (is (not (nil? (:code record))) "should include code field")
    (is (token/is-valid? record) "should be valid by default")))

(deftest auth-code-creation
  (base/reset-auth-code-store!)
  (is (= 0 (count (base/auth-codes))) "starts out empty")
  (let [record (base/create-auth-code "my-client" "my-user"
                                      "http://test.com/redirect")]
    (is (= "my-client" (:client record)) "should have client")
    (is (= "my-user" (:subject record)) "should have subject")
    (is (= "http://test.com/redirect" (:redirect-uri record))
        "should have redirect-uri")
    (is (not (nil? (:code record))) "should include auth-code field")
    (is (= 1 (count (base/auth-codes))) "added one")
    (is (= record (first (base/auth-codes))) "added one")
    (is (= record (base/find-valid-auth-code (:code record))))))

(deftest auth-code-validity
  (is (token/is-valid? {}) "by default it's valid")
  (is (not (token/is-valid? nil)) "nil is always false")
  (is (token/is-valid? {:expires (time/plus (time/now) (time/days 1))})
      "valid if expiry date is in the future")
  (is (not (token/is-valid? {:expires (time/date-time 2012 3 13)}))
      "expires if past expiry date"))

(deftest auth-code-store-implementation
  (base/reset-auth-code-store!)
  (is (= 0 (count (base/auth-codes))) "starts out empty")
  (let [record (base/oauth-code
                "my-client" "my-user" "http://test.com/redirect")]
    (is (nil? (base/fetch-auth-code (:code record))))
    (do (base/store-auth-code record)
        (is (= record (base/fetch-auth-code (:code record))))
        (is (= 1 (count (base/auth-codes))) "added one"))))
