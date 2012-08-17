(ns clauth.test.auth-code
  (:use [clauth.auth-code]
        [clauth.token]
        [clojure.test])
  (:require [clj-time.core :as time]))

(deftest auth-code-records
  (let [record (oauth-code "my-client" "user" "http://test.com/redirect")]
    (is (= "my-client" (:client record)) "should have client")
    (is (= "user" (:subject record)) "should have subject")
    (is (= "http://test.com/redirect" (:redirect-uri record))
        "should have redirect-uri")
    (is (not (nil? (:code record))) "should include code field")
    (is (is-valid? record) "should be valid by default")))

(deftest auth-code-creation
  (reset-auth-code-store!)
  (is (= 0 (count (auth-codes))) "starts out empty")
  (let [record (create-auth-code "my-client" "my-user"
                                 "http://test.com/redirect")]
    (is (= "my-client" ( :client record )) "should have client")
    (is (= "my-user" ( :subject record )) "should have subject")
    (is (= "http://test.com/redirect" ( :redirect-uri record ))
        "should have redirect-uri")
    (is (not (nil? (:code record ))) "should include auth-code field")
    (is (= 1 (count (auth-codes ))) "added one")
    (is (= record (first (auth-codes ))) "added one")
    (is (= record (find-valid-auth-code (:code record))))))

(deftest auth-code-validity
  (is (is-valid? {}) "by default it's valid")
  (is (not (is-valid? nil)) "nil is always false")
  (is (is-valid? {:expires (time/plus (time/now) (time/days 1))})
      "valid if expiry date is in the future")
  (is (not (is-valid? {:expires (time/date-time 2012 3 13)}))
      "expires if past expiry date"))

(deftest auth-code-store-implementation
  (reset-auth-code-store!)
  (is (= 0 (count (auth-codes))) "starts out empty")
  (let [record (oauth-code "my-client" "my-user" "http://test.com/redirect")]
    (is (nil? (fetch-auth-code (:code record))))
    (do (store-auth-code record)
        (is (= record (fetch-auth-code (:code record))))
        (is (= 1 (count (auth-codes))) "added one"))))
