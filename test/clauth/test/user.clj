(ns clauth.test.user
  (:require [clojure.test :refer :all]
            [clauth.user :as base]))

(deftest user-registration
  (base/reset-user-store!)
  (let [record (base/register-user "john@example.com" "password" "John Doe"
                                   "http://example.com")]
    (is (= "John Doe" (:name record)) "should add extra attributes to user")
    (is (= 1 (count (base/users))) "added one")
    (is (= record (first (base/users))) "added one")
    (is (= record (base/authenticate-user "john@example.com" "password"))
        "should authenticate user")
    (is (nil? (base/authenticate-user "john@example.com" "bad"))
        "should not authenticate user with wrong password")
    (is (nil? (base/authenticate-user "idontexist" "bad"))
        "should not authenticate user with wrong id")))

(deftest user-store-implementation
  (base/reset-user-store!)
  (is (= 0 (count (base/users))) "starts out empty")
  (let [record (base/new-user "john@example.com" "password")]
    (is (nil? (base/fetch-user "john@example.com")))
    (do
      (base/store-user record)
      (is (= record (base/fetch-user "john@example.com")))
      (is (= 1 (count (base/users))) "added one"))))
