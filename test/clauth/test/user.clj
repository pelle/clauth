(ns clauth.test.user
  (:use [clauth.user]
        [clojure.test]))

   (deftest user-registration
     (reset-user-store!)
     (let 
        [ record (register-user "john@example.com" "password" "John Doe" "http://example.com")]
        (is (= "John Doe" (:name record )) "should add extra attributes to user")
        (is (= 1 (count (users))) "added one")
        (is (= record (first (users))) "added one")
        (is (= record (authenticate-user "john@example.com" "password")) "should authenticate user")
        (is (nil? (authenticate-user "john@example.com" "bad")) "should not authenticate user with wrong password")
        (is (nil? (authenticate-user "idontexist" "bad")) "should not authenticate user with wrong id")))

   (deftest user-store-implementation
     (reset-user-store!)
     (is (= 0 (count (users))) "starts out empty")
     (let 
        [ record (new-user "john@example.com" "password")]
        (is (nil? (fetch-user "john@example.com")))
        (do
          (store-user record)
          (is (= record (fetch-user "john@example.com")))
          (is (= 1 (count (users))) "added one"))))
