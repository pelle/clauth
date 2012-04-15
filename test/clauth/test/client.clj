(ns clauth.test.client
  (:use [clauth.client]
        [clojure.test]))

   (deftest client-registration
     (reset-client-store!)
     (let 
        [ record (register-client "Super company inc" "http://example.com")
          client-id (:client-id record )
          client-secret (:client-secret record )]

        (is (= "Super company inc" (:name record )) "should add extra attributes to client")
        (is (not (nil? client-id )) "should include client_id field")
        (is (not (nil? client-secret )) "should include client_secret field")
        (is (= 1 (count (clients))) "added one")
        (is (= record (first (clients))) "added one")
        (is (= record (authenticate-client client-id client-secret)) "should authenticate client")
        (is (nil? (authenticate-client client-id "bad")) "should not authenticate client with wrong password")
        (is (nil? (authenticate-client "idontexist" "bad")) "should not authenticate client with wrong id")))

   (deftest client-store-implementation
     (reset-client-store!)
     (is (= 0 (count (clients))) "starts out empty")
     (let 
        [ record (client-app)]
        (is (nil? (fetch-client (:client-id record))))
        (do
          (store-client record)
          (is (= record (fetch-client (:client-id record))))
          (is (= 1 (count (clients))) "added one"))))
