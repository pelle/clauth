(ns clauth.test.token
  (:use [clauth.token])
  (:use [clojure.test]))

   (deftest token-creation
     (swap! tokens {})
     (is (= 0 (count @tokens)) "starts out empty")
     (let 
        [record (create-token { :client-id "my-client" })]
        (is (= "my-client" (record :client-id )) "should add extra attributes to token")
        (is (not (nil? (record :token ))) "should include token field")
        (is (= 1 (count @tokens)) "added one")
        (is (= record (first (vals @tokens))) "added one")))
