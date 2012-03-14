(ns clauth.test.client
  (:use [clauth.client])
  (:use [clojure.test]))

   (deftest client-registration
     (is (= 0 (count @clients)) "starts out empty")
     (let 
        [record (register-client { :name "Super company inc" })]
        (is (= "Super company inc" (record :name )) "should add extra attributes to client")
        (is (not (nil? (record :client-id ))) "should include client_id field")
        (is (not (nil? (record :client-secret ))) "should include client_secret field")
        (is (= 1 (count @clients)) "added one")
        (is (= record (first (vals @clients))) "added one")))
