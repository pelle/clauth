(ns clauth.test.client
  (:use [clauth.client])
  (:use [clojure.test]))

   (deftest client-registration
     (swap! clients {})
     (is (= 0 (count @clients)) "starts out empty")
     (let 
        [ record (register-client { :name "Super company inc" })
          client-id (record :client-id)
          client-secret (record :client-secret)]

        (is (= "Super company inc" (record :name )) "should add extra attributes to client")
        (is (not (nil? client-id )) "should include client_id field")
        (is (not (nil? client-secret )) "should include client_secret field")
        (is (= 1 (count @clients)) "added one")
        (is (= record (first (vals @clients))) "added one")
        (is (= record (authenticate-client client-id client-secret)) "should authenticate client")
        (is (nil? (authenticate-client client-id "bad")) "should not authenticate client with wrong password")
        (is (nil? (authenticate-client "idontexist" "bad")) "should not authenticate client with wrong id")))

