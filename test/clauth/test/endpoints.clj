(ns clauth.test.endpoints
  (:use [clauth.endpoints])
  (:use [clojure.test]))

    (deftest token-decoration
        (is (= (decorate-token { :token "SECRET" :unimportant "forget this"})
            { :access_token "SECRET" :token_type "bearer"})))

    (deftest token-ring-response
        (is (= (token-response { :token "SECRET" :unimportant "forget this"})
            { :status 200
              :headers {"Content-Type" "application/json"}
              :body "{\"access_token\":\"SECRET\",\"token_type\":\"bearer\"}"})))

    (deftest ring-error-response
        (is (= (error-response :invalid_request)
            { :status 400
              :headers {"Content-Type" "application/json"}
              :body "{\"error\":\"invalid_request\"}"})))


    (deftest requesting-client-owner-token
        (swap! clauth.token/tokens {})
        (swap! clauth.client/clients {})
        (let [ handler (token-handler clauth.client/authenticate-client)
               client (clauth.client/register-client { :name "Super company inc" })]

            (is (= (handler { 
                    :params {
                        :grant_type "client_credentials"
                        :client_id (client :client-id)
                        :client_secret (client :client-secret)}})
                { :status 200
                  :headers {"Content-Type" "application/json"}
                  :body (str "{\"access_token\":\"" ((first (vals @clauth.token/tokens)) :token) "\",\"token_type\":\"bearer\"}") }))

            (is (= (handler { 
                    :params {
                        :grant_type "client_credentials"
                        :client_id  "bad"
                        :client_secret "client"}})
                { :status 400
                  :headers {"Content-Type" "application/json"}
                  :body "{\"error\":\"invalid_client\"}"}) "should fail on bad client authentication") 

            (is (= (handler { :params { :grant_type "client_credentials"}})
                { :status 400
                  :headers {"Content-Type" "application/json"}
                  :body "{\"error\":\"invalid_client\"}"}) "should fail with missing client authentication") ))

    (deftest requesting-unsupported-grant
        (swap! clauth.token/tokens {})
        (swap! clauth.client/clients {})
        (let [ handler (token-handler clauth.client/authenticate-client)
               client (clauth.client/register-client { :name "Super company inc" })]

            (is (= (handler { :params { :grant_type "telepathy"}})
                { :status 400
                  :headers {"Content-Type" "application/json"}
                  :body "{\"error\":\"unsupported_grant_type\"}"}) "should fail with unsupported grant type") 

            (is (= (handler { :params { }})
                { :status 400
                  :headers {"Content-Type" "application/json"}
                  :body "{\"error\":\"unsupported_grant_type\"}"}) "should fail with missing grant type") ))
