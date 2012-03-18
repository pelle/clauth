(ns clauth.test.endpoints
  (:use [clauth.endpoints])
  (:use [clauth.token])
  (:use [clojure.test])
  (:import [org.apache.commons.codec.binary Base64]))

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

    (deftest extract-basic-authenticated-credentials
        (is (= ["user" "password"] (basic-authentication-credentials { :headers {"authorization" "Basic dXNlcjpwYXNzd29yZA=="}}))))

    (deftest requesting-client-owner-token
        (reset-token-store!)
        (swap! clauth.client/clients {})
        (let [ handler (token-handler clauth.client/authenticate-client)
               client (clauth.client/register-client { :name "Super company inc" })]

            (is (= (handler { 
                    :params {
                        "grant_type" "client_credentials"
                        "client_id" (client :client-id)
                        "client_secret" (client :client-secret)}})
                { :status 200
                  :headers {"Content-Type" "application/json"}
                  :body (str "{\"access_token\":\"" ( :token (first (tokens))) "\",\"token_type\":\"bearer\"}") }) "url form encoded client credentials")

            (is (= (handler { 
                    :params { "grant_type" "client_credentials" }
                    :headers {"authorization" 
                    (str "Basic " (.encodeAsString (Base64.) (.getBytes (str (client :client-id) ":" (client :client-secret))) ))}})
                { :status 200
                  :headers {"Content-Type" "application/json"}
                  :body (str "{\"access_token\":\"" (:token (first (tokens)) ) "\",\"token_type\":\"bearer\"}") }) "basic authenticated client credentials")


            (is (= (handler { 
                    :params {
                        "grant_type" "client_credentials"
                        "client_id"  "bad"
                        "client_secret" "client"}})
                { :status 400
                  :headers {"Content-Type" "application/json"}
                  :body "{\"error\":\"invalid_client\"}"}) "should fail on bad client authentication") 

            (is (= (handler { :params { "grant_type" "client_credentials"}})
                { :status 400
                  :headers {"Content-Type" "application/json"}
                  :body "{\"error\":\"invalid_client\"}"}) "should fail with missing client authentication") ))

    (deftest requesting-unsupported-grant
        (reset-token-store!)
        (swap! clauth.client/clients {})
        (let [ handler (token-handler clauth.client/authenticate-client)
               client (clauth.client/register-client { :name "Super company inc" })]

            (is (= (handler { :params { "grant_type" "telepathy"}})
                { :status 400
                  :headers {"Content-Type" "application/json"}
                  :body "{\"error\":\"unsupported_grant_type\"}"}) "should fail with unsupported grant type") 

            (is (= (handler { :params { }})
                { :status 400
                  :headers {"Content-Type" "application/json"}
                  :body "{\"error\":\"unsupported_grant_type\"}"}) "should fail with missing grant type") ))
