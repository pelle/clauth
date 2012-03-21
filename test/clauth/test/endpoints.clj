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
        (clauth.client/reset-client-store!)
        (let [ handler (token-handler)
               client (clauth.client/register-client)]

            (is (= (handler { 
                    :params {
                        "grant_type" "client_credentials"
                        "client_id" (:client-id client )
                        "client_secret" (:client-secret client)}})
                { :status 200
                  :headers {"Content-Type" "application/json"}
                  :body (str "{\"access_token\":\"" ( :token (first (tokens))) "\",\"token_type\":\"bearer\"}") }) "url form encoded client credentials")

            (is (= (handler { 
                    :params { "grant_type" "client_credentials" }
                    :headers {"authorization" 
                    (str "Basic " (.encodeAsString (Base64.) (.getBytes (str (:client-id client ) ":" (:client-secret client )))))}})
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

    (deftest requesting-resource-owner-password-credentials-token
        (reset-token-store!)
        (clauth.client/reset-client-store!)
        (clauth.user/reset-user-store!)
        (let [ handler (token-handler)
               client (clauth.client/register-client)
               user   (clauth.user/register-user "john@example.com" "password")]

            (is (= (handler { 
                    :params {
                        "grant_type" "password"
                        "username" "john@example.com"
                        "password" "password"
                        "client_id" (:client-id client )
                        "client_secret" (:client-secret client)}})
                { :status 200
                  :headers {"Content-Type" "application/json"}
                  :body (str "{\"access_token\":\"" ( :token (first (tokens))) "\",\"token_type\":\"bearer\"}") }) "url form encoded client credentials")

            (is (= (handler { 
                    :params { "grant_type" "password" 
                              "username" "john@example.com"
                              "password" "password"}
                    :headers {"authorization" 
                    (str "Basic " (.encodeAsString (Base64.) (.getBytes (str (:client-id client ) ":" (:client-secret client )))))}})
                { :status 200
                  :headers {"Content-Type" "application/json"}
                  :body (str "{\"access_token\":\"" (:token (first (tokens)) ) "\",\"token_type\":\"bearer\"}") }) "basic authenticated client credentials")

            (is (= (handler { 
                    :params {
                        "grant_type" "password"
                        "username" "john@example.com"
                        "password" "not my password"
                        "client_id" (:client-id client )
                        "client_secret" (:client-secret client)}})
                { :status 400
                  :headers {"Content-Type" "application/json"}
                  :body "{\"error\":\"invalid_grant\"}"}) "should fail on bad client authentication") 

            (is (= (handler { :params { "grant_type" "password"                        
                                        "client_id" (:client-id client )
                                        "client_secret" (:client-secret client)}})

                { :status 400
                  :headers {"Content-Type" "application/json"}
                  :body "{\"error\":\"invalid_grant\"}"}) "should fail with missing client authentication") 


            (is (= (handler { 
                    :params {
                        "grant_type" "password"
                        "username" "john@example.com"
                        "password" "password"
                        "client_id"  "bad"
                        "client_secret" "client"}})
                { :status 400
                  :headers {"Content-Type" "application/json"}
                  :body "{\"error\":\"invalid_client\"}"}) "should fail on bad client authentication") 

            (is (= (handler { :params { "grant_type" "password"}})
                { :status 400
                  :headers {"Content-Type" "application/json"}
                  :body "{\"error\":\"invalid_client\"}"}) "should fail with missing client authentication") ))

    (deftest requesting-unsupported-grant
        (reset-token-store!)
        (clauth.client/reset-client-store!)
        (let [ handler (token-handler)
               client (clauth.client/register-client)]

            (is (= (handler { :params { "grant_type" "telepathy"}})
                { :status 400
                  :headers {"Content-Type" "application/json"}
                  :body "{\"error\":\"unsupported_grant_type\"}"}) "should fail with unsupported grant type") 

            (is (= (handler { :params { }})
                { :status 400
                  :headers {"Content-Type" "application/json"}
                  :body "{\"error\":\"unsupported_grant_type\"}"}) "should fail with missing grant type")))


    (deftest interactive-login-session
        (reset-token-store!)
        (clauth.client/reset-client-store!)
        (clauth.user/reset-user-store!)
        (let [ client (clauth.client/register-client)
               handler (login-handler (fn [_] "login form" ) client)
               user   (clauth.user/register-user "john@example.com" "password")]

            (let [ response (handler { 
                    :request-method :post
                    :params {
                        "username" "john@example.com"
                        "password" "password"}})
                   session (response :session)
                   token-string (session :access_token)
                   token (fetch-token token-string)]
              (is (= 302 (response :status)) "Should redirect user")
              (is (= user (:subject token)) "should set user to token")
              (is (= client (:client token)) "should set client to token")

            (let [ response (handler { 
                    :request-method :get })]
              (is (= response "login form") "should show login form"))

            (let [ response (handler { 
                    :request-method :post
                    :params {
                        "username" "john@example.com"
                        "password" "wrong"}})]
              (is (= response "login form") "should show login form for wrong password")))))


