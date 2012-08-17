(ns clauth.test.endpoints
  (:use [clauth.endpoints]
        [clauth.token]
        [clauth.auth-code]
        [clojure.test]
        [hiccup.util])
  (:import [org.apache.commons.codec.binary Base64]))

(deftest token-decoration
  (is (= (decorate-token {:token "SECRET" :unimportant "forget this"})
         {:access_token "SECRET" :token_type "bearer"})))

(deftest token-ring-response
  (is (= (token-response {:token "SECRET" :unimportant "forget this"})
         {:status 200
          :headers {"Content-Type" "application/json"}
          :body "{\"access_token\":\"SECRET\",\"token_type\":\"bearer\"}"})))

(deftest ring-error-response
  (is (= (error-response :invalid_request)
         {:status 400
          :headers {"Content-Type" "application/json"}
          :body "{\"error\":\"invalid_request\"}"})))

(deftest extract-basic-authenticated-credentials
  (is (= ["user" "password"]
         (basic-authentication-credentials
          {:headers {"authorization" "Basic dXNlcjpwYXNzd29yZA=="}}))))

(deftest requesting-client-owner-token
  (reset-token-store!)
  (clauth.client/reset-client-store!)
  (let [handler (token-handler)
        client (clauth.client/register-client)]
    (is (= (handler {:params {:grant_type "client_credentials"
                              :client_id (:client-id client)
                              :client_secret (:client-secret client)}})
           {:status 200
            :headers {"Content-Type" "application/json"}
            :body (str "{\"access_token\":\"" (:token (first (tokens)))
                       "\",\"token_type\":\"bearer\"}")})
        "url form encoded client credentials")

    (is (= (handler {:params { :grant_type "client_credentials" }
                     :headers {"authorization"
                               (str "Basic "
                                    (.encodeAsString
                                     (Base64.)
                                     (.getBytes
                                      (str (:client-id client ) ":"
                                           (:client-secret client )))))}})
           {:status 200
            :headers {"Content-Type" "application/json"}
            :body (str "{\"access_token\":\"" (:token (first (tokens)))
                       "\",\"token_type\":\"bearer\"}")})
        "basic authenticated client credentials")


    (is (= (handler {:params {:grant_type "client_credentials"
                              :client_id  "bad"
                              :client_secret "client"}})
           {:status 400
            :headers {"Content-Type" "application/json"}
            :body "{\"error\":\"invalid_client\"}"})
        "should fail on bad client authentication")

    (is (= (handler {:params { :grant_type "client_credentials"}})
           {:status 400
            :headers {"Content-Type" "application/json"}
            :body "{\"error\":\"invalid_client\"}"})
        "should fail with missing client authentication")))

(deftest requesting-resource-owner-password-credentials-token
  (reset-token-store!)
  (clauth.client/reset-client-store!)
  (clauth.user/reset-user-store!)
  (let [handler (token-handler)
        client (clauth.client/register-client)
        user (clauth.user/register-user "john@example.com" "password")]
    (is (= (handler {:params {:grant_type "password"
                              :username "john@example.com"
                              :password "password"
                              :client_id (:client-id client)
                              :client_secret (:client-secret client)}})
           {:status 200
            :headers {"Content-Type" "application/json"}
            :body (str "{\"access_token\":\"" (:token (first (tokens)))
                       "\",\"token_type\":\"bearer\"}")})
        "url form encoded client credentials")

    (is (= (handler {:params {:grant_type "password"
                              :username "john@example.com"
                              :password "password"}
                     :headers {"authorization"
                               (format "Basic %s"
                                       (.encodeAsString
                                        (Base64.)
                                        (.getBytes
                                         (format "%s:%s"
                                                 (:client-id client)
                                                 (:client-secret client)))))}})
           {:status 200
            :headers {"Content-Type" "application/json"}
            :body (str "{\"access_token\":\"" (:token (first (tokens)))
                       "\",\"token_type\":\"bearer\"}")})
        "basic authenticated client credentials")

    (is (= (handler {:params {:grant_type "password"
                              :username "john@example.com"
                              :password "not my password"
                              :client_id (:client-id client)
                              :client_secret (:client-secret client)}})
           {:status 400
            :headers {"Content-Type" "application/json"}
            :body "{\"error\":\"invalid_grant\"}"})
        "should fail on bad user password")

    (is (= (handler {:params {:grant_type "password"
                              :client_id (:client-id client)
                              :client_secret (:client-secret client)}})

           {:status 400
            :headers {"Content-Type" "application/json"}
            :body "{\"error\":\"invalid_grant\"}"})
        "should fail with missing user authentication")

    (is (= (handler {:params {:grant_type "password"
                              :username "john@example.com"
                              :password "password"
                              :client_id  "bad"
                              :client_secret "client"}})
           {:status 400
            :headers {"Content-Type" "application/json"}
            :body "{\"error\":\"invalid_client\"}"})
        "should fail on bad client authentication")

    (is (= (handler { :params {:grant_type "password"}})
           {:status 400
            :headers {"Content-Type" "application/json"}
            :body "{\"error\":\"invalid_client\"}"})
        "should fail with missing client authentication")))

(deftest requesting-authorization-code-token
  (reset-token-store!)
  (reset-auth-code-store!)
  (clauth.client/reset-client-store!)
  (clauth.user/reset-user-store!)
  (let [handler (token-handler)
        client (clauth.client/register-client)
        user (clauth.user/register-user "john@example.com" "password")
        scope "calendar"
        redirect_uri "http://test.com/redirect_uri"
        object {:id "stuff"}]
    (let [code (create-auth-code client user redirect_uri scope object)]
      (is (= (handler {:params {:grant_type "authorization_code"
                                :code (:code code)
                                :redirect_uri redirect_uri
                                :client_id (:client-id client)
                                :client_secret (:client-secret client)}})
             {:status 200
              :headers {"Content-Type" "application/json"}
              :body (str "{\"access_token\":\"" (:token (first (tokens)))
                         "\",\"token_type\":\"bearer\"}")})
          "url form encoded client credentials"))

    (let [code (create-auth-code client user redirect_uri "calendar" object)]
      (is (= (handler {:params {:grant_type "authorization_code"
                                :redirect_uri redirect_uri
                                :code (:code code)}
                       :headers {"authorization"
                                 (format "Basic %s"
                                         (.encodeAsString
                                          (Base64.)
                                          (.getBytes
                                           (format "%s:%s"
                                                   (:client-id client)
                                                   (:client-secret
                                                    client)))))}})
             {:status 200
              :headers {"Content-Type" "application/json"}
              :body (str "{\"access_token\":\"" (:token (first (tokens)))
                         "\",\"token_type\":\"bearer\"}")})
          "basic authenticated client credentials"))

    (let [code (create-auth-code client user redirect_uri "calendar" object)]
      (is (= (handler {:params {:grant_type "authorization_code"
                                :code (:code code)
                                :redirect_uri redirect_uri
                                :client_id (:client-id client)
                                :client_secret "bad"}})
             {:status 400
              :headers {"Content-Type" "application/json"}
              :body "{\"error\":\"invalid_client\"}"})
          "should fail on bad client authentication"))

    (let [code (create-auth-code client user redirect_uri "calendar" object)
          other (clauth.client/register-client)]
      (is (= (handler {:params {:grant_type "authorization_code"
                                :code (:code code)
                                :redirect_uri redirect_uri
                                :client_id (:client-id other )
                                :client_secret (:client-secret other)}})
                {:status 400
                 :headers {"Content-Type" "application/json"}
                 :body "{\"error\":\"invalid_grant\"}"})
          "should fail for other client")

      (is (= (handler {:params {:grant_type "authorization_code"
                                :code (:code code)
                                :client_id (:client-id client )
                                :client_secret (:client-secret client)}})

             {:status 400
              :headers {"Content-Type" "application/json"}
              :body "{\"error\":\"invalid_grant\"}"})
          "should fail with missing redirect_uri")

      (is (= (handler {:params {:grant_type "authorization_code"
                                :code (:code code)
                                :redirect_uri "http://badsite.com"
                                :client_id (:client-id client)
                                :client_secret (:client-secret client)}})

             {:status 400
              :headers {"Content-Type" "application/json"}
              :body "{\"error\":\"invalid_grant\"}"})
          "should fail with wrong redirect_uri"))

    (is (= (handler {:params {:grant_type "authorization_code"
                              :redirect_uri redirect_uri
                              :client_id (:client-id client )
                              :client_secret (:client-secret client)}})

           {:status 400
            :headers {"Content-Type" "application/json"}
            :body "{\"error\":\"invalid_grant\"}"})
        "should fail with missing code")

    (let [code (create-auth-code client user redirect_uri "calendar" object)]
      (is (= (handler {:params {:grant_type "authorization_code"
                                :code (:code code)
                                :redirect_uri redirect_uri
                                :client_id "bad"
                                :client_secret "client"}})
             {:status 400
              :headers {"Content-Type" "application/json"}
              :body "{\"error\":\"invalid_client\"}"})
          "should fail on bad client authentication"))

    (let [code (create-auth-code client user redirect_uri "calendar" object)]
      (is (= (handler {:params {:grant_type "authorization_code"
                                :code (:code code)
                                :redirect_uri redirect_uri}})
             {:status 400
              :headers {"Content-Type" "application/json"}
              :body "{\"error\":\"invalid_client\"}"})
          "should fail with missing client authentication"))))

(deftest requesting-authorization-code
  (reset-token-store!)
  (reset-auth-code-store!)
  (clauth.client/reset-client-store!)
  (clauth.user/reset-user-store!)
  (let [handler (authorization-handler)
        client (clauth.client/register-client)
        user (clauth.user/register-user "john@example.com" "password")
        redirect_uri "http://test.com"
        uri "/authorize"
        params {:response_type "code"
                :client_id (:client-id client)
                :redirect_uri redirect_uri
                :state "abcde"
                :scope "calendar"}
        query-string (url-encode params)]

    (let [session_token (create-token client user)
          response (handler {:request-method :get
                             :params params
                             :uri uri
                             :query-string query-string
                             :session {:access_token (:token session_token )}})]
      (is (= (response :status) 200)))

    (let [response (handler {:request-method :get
                             :uri uri
                             :query-string query-string
                             :headers {"accept" "text/html"}
                             :params params})
          session (response :session)]
      (is (= (response :status) 302))
      (is (= (session :return-to)
             (str uri "?" query-string)))
      (is (= (response :headers) {"Location" "/login"})))
    ;; Missing parameters
    (let [session_token (create-token client user)
          response (handler {:request-method :get
                             :params (dissoc params :response_type)
                             :uri uri
                             :query-string query-string
                             :session {:access_token (:token session_token)}})]
      (is (= (response :status) 302))
      (is (= (response :headers)
             {"Location" "http://test.com?state=abcde&error=invalid_request"})))

    (let [session_token (create-token client user)
          response (handler {:request-method :get
                             :params (dissoc params :client_id)
                             :uri uri
                             :query-string query-string
                             :session {:access_token (:token session_token)}})]
      (is (= (response :status) 302))
      (is (= (response :headers)
             {"Location" "http://test.com?state=abcde&error=invalid_request"})
          "should redirect with error in query"))

    (let [session_token (create-token client user)
          response (handler {:request-method :get
                             :params (dissoc params :client_id :state)
                             :uri uri
                             :query-string query-string
                             :session {:access_token (:token session_token)}})]
      (is (= (response :status) 302))
      (is (= (response :headers)
             {"Location" "http://test.com?error=invalid_request"})
          "should redirect with error in query"))

    (let [session_token (create-token client user)
          response (handler {:request-method :get
                             :params (assoc params :response_type "unsupported")
                             :uri uri
                             :query-string query-string
                             :session {:access_token (:token session_token)}})]
      (is (= (response :status) 302))
      (is (= (response :headers)
             {"Location"
              "http://test.com?state=abcde&error=unsupported_response_type"})
          "should return error on unsupported response type"))

    (let [session_token (create-token client user)
          params (assoc params :csrf-token "csrftoken")
          response (handler {:request-method :post
                             :params params
                             :uri uri
                             :query-string query-string
                             :session {:access_token (:token session_token)
                                       :csrf-token "csrftoken"}})
          post_auth_redirect_uri ((response :headers) "Location")
          code_string (last (re-find #"code=([^&]+)" post_auth_redirect_uri))
          auth-code (fetch-auth-code code_string)]
      (is (= (response :status) 302))
      (is (= post_auth_redirect_uri
             (str "http://test.com?state=abcde&code=" code_string))
          "should redirect with proper format")
      (is (= (:client auth-code) client) "should properly set client")
      (is (= (:subject auth-code) user) "should properly set subject")
      (is (= (:redirect-uri auth-code) redirect_uri)
          "should properly save redirect_uri"))))

(deftest requesting-implicit-authorization
  (reset-token-store!)
  (clauth.client/reset-client-store!)
  (clauth.user/reset-user-store!)
  (let [ handler (authorization-handler)
        client (clauth.client/register-client)
        user   (clauth.user/register-user "john@example.com" "password")
        redirect_uri "http://test.com"
        uri "/authorize"
        params {:response_type "token"
                :client_id ( :client-id client )
                :redirect_uri redirect_uri
                :state "abcde"
                :scope "calendar"}
        query-string (url-encode params)]

    (let [session_token (create-token client user)
          response (handler {:request-method :get
                             :params params
                             :uri uri
                             :query-string query-string
                             :session {:access_token (:token session_token)}})]
      (is (= (response :status) 200)))

    (let [response (handler {:request-method :get
                             :uri uri
                             :query-string query-string
                             :headers {"accept" "text/html"}
                             :params params})
          session (response :session)]
      (is (= (response :status) 302))
      (is (= (session :return-to)
             (str uri "?" query-string)))
      (is (= (response :headers) {"Location" "/login"})))

    ;; Missing parameters
    (let [session_token (create-token client user)
          response (handler {:request-method :get
                             :params (dissoc params :response_type)
                             :uri uri
                             :query-string query-string
                             :session {:access_token (:token session_token)}})]
      (is (= (response :status) 302))
      (is (= (response :headers)
             {"Location" "http://test.com?state=abcde&error=invalid_request"})))

    (let [session_token (create-token client user)
          response (handler {:request-method :get
                             :params (dissoc params :client_id)
                             :uri uri
                             :query-string query-string
                             :session {:access_token (:token session_token )}})]
      (is (= (response :status) 302))
      (is (= (response :headers)
             {"Location" "http://test.com#state=abcde&error=invalid_request"})
          "should redirect with error in fragment"))

    (let [session_token (create-token client user)
          response (handler {:request-method :get
                             :params (dissoc params :client_id :state)
                             :uri uri
                             :query-string query-string
                             :session {:access_token (:token session_token)}})]
      (is (= (response :status) 302))
      (is (= (response :headers)
             {"Location" "http://test.com#error=invalid_request"})
          "should redirect with error in fragment"))

    (let [session_token (create-token client user)
          response (handler {:request-method :get
                             :params (assoc params :response_type "unsupported")
                             :uri uri
                             :query-string query-string
                             :session {:access_token (:token session_token )}})]
      (is (= (response :status) 302))
      (is (= (response :headers)
             {"Location"
              "http://test.com?state=abcde&error=unsupported_response_type"})
          "should return error on unsupported response type"))

    (let [session_token (create-token client user)
          params (assoc params :csrf-token "csrftoken")
          response (handler {:request-method :post
                             :params params
                             :uri uri
                             :query-string query-string
                             :session {:access_token (:token session_token)
                                       :csrf-token "csrftoken"}})
          redirect_uri ((response :headers) "Location")
          token_string (last (re-find #"access_token=([^&]+)" redirect_uri))
          token (fetch-token token_string)]
      (is (= (response :status) 302))
      (is (= redirect_uri (str "http://test.com#state=abcde&access_token="
                               token_string "&token_type=bearer"))
          "should redirect with proper format")
      (is (= (:client token) client) "should properly set client")
      (is (= (:subject token) user) "should properly set subject"))))

(deftest requesting-unsupported-grant
  (reset-token-store!)
  (clauth.client/reset-client-store!)
  (let [handler (token-handler)
        client (clauth.client/register-client)]

    (is (= (handler {:params {:grant_type "telepathy"}})
           {:status 400
            :headers {"Content-Type" "application/json"}
            :body "{\"error\":\"unsupported_grant_type\"}"})
        "should fail with unsupported grant type")

    (is (= (handler {:params {}})
           {:status 400
            :headers {"Content-Type" "application/json"}
            :body "{\"error\":\"unsupported_grant_type\"}"})
        "should fail with missing grant type")))

(deftest interactive-login-session
  (reset-token-store!)
  (clauth.client/reset-client-store!)
  (clauth.user/reset-user-store!)
  (let [client (clauth.client/register-client)
        handler (login-handler {:login-form (fn [_] {:body "login form"})
                                :client client})
        user (clauth.user/register-user "john@example.com" "password")
        response (handler {:request-method :post
                           :session {:csrf-token "csrftoken"}
                           :params {:username "john@example.com"
                                    :password "password"
                                    :csrf-token "csrftoken"}})
        session (response :session)
        token-string (session :access_token)
        token (fetch-token token-string)]
    (is (= 302 (response :status)) "Should redirect user")
    (is (= "/" ((response :headers) "Location")) "Should redirect user to home")
    (is (= user (:subject token)) "should set user to token")
    (is (= client (:client token)) "should set client to token")

    (let [response (handler {:request-method :post
                             :session {:csrf-token "csrftoken"
                                       :return-to "/authorization"}
                             :params {:username "john@example.com"
                                      :password "password"
                                      :csrf-token "csrftoken"}})
          session (response :session)
          token-string (session :access_token)
          token (fetch-token token-string)]
      (is (= 302 (response :status)) "Should redirect user")
      (is (= "/authorization" ((response :headers) "Location"))
          "Should redirect user to whatever is in the return-to session")
      (is (nil? (session :return-to)) "Should remove return-to from session")
      (is (= user (:subject token)) "should set user to token")
      (is (= client (:client token)) "should set client to token"))

    (let [response (handler {:request-method :get})]
      (is (= (response :body) "login form") "should show login form"))
    (let [response (handler {:request-method :post
                             :session {:csrf-token "csrftoken"}
                             :params {:username "john@example.com"
                                      :password "wrong"
                                      :csrf-token "csrftoken"}})]
      (is (= (response :body) "login form")
          "should show login form for wrong password"))))

(deftest login-helpers
  (let [req {}]
    (is (not (logged-in? req)) "should not be marked as logged in")
    (is (nil? (current-user req)) "should not have a current user"))

  (let [client (clauth.client/register-client)
        user (clauth.user/register-user "john@example.com" "password")
        session-token (create-token client user)
        req {:access-token session-token}]
    (is (logged-in? req) "should be marked as logged in")
    (is (= (current-user req) user) "should have a current user")))

