(ns clauth.endpoints
  (:use   [clauth.token])
  (:use   [clauth.client])
  (:use   [clauth.user])
  (:use   [clauth.middleware :only [csrf-protect! require-user-session!]])
  (:use   [clauth.views :only [login-form-handler authorization-form-handler]])
  (:use   [hiccup.util :only [url-encode]])
  (:use   [ring.util.response])
  (:use   [cheshire.core])
  (:import [org.apache.commons.codec.binary Base64]))



(defn decorate-token 
  "Take a token map and decorate it according to specs

  http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-5.1"
  [token]

  { :access_token (:token token) :token_type "bearer"}
  )

(defn token-response 
  "Create a ring response for a token response"
  [token]
  {  :status 200
      :headers {"Content-Type" "application/json"}
      :body (generate-string (decorate-token token))})

(defn error-response 
  "Create a ring response for a oauth error"
  [error]
  {  :status 400
      :headers {"Content-Type" "application/json"}
      :body (generate-string {:error error })})

(defn respond-with-new-token
  "create a new token and respond with json"
  [client owner]
  (token-response (create-token client owner)))

(defn basic-authentication-credentials 
  "decode basic authentication credentials.

   If it exists it returns a vector of username and password.

   If not nil."
  [req]
  (if-let [ basic-token (last (re-find #"^Basic (.*)$" ((req :headers {}) "authorization" ""))) ]
    (if-let [ credentials (String. (Base64/decodeBase64 basic-token))]
      (clojure.string/split credentials #":" )
      )))

(defn client-authenticated-request 
  "Check that request is authenticated by client either using Basic authentication or url form encoded parameters.

   The client_id and client_secret are checked against the authenticate-client function.

   If authenticate-client returns a client map it runs success function with the request and the client."
  [req authenticator success]
  (let [ basic (basic-authentication-credentials req)
         client_id (if basic (first basic) ((req :params ) "client_id"))
         client_secret (if basic (last basic) ((req :params) "client_secret"))
         client (authenticator client_id client_secret)]
          (if client 
            (success req client)
            (error-response "invalid_client"))))

(defn grant-type
  "extract grant type from request"
  [req _ _] ((req :params) "grant_type"))

(defmulti token-request-handler grant-type)

(defmethod token-request-handler "client_credentials" [req client-authenticator _]
  (client-authenticated-request 
    req 
    client-authenticator
    (fn [req client] (respond-with-new-token client client))))

(defmethod token-request-handler "password" [req client-authenticator user-authenticator]
  (client-authenticated-request 
    req 
    client-authenticator
    (fn [req client] (if-let [user (user-authenticator ((req :params) "username") ((req :params) "password"))]
                        (respond-with-new-token client client)
                        (error-response "invalid_grant")))))

(defmethod token-request-handler :default [req client-authenticator user-authenticator]
  (error-response "unsupported_grant_type"))


(defn token-handler
  ([]
    (token-handler clauth.client/authenticate-client clauth.user/authenticate-user))
  ([client-authenticator user-authenticator]
    (fn [req]
      (token-request-handler req client-authenticator user-authenticator)
      )))
 
(defn login-handler
  "present a login form to user and log them in by adding an access token to the session"
  ([client]
    (login-handler login-form-handler clauth.user/authenticate-user client))
  ([login-form client]
    (login-handler login-form clauth.user/authenticate-user client))
  ([login-form user-authenticator client]
    (csrf-protect!
      (fn [req]
        (if (= :get (req :request-method))
          (login-form req)
          (if-let [user (user-authenticator ((req :params) "username") ((req :params) "password"))]
            (let 
              [ destination ((req :session {}) :return-to "/")
                session ( dissoc (assoc (req :session) :access_token (:token (create-token client user))) :return-to )
              ]
              { :status 302
                :headers {"Content-Type" "text/html" "Location" destination}
                :session session
                :body "Redirecting to /"})
            (login-form req)))))))

(defn authorization-response
  "Create a proper redirection response depending on response_type"
  [req response_params ]
  (let [ params (req :params)
         redirect_uri (params "redirect_uri")]
    (redirect (str redirect_uri 
        (if (= (params "response_type") "token")
          "#"
          "?")
        (url-encode (merge response_params (filter val (select-keys (req :params) ["state"]))))
      ))))

(defn authorization-error-handler
  "redirect to client with error code"
  [req error]
  (authorization-response req { "error" error}))

(defn authorization-handler
  "present a login form to user and log them in by adding an access token to the session"
  ([]
    (authorization-handler authorization-form-handler))
  ([login-form]
    (require-user-session!
      (csrf-protect!
        (fn [req]
          (let [params (req :params)]
            (if (and (params "response_type") (params "client_id"))

              (if (= (params "response_type") "token")
                (if (= :get (req :request-method))
                  (authorization-form-handler req)
                )
                (authorization-error-handler req "unsupported_response_type")
              )
              (authorization-error-handler req "invalid_request"))))))))

