(ns clauth.endpoints
  (:use   [clauth.token]
          [clauth.client]
          [clauth.user]
          [clauth.auth-code]
          [clauth.middleware :only [csrf-protect! require-user-session!]]
          [clauth.views :only [login-form-handler authorization-form-handler error-page]]
          [hiccup.util :only [url-encode]]
          [ring.util.response]
          [cheshire.core])
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
  "create a new token and respond with json. If using built in token system it takes client and subject (user).
   You can also pass a function to it and the client and subject."
  ([client subject]
    (respond-with-new-token create-token client subject))
  ([token-creator client subject]
    (token-response (token-creator client subject))))

(defn basic-authentication-credentials 
  "decode basic authentication credentials.

   If it exists it returns a vector of username and password.

   If not nil."
  [req]
  (if-let [ auth-string ((req :headers {}) "authorization")]
    (if-let [ basic-token (last (re-find #"^Basic (.*)$" auth-string)) ]
      (if-let [ credentials (String. (Base64/decodeBase64 basic-token))]
        (clojure.string/split credentials #":" )
      ))))

(defn client-authenticated-request 
  "Check that request is authenticated by client either using Basic authentication or url form encoded parameters.

   The client_id and client_secret are checked against the authenticate-client function.

   If authenticate-client returns a client map it runs success function with the request and the client."
  [req authenticator success]
  (let [ basic (basic-authentication-credentials req)
         client_id (if basic (first basic) ((req :params ) :client_id))
         client_secret (if basic (last basic) ((req :params) :client_secret))
         client (authenticator client_id client_secret)]
          (if client 
            (success req client)
            (error-response "invalid_client"))))

(defn grant-type
  "extract grant type from request"
  [req _] ((req :params) :grant_type))

(defmulti token-request-handler grant-type)

(defmethod token-request-handler "client_credentials" 
  [req { :keys [client-authenticator token-creator]}]
  (client-authenticated-request 
    req 
    client-authenticator
    (fn [req client] (respond-with-new-token token-creator client client))))

(defmethod token-request-handler "authorization_code" 
  [req { :keys [ client-authenticator token-creator auth-code-lookup auth-code-revoker ]}]
  (client-authenticated-request 
    req 
    client-authenticator
    (fn [req client] 
      (if-let [code (auth-code-lookup ((req :params) :code))]
        (if (and  (= (:client-id client) (:client-id (:client code)))
                  (= (:redirect-uri code) ((req :params) :redirect_uri)))
          (let [ _ (auth-code-revoker code)                  
                 token (token-creator client (:subject code) (:scope code) (:object code))]
             (token-response token))
          (error-response "invalid_grant"))
        (error-response "invalid_grant")))))
      

(defmethod token-request-handler "password" 
  [req { :keys [ client-authenticator token-creator user-authenticator]} ]
  (client-authenticated-request 
    req 
    client-authenticator
    (fn [req client] (if-let [user (user-authenticator ((req :params) :username) ((req :params) :password))]
                        (respond-with-new-token token-creator client user)
                        (error-response "invalid_grant")))))

(defmethod token-request-handler :default [req _]
  (error-response "unsupported_grant_type"))


(defn token-handler
  "Ring handler that issues oauth tokens.

  Configure it by passing an optional map containing:

  :client-authenticator a function that returns a client record when passwed a correct client_id and client secret combo
  :user-authenticator a function that returns a user when passwed a correct username and password combo
  :auth-code-lookup  a function which returns a auth code record when passed it's code string
  :token-creator a function that creates a new token when passed a client and a user
  :auth-code-revoker a function that revokes a auth-code when passed an auth-code record"
  ([]
    (token-handler {}))
  ([client-authenticator user-authenticator]
    (token-handler {:client-authenticator client-authenticator :user-authenticator user-authenticator}))
  ([config]
    (fn [req]
      (token-request-handler req (merge { :client-authenticator clauth.client/authenticate-client 
                                          :user-authenticator clauth.user/authenticate-user
                                          :token-creator create-token
                                          :auth-code-revoker revoke-auth-code! 
                                          :auth-code-lookup fetch-auth-code } config)))))
 
(defn login-handler
  "Present a login form to user and log them in by adding an access token to the session.

  Configure it by passing the following to a map:

  Required value
  :client the site's own client application record

  Optional entries to customize functionality:
  :login-form a ring handler to display a login form
  :user-authenticator a function that returns a user when passwed a correct username and password combo
  :token-creator a function that creates a new token when passed a client and a user"
  [config]
    (let [config (merge { :login-form login-form-handler
                          :user-authenticator clauth.user/authenticate-user
                          :token-creator clauth.token/create-token } config)
          {:keys [client login-form user-authenticator token-creator]} config ]
      (csrf-protect!
        (fn [{:keys [request-method params session] :as req} ]
          (if (= :get request-method)
            (login-form req)
            (if-let [user (user-authenticator (params :username) (params :password))]
              (let 
                [ destination (session :return-to "/")
                  session ( dissoc (assoc session :access_token (:token (token-creator client user))) :return-to )]
                { :status 302
                  :headers {"Content-Type" "text/html" "Location" destination}
                  :session session
                  :body "Redirecting to /"})
              (login-form req)))))))

(defn logout-handler
  "logout user"
  [req]
    (assoc (redirect "/") :session ( dissoc (req :session) :access_token)))

(defn logged-in?
  "returns true if request is logged in"
  [req]
  (not (nil? (req :access-token))))
  
(defn current-user
  "returns current user associated with request"
  [req]
  (if (logged-in? req)
    (:subject (req :access-token))))
  
(defn authorization-response
  "Create a proper redirection response depending on response_type"
  [req response_params ]
  (let [ params (req :params)
         redirect_uri (params :redirect_uri)]
    (redirect (str redirect_uri 
        (if (= (params :response_type) "token")
          "#"
          "?")
        (url-encode (merge response_params (filter val (select-keys (req :params) [:state]))))
      ))))

(defn authorization-error-response
  "redirect to client with error code"
  [req error]
  (if ((req :params) :redirect_uri)
    (authorization-response req { "error" error })
    (error-page error)))

(defn response-type
  "extract grant type from request"
  [req _] ((req :params) :response_type))

(defmulti authorization-request-handler response-type)

(defmethod authorization-request-handler "token" [req {:keys [client-lookup token-lookup token-creator ]}]
  (let [ params (req :params)
         client (client-lookup (params :client_id))
         user ( :subject (token-lookup (:access_token (req :session))))
         token (token-creator client user)]
    (authorization-response req {:access_token (:token token) :token_type "bearer"})))

(defmethod authorization-request-handler "code" [req {:keys [client-lookup token-lookup auth-code-creator ]}]
  (let [ params (req :params)
         client (client-lookup (params :client_id))
         user ( :subject (token-lookup (:access_token (req :session))))
         code (auth-code-creator client user (:redirect_uri params))]
    (authorization-response req {:code (:code code)})))

(defmethod authorization-request-handler :default [req]
  (authorization-error-response req "unsupported_grant_type"))

(defn authorization-handler
  "present a login form to user and log them in by adding an access token to the session

  Configure it by passing an optional map containing:

  :authorization-form a ring handler to display a authorization form
  :client-lookup a function which returns a client when passed its client_id
  :token-lookup  a function which returns a token record when passed it's token string
  :token-creator a function that creates a new token when passed a client and a user
  :auth-code-creator a function that creates an authorization code record when passed a client, user and redirect uri"
  ([]
    (authorization-handler {}))
  ([config]
    (let [config (merge {:authorization-form authorization-form-handler
                        :client-lookup clauth.client/fetch-client
                        :token-lookup clauth.token/fetch-token
                        :token-creator clauth.token/create-token 
                        :auth-code-creator clauth.auth-code/create-auth-code} config)
          authorization-form (config :authorization-form)]

      (require-user-session!
        (csrf-protect!
          (fn [ {:keys [params] :as req}]
            (if (and (params :response_type) (params :client_id))
              (if (some (partial = (params :response_type)) ["code" "token"] )
                (if (= :get (req :request-method))
                  (authorization-form req)
                  (authorization-request-handler req config)
                )
                (authorization-error-response req "unsupported_response_type")
              )
              (authorization-error-response req "invalid_request"))))))))

