(ns clauth.middleware
  (:use [clauth.token]
        [ring.util.response :only [redirect]]))

(defn wrap-bearer-token
  "Wrap request with a OAuth2 bearer token as defined in http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08.

  A find-token function is passed the token and returns a clojure map describing the subject of the token.

  It supports the following ways of setting the token.

  * [Authorization header](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.1)
  * [Form encoded body parameter](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.2)
  * [URI query field](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.3)
  * Non standard http cookie ('access_token') for use in interactive applications


  The subject is added to the :access-token key of the request."
  
  ([app]
    (wrap-bearer-token app clauth.token/find-valid-token ))
  ([app find-token]
    (fn [req]
      (let [auth ((:headers req {}) "authorization")
            token (or (last
                    (re-find #"^Bearer (.*)$" (str auth)))
                    ((:params req {}) :access_token)
                    ((:params req {}) "access_token")
                    ((:session req {}) :access_token)
                    (((:cookies req {}) "access_token" {}) :value )
                  )]
        (if-let [access-token (find-token token)]
          (app ( assoc req :access-token access-token))
          (app req))))))

(defn wrap-user-session
  "Wrap request with a OAuth2 token stored in the session. Use this for optional authentication where no API access is wished.

  A find-token function is passed the token and returns a clojure map describing the subject of the token.

  It supports the following ways of setting the token.


  The subject is added to the :access-token key of the request."
  
  ([app]
    (wrap-user-session app clauth.token/find-valid-token ))
  ([app find-token]
    (fn [req]
      (let [auth ((:headers req {}) "authorization")
            token ((:session req {}) :access_token)]
        (if-let [access-token (find-token token)]
          (app ( assoc req :access-token access-token))
          (app req))))))


(defn is-html?
  "returns true if request has text/html in the accept header"
  [req]
  (if-let [accept ((req :headers {}) "accept")]
    (re-find #"(text/html|application/xhtml\+xml)" accept)))

(defn is-form?
  "returns true if request has text/html in the accept header"
  [req]
  (if (or (not (:access-token req)) (and (:access-token req) (:access_token (req :session {}))))
    (if-let [content-type (req "content-type")]
      (if (seq (filter (partial  = content-type) ["application/x-www-form-urlencoded" "multipart/form-data"])) true))))

  
(defmacro if-html
  "if request is for a html page it runs the first handler if not the second"
  [req html api]
  `(if (is-html? ~req) ~html ~api))

(defmacro if-form
  "if request is url form encoded it runs the first handler if not the second"
  [req html api]
  `(if (is-form? ~req) ~html ~api))


(defn csrf-token
  "extract csrf token from request"
  [req]
  ((req :session {}) :csrf-token))

(defn with-csrf-token
  "add a csrf token to request"
  [req]
  (if (csrf-token req)
    req
    (let [token (crypto.random/base64 32)
      session (assoc (req :session {}) :csrf-token token)]
      (assoc req :session session))))

(defn csrf-protect!
  "add a csrf token to session and reject a post request without it"
  [app]
    (fn
      [req]
      (if-form req 
        (let [req (with-csrf-token req)
              token (csrf-token req)
              session (req :session)]
          (if (or 
                (= (:request-method req) :get)
                (= token ((req :params {}) :csrf-token)))
            (let [response (app req)
                  session (assoc (response :session (req :session)) :csrf-token token)]
              (assoc response :session session))

            { :status 403 }))
        (app req))))


(defn athentication-required-response 
  "Return HTTP 401 Response"
  [ req ]
  (if-html req 
    (assoc (redirect "/login") :session {:return-to (str (req :uri) "?" (req :query-string))})
    { :status  401
    :headers {
      "Content-Type" "text/plain"
      "WWW-Authenticate" "Bearer realm=\"OAuth required\""}
    :body "access denied" }))


(defn require-bearer-token!
  "Require request with a OAuth2 bearer token as defined in http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08.

  A find-token function is passed the token and returns a clojure map describing the token.

  It supports the following ways of setting the token.

  * [Authorization header](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.1)
  * [Form encoded body parameter](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.2)
  * [URI query field](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.3)
  * Non standard http cookie ('access_token') for use in interactive applications


  The token is added to the :access-token key of the request.

  will return a [HTTP 401 header](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.4) if no valid token is present."

  ([app]
    (require-bearer-token! app clauth.token/find-valid-token ))  
  ([app find-token]
    (wrap-bearer-token 
     (fn [req]
       (if (req :access-token)
           (app req)
           (athentication-required-response req ))) find-token)))

(defn request-uri [req]
  (if (req :query-string)
    (str (req :uri) "?" (req :query-string))
    (req :uri)))

(defn user-session-required-response 
  "Return HTTP 403 Response or redirects to login"
  [ req ]
  (if-html req 
    (assoc (redirect "/login") :session {:return-to (request-uri req)})
    { :status  403
      :headers {
        "Content-Type" "text/plain" }
      :body "Forbidden" }))

(defn require-user-session!
  "Require that user is authenticated via an access_token stored in the session.

  Use this to protect parts of your application that web services should not have access to.

  A find-token function is passed the token and returns a clojure map describing the token.

  The token is added to the :access-token key of the request.

  Will redirect user to login url if not authenticated and issue a 403 to other requests."

  ([app]
    (require-user-session! app clauth.token/find-valid-token ))  
  ([app find-token]
    (wrap-user-session
     (fn [req]
       (if (req :access-token)
           (app req)
           (user-session-required-response req ))) find-token)))
