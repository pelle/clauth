(ns clauth.middleware
  (:use [clauth.token])
  (:use [ring.util.response :only [redirect]]))

(defn wrap-bearer-token
  "Wrap request with a OAuth2 bearer token as defined in http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08.

  A find-token function is passed the token and returns a clojure map describing the subject of the token.

  It supports the following ways of setting the token.

  * [Authorization header](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.1)
  * [Form encoded body parameter](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.2)
  * [URI query field](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.3)
  * Non standard http cookie ('access_token') for use in interactive applications


  The subject is added to the :oauth-token key of the request."
  
  ([app]
    (wrap-bearer-token app clauth.token/find-valid-token ))
  ([app find-token]
    (fn [req]
      (let [auth ((:headers req {}) "authorization")
            token (or (last
                    (re-find #"^Bearer (.*)$" (str auth)))
                    ((:params req {}) "access_token")
                    ((:session req {}) :access_token)
                    (((:cookies req {}) "access_token" {}) :value )
                  )]
        (if-let [access-token (find-token token)]
          (app ( assoc req :access-token access-token))
          (app req))))))

(defn is-html?
  "returns true if request has text/html in the accept header"
  [req]
  (if-let [accept ((req :headers {}) "accept")]
    (re-find #"(text/html|application/xhtml\+xml)" accept)))
  
(defmacro if-html
  "if request is for a html page it runs the first handler if not the second"
  [req html api]
  `(if (is-html? ~req) ~html ~api))

(defn athentication-required-response 
  "Return HTTP 401 Response"
  [ req ]
  (if-html req 
    (redirect "/login")
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
