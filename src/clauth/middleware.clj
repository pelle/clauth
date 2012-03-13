(ns clauth.middleware)

(defn wrap-bearer-token
  "Wrap request with a OAuth2 bearer token as defined in http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08.

  A find-token function is passed the token and returns a clojure map describing the subject of the token.

  It supports the following ways of setting the token.

  * [Authorization header](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.1)
  * [Form encoded body parameter](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.2)
  * [URI query field](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.3)
  * Non standard http cookie ('access_token') for use in interactive applications


  The subject is added to the :oauth-token key of the request."
  
  [app find-token]
    (fn [req]
      (let [auth ((:headers req {}) "authorization")
            token (or (last
                    (re-find #"^Bearer (.*)$" (str auth)))
                    ((:params req {}) "access_token")
                    (((:cookies req {}) "access_token" {}) :value )
                  )]
        (if-let [subject (find-token token)]
          (app (assoc req :oauth-token subject))
          (app req)))))

(defn athentication-required-response 
  "Return HTTP 401 Response"
  [ req ]
  { :status  401
    :headers {
      "Content-Type" "text/plain"
      "WWW-Authenticate" "Bearer realm=\"OAuth required\""}
    :body "access denied" })

(defn require-bearer-token!
  "Require request with a OAuth2 bearer token as defined in http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08.

  A find-token function is passed the token and returns a clojure map describing the subject of the token.

  It supports the following ways of setting the token.

  * [Authorization header](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.1)
  * [Form encoded body parameter](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.2)
  * [URI query field](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.3)
  * Non standard http cookie ('access_token') for use in interactive applications


  The subject is added to the :oauth-token key of the request.

  will return a [HTTP 401 header](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.4) if no valid token is present."

  
  ([app find-token]
    (wrap-bearer-token 
     (fn [req]
       (if (req :oauth-token)
           (app req)
           (athentication-required-response req ))) find-token)))
