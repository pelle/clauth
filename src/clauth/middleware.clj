(ns clauth.middleware)

(defn wrap-bearer-token
  "Wrap response with a OAuth2 bearer token as defined in http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08.

  A find-token function is passed the token and returns a clojure map describing the subject of the token.

  This subject is added to the :oauth-token key of the request."
  
  [app find-token]
    (fn [req]
      (let [auth ((:headers req {}) "authorization")
            token (or (last
                    (re-find #"^Bearer (.*)$" (str auth)))
                    ((:params req {}) :access_token)
                  )]
        (if-let [subject (find-token token)]
          (app (assoc req :oauth-token subject))
          (app req)))))

