(ns clauth.demo
  (:use [clauth.middleware])
  (:use [ring.adapter.jetty])
  (:use [ring.middleware.cookies])
  (:use [ring.middleware.params]))


(defn handler [request]
  {:status 200
   :headers {"Content-Type" "application/json"}
   :body (if-let [token (request :oauth-token)]
                (str "{\"token\":\"" token "\"}")
                "{}"
          )})

(run-jetty (-> handler 
              (require-bearer-token! #{"secret"}) 
              (wrap-params) (wrap-cookies)) {:port 3000})