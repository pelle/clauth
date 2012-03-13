(ns clauth.demo
  (:use [clauth.middleware])
  (:use [ring.adapter.jetty])
  (:use [ring.middleware.cookies])
  (:use [ring.middleware.params]))


(defn handler 
  "dummy ring handler. Returns json with the token if present."
  [request]
  {:status 200
   :headers {"Content-Type" "application/json"}
   :body (if-let [token (request :oauth-token)]
                (str "{\"token\":\"" token "\"}")
                "{}"
          )})

(defn demo 
  "start web server. This first wraps the request in the cookies and params middleware, then requires a bearer token.

  The function passed in this example to require-bearer-token is a clojure set containing the single value \"secret\".

  You could instead use a hash for a simple in memory token database or a function querying a database."
  []
  (run-jetty (-> handler 
              (require-bearer-token! #{"secret"}) 
              (wrap-params) 
              (wrap-cookies)) {:port 3000}))