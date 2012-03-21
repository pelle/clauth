(ns clauth.demo
  (:use [clauth.middleware])
  (:use [clauth.endpoints])
  (:use [clauth.client])
  (:use [clauth.token])
  (:use [clauth.store.redis])
  (:require [redis.core :as redis])
  (:use [ring.adapter.jetty])
  (:use [ring.middleware.cookies])
  (:use [ring.middleware.session])
  (:use [ring.middleware.params]))


(defn handler 
  "dummy ring handler. Returns json with the token if present."
  [request]
  (if-html request
    (clauth.views/hello-world request)
    {:status 200
     :headers {"Content-Type" "application/json"}
     :body (if-let [token (request :access-token)]
                  (str "{\"token\":\"" (str (:token token)) "\"}")
                  "{}"
          )}))

(defn routes [master-client]
  (fn [req]
    (case (req :uri)
      "/token" ((token-handler) req )
      "/login" ((login-handler master-client) req )
      ((require-bearer-token! handler) req))))

(defn wrap-redis-store [app]
  (fn [req]
    (redis/with-server
     {:host "127.0.0.1"
      :port 6379
      :db 14
     }
     (app req))))

(defn -main 
  "start web server. This first wraps the request in the cookies and params middleware, then requires a bearer token.

  The function passed in this example to require-bearer-token is a clojure set containing the single value \"secret\".

  You could instead use a hash for a simple in memory token database or a function querying a database."
  []
   (do 

    (reset! token-store (create-redis-store "tokens"))
    (reset! client-store (create-redis-store "clients"))
    (redis/with-server
     {:host "127.0.0.1"
      :port 6379
      :db 14
     }
    (let [client ( or (first (clients)) (register-client))
          user ( or (first (clauth.user/users)) (clauth.user/register-user "demo" "password"))] 
      (println "App starting up:")
      (prn client)
      (println "Token endpoint /token")
      (println)
      (println "Fetch a Client Credentialed access token:")
      (println)
      (println "curl http://127.0.0.1:3000/token -d grant_type=client_credentials -u " (clojure.string/join ":" [(:client-id client) (:client-secret client)]) )
      (println)
      (println "Interactive login with demo/password")
      (println)
      (println "http://127.0.0.1:3000/login")

      (run-jetty (-> (routes client)
                (wrap-params) 
                (wrap-cookies)
                (wrap-session)
                (wrap-redis-store)) {:port 3000})))))
