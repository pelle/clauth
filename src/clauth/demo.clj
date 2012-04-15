(ns clauth.demo
  (:require [redis.core :as redis])
  (:use [clauth.middleware]
        [clauth.endpoints]
        [clauth.client]
        [clauth.token]
        [clauth.store.redis]
        [ring.adapter.jetty]
        [ring.middleware.cookies]
        [ring.middleware.session]
        [ring.middleware.params]
        [ring.middleware.keyword-params]
        [hiccup.bootstrap.middleware]
        [hiccup.bootstrap.page]
        [hiccup.page]
        [hiccup.element]))

(defn nav-menu [req]
  (if (logged-in? req)
    [(link-to "/logout" "Logout")]
    [(link-to "/login" "Login")]
    ))

(defn layout [req title & body]
  (html5
    [:head
      [:title (or title "Clauth demo")]
      (include-bootstrap)]
    [:body
      (fixed-layout
        [:div {:class "navbar"}
          [:div {:class "navbar-inner"}
            [:div {:class "container"}
              [:a {:href "/" :class "brand"} "Clauth"]
              (unordered-list {:class "nav"} (nav-menu req))]]]
        [:h1 (or title "Clauth demo")]
        body)]))

(defn use-layout 
  "Wrap a response with a layout"
  [req title response]
  (assoc response :body (layout req title (response :body))))

(defn handler 
  "dummy ring handler. Returns json with the token if present."
  [req]
  (if-html req
    (use-layout req nil (clauth.views/hello-world req))
    {:status 200
     :headers {"Content-Type" "application/json"}
     :body (if-let [token (req :access-token)]
                  (str "{\"token\":\"" (str (:token token)) "\"}")
                  "{}"
          )}))

(defn routes [master-client]
  (fn [req]
    (do
      ; (prn (req :session))
      ; (prn req)
    (case (req :uri)
      "/token" ((token-handler) req )
      "/authorization" (use-layout req "Authorize App" ((authorization-handler) req ))
      "/login" (use-layout req "Login" ((login-handler master-client) req ))
      "/logout" (logout-handler req )
      ((require-bearer-token! handler) req)))))

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
                (wrap-keyword-params) 
                (wrap-params) 
                (wrap-cookies)
                (wrap-session)                
                (wrap-redis-store)
                (wrap-bootstrap-resources)) {:port 3000})))))
