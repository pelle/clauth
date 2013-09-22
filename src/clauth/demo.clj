(ns clauth.demo
  (:require [clauth
             [middleware :as mw]
             [endpoints :as ep]
             [client :refer [client-store clients register-client]]
             [token :refer [token-store]]
             [user :refer [user-store]]
             [auth-code :refer [auth-code-store]]]
            [clauth.store.redis
             :refer [create-redis-store]]
            [ring.adapter.jetty :refer [run-jetty]]
            [ring.middleware
             [cookies :refer [wrap-cookies]]
             [session :refer [wrap-session]]
             [params :refer [wrap-params]]
             [keyword-params :refer [wrap-keyword-params]]]
            [hiccup.bootstrap
             [middleware :refer [wrap-bootstrap-resources]]
             [page :refer [include-bootstrap fixed-layout]]]
            [hiccup
             [page :refer [html5]]
             [element :refer [link-to unordered-list]]]))

(defn nav-menu [req]
  (if (ep/logged-in? req)
    [(link-to "/logout" "Logout")]
    [(link-to "/login" "Login")]))

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
  (mw/if-html req
    (use-layout req nil (clauth.views/hello-world req))
    {:status 200
     :headers {"Content-Type" "application/json"}
     :body (if-let [token (req :access-token)]
                  (str "{\"token\":\"" (str (:token token)) "\"}")
                  "{}")}))

(defn routes [master-client]
  (fn [req]
    (do
      ;; (prn (req :session))
      ;; (prn req)
      (case
       (req :uri)
       "/token" ((ep/token-handler) req)
       "/authorization" (use-layout req "Authorize App"
                                    ((ep/authorization-handler) req))
       "/login" (use-layout req "Login"
                            ((ep/login-handler {:client master-client}) req))
       "/logout" (ep/logout-handler req)
       ((mw/require-bearer-token! handler) req)))))


(defn -main
  "start web server. This first wraps the request in the cookies and params
   middleware, then requires a bearer token.

   The function passed in this example to require-bearer-token is a clojure set
   containing the single value \"secret\".

   You could instead use a hash for a simple in memory token database or a
   function querying a database."
  []
  (try
    (do
      (reset! token-store (create-redis-store "tokens"))
      (reset! auth-code-store (create-redis-store "auth-codes"))
      (reset! client-store (create-redis-store "clients"))
      (reset! user-store (create-redis-store "users"))
        (let [client (or (first (clients))
                         (register-client "Clauth Demo"
                                          "http://pelle.github.com/clauth"))
              user (or (first (clauth.user/users))
                       (clauth.user/register-user "demo" "password"))]
          (println "App starting up:")
          (prn client)
          (println
           (str "Token endpoint /token\n\n"
                "Fetch a Client Credentialed access token:\n\n"
                "curl http://127.0.0.1:3000/token "
                "-d grant_type=client_credentials -u "
                (clojure.string/join ":" [(:client-id client)
                                          (:client-secret client)])
                "\n\n"
                "Interactive login with demo/password\n\n"
                "http://127.0.0.1:3000/login"))

          (run-jetty (-> (routes client)
                         (wrap-keyword-params)
                         (wrap-params)
                         (wrap-cookies)
                         (wrap-session)
                         (wrap-bootstrap-resources)) {:port 3000})))

    (catch java.net.ConnectException e
      (println "You don't have a Redis database running in the background:"
               (.getMessage e)))))
