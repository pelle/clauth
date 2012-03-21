(ns clauth.views
  (:use hiccup.core))

(defn login-form 
  ([] (login-form "/login" nil nil))
  ([req] (login-form (req :uri) ((req :params) "username") ((req :params) "password")))
  ([uri username password]
    (html
      [:form {:action uri :method :post}
        [:label {:for "username"} "User name:"]
        [:input {:type "text" :id "username" :name "username" :value username}]

        [:label {:for "password"} "Password:"]
        [:input {:type "password" :id "password" :name "password" :value password }]

        [:button {:type "submit" :class "btn"} "Login"]])))

(defn login-form-handler
  "Login form ring handler"
  [req]
  {
    :status 200
    :headers {"Content-Type" "text/html"}
    :body (login-form req)})