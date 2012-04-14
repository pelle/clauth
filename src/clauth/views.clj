(ns clauth.views
  (:use ring.util.response)
  (:use [clauth.middleware :only [csrf-token]])
  (:use hiccup.core)
  (:use hiccup.form))

(defn csrf-field 
  "hidden form field containing csrf-token"
  [req]
  (hidden-field :csrf-token (csrf-token req)))

(defn include-hidden-params
  "Include certain parameters as hidden fields if present"
  [{ params :params} fields]
    (map #(hidden-field (key %) (val %)) 
    (filter val (select-keys params fields))))

(defn login-form 
  ([req] (login-form req (req :uri) ((req :params) "username") ((req :params) "password")))
  ([req uri username password]
    (html
      (form-to [:post (req :uri)]
        (csrf-field req)
        (label :username "User name:")
        (text-field :username username)
        (label :password "Password:")
        (password-field :password password)
        [:div {:class "form-actions"}
          [:button {:type "submit" :class "btn btn-primary"} "Login"]]))))

(defn login-form-handler
  "Login form ring handler"
  [req]
  {
    :status 200
    :headers {"Content-Type" "text/html"}
    :body (login-form req)})

(defn authorization-form 
  ([req]
    (html
      (form-to [:post (req :uri)]
        (csrf-field req)
        (include-hidden-params req ["client_id" "response_type" "redirect_uri" "scope" "state"])
        [:div {:class "form-actions"}
          [:button {:type "submit" :class "btn btn-primary"} "Authorize"]
          [:a {:class "btn" :href (or ((req :params) "redirect_uri") "/")} "Cancel"]]))))

(defn authorization-form-handler
  "Login form ring handler"
  [req]
  {
    :status 200
    :headers {"Content-Type" "text/html"}
    :body (authorization-form req)})

(defn error-page
  "returns a simple error page"
  [error]
  (response (html
    [:h1 error])
  ))

(defn hello-world
  [req]
  (let [user (:subject (req :access-token))]
    (response (html
              [:h1 "Hello " (:login user)]))))