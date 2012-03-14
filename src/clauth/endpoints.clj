(ns clauth.endpoints
  (:use   [clauth.token])
  (:use   [clauth.client])
  (:use   [cheshire.core]))



(defn decorate-token 
  "Take a token map and decorate it according to specs

  http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-5.1"
  [token]

  { :access_token (token :token) :token_type "bearer"}
  )

(defn token-response 
  "Create a ring response for a token response"
  [token]
  {  :status 200
      :headers {"Content-Type" "application/json"}
      :body (generate-string (decorate-token token))})

(defn error-response 
  "Create a ring response for a oauth error"
  [error]
  {  :status 400
      :headers {"Content-Type" "application/json"}
      :body (generate-string {:error error })})


(defn respond-with-new-token
  "create a new token and respond with json"
  [client owner]
  (token-response (create-token { :client_id (client :client_id) :owner owner})))
  
(defn token-handler
  [authenticate-client]
  (fn [req]
    (let [ client_id ((req :params ) :client_id)
         client (authenticate-client client_id ((req :params) :client_secret))]
          (if client 
            (respond-with-new-token client client)
            (error-response "invalid_client")))))
 
