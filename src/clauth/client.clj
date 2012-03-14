(ns clauth.client
    (:use [clauth.token]))


(def clients 
  "In memory client store"
  (atom {})) 

(defn register-client 
  "create a unique client and store it in the client store"
  [ attrs ]
  (let [client-id (generate-token)
        record (assoc attrs :client-id client-id :client-secret (generate-token))]
    (do 
      (swap! clients assoc client-id record)
      record)))
  
(defn authenticate-client
  "authenticate client application using client_id and client_secret"
  [client-id client-secret]
  (if-let [ client (@clients client-id)]
    (if (= client-secret (client :client-secret))
      client
    )))