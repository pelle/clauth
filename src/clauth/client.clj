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
  
