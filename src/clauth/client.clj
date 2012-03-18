(ns clauth.client
    (:use [clauth.token])
    (:use [clauth.store]))


(defonce client-store (atom (create-memory-store)))

(defrecord ClientApplication
  [client-id client-secret name url])

(defn client-app
  "Create new client-application record"
  ([] (client-app nil nil))
  ([name url] (ClientApplication. (generate-token) (generate-token) name url)))
  
(defn reset-client-store!
  "mainly for used in testing. Clears out all clients."
  []
  (reset-store! @client-store))

(defn fetch-client
  "Find OAuth token based on the token string"
  [t]
  (fetch @client-store t))

(defn store-client
  "Store the given ClientApplication and return it."
  [t]
  (store @client-store :client-id t))

(defn clients
  "Sequence of clients"
  []
  (entries @client-store))

(defn register-client 
  "create a unique client and store it in the client store"
  ([] (register-client nil nil))
  ([ name url ]
    (let [client (client-app name url)]
      (store-client client))))

(defn authenticate-client
  "authenticate client application using client_id and client_secret"
  [client-id client-secret]
  (if-let [ client (fetch-client client-id)]
    (if (= client-secret (:client-secret client))
      client
    )))
