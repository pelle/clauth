(ns clauth.client
  (:require [clauth
             [token :refer [generate-token]]
             [store :as store]]))

(defonce client-store (atom (store/create-memory-store)))

(defn client-app
  "Create new client-application record"
  ([attrs]
     (if attrs
       (merge attrs
              {:client-id (:client-id attrs (generate-token))
               :client-secret (:client-secret attrs (generate-token))})))
  ([] (client-app nil nil))
  ([name url] (client-app {:name name :url url})))

(defn reset-client-store!
  "mainly for used in testing. Clears out all clients."
  []
  (store/reset-store! @client-store))

(defn fetch-client
  "Find OAuth token based on the id string"
  [t]
  (client-app (store/fetch @client-store t)))

(defn store-client
  "Store the given ClientApplication and return it."
  [t]
  (store/store! @client-store :client-id t))

(defn clients
  "Sequence of clients"
  []
  (store/entries @client-store))

(defn register-client
  "create a unique client and store it in the client store"
  ([] (register-client nil nil))
  ([name url]
     (let [client (client-app name url)]
       (store-client client))))

(defn authenticate-client
  "authenticate client application using client_id and client_secret"
  [client-id client-secret]
  (if-let [client (fetch-client client-id)]
    (if (= client-secret (:client-secret client))
      client)))
