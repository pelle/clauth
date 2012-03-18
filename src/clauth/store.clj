(ns clauth.store)

(defprotocol OAuthTokenStore
  "Store OAuthTokens"
  (find-token [ e t ] "Find the token based on a token string.")
  (store-token [ e token ] "Store the given OAuthToken and return it.")
  (tokens [e] "sequence of tokens"))

(defrecord MemoryTokenStore [tokens] 
  OAuthTokenStore 
  (find-token [this t] (@tokens t))
  (store-token [this token]
    (do
      (swap! tokens assoc (:token token) token)
      token)
    )
  (tokens [this] (vals @tokens)))

(defn create-memory-token-store 
  "Create a memory token store"
  ([] (create-memory-token-store {}))
  ([data]
    (MemoryTokenStore. (atom data))))

(defonce token-store (atom (create-memory-token-store)))

(defn reset-memory-store!
  "mainly for used in testing. Clears out all tokens."
  []
  (reset! token-store (create-memory-token-store)))

