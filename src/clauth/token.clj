(ns clauth.token
  (:require [clauth.store :as store]
            [crypto.random :as random]
            [clj-time
             [core :as time]
             [coerce :as coerce]]
            [cheshire.core :as cheshire]))

(defprotocol Expirable
  "Check if object is valid"
  (is-valid? [t] "is the object still valid"))

(extend-protocol Expirable clojure.lang.IPersistentMap
  (is-valid? [t] (if-let [expiry (:expires t)]
                   (time/after? (coerce/to-date-time expiry)
                                (time/now))
                   true)))

(extend-protocol Expirable nil (is-valid? [t] false))

(defn generate-token "generate a unique token" [] (random/base32 20))

(defn oauth-token
  "The oauth-token defines supports various functions to verify the validity

  The following keys are defined:

  * token - a unique token identifying it
  * client - a map/record of the client app who was issued the token
  * subject - the subject who authorized the token - eg. user
  * expires - Optional time of expiry
  * scope   - An optional vector of scopes authorized
  * object  - An optional object authorized. Eg. account, photo"

  ([attrs] ; Swiss army constructor. There must be a better way.
     (if attrs
       (if (:token attrs)
         attrs
         (assoc attrs :token (generate-token)))
       )
     )
  ([client subject]
     (oauth-token client subject nil nil nil))
  ([client subject expires scope object]
     (oauth-token (generate-token) client subject expires scope object))
  ([token client subject expires scope object]
     (oauth-token {:token token :client client :subject subject :expires expires :scope scope :object object})))

(defonce token-store (atom (store/create-memory-store)))

(defn reset-token-store!
  "mainly for used in testing. Clears out all tokens."
  []
  (store/reset-store! @token-store))

(defn fetch-token
  "Find OAuth token based on the token string"
  [t]
  (oauth-token (store/fetch @token-store t)))

(defn store-token
  "Store the given OAuthToken and return it."
  [t]
  (store/store! @token-store :token t))

(defn revoke-token
  "Revoke the given OAuth token, given either a token string or object."
  [t]
  (cond
   (instance? java.lang.String t) (store/revoke! @token-store t)
   :default (store/revoke! @token-store (:token t))))

(defn tokens
  "Sequence of tokens"
  []
  (map oauth-token (store/entries @token-store)))

(defn create-token
  "create a unique token and store it in the token store"
  ([client subject]
     (create-token (oauth-token client subject)))
  ([client subject scope object]
     (create-token client subject nil scope object))
  ([client subject expires scope object]
     (create-token (oauth-token client subject expires scope object)))
  ([token]
     (store-token (oauth-token token))))

(defn find-valid-token
  "return a token from the store if it is valid."
  [t]
  (if-let [token (fetch-token t)]
    (if (is-valid? token) token)))

(defn find-tokens-for
  "return tokens matching a given criteria"
  [criteria]
  (filter #(= criteria (select-keys % (keys criteria))) (tokens)))
