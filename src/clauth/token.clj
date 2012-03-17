(ns clauth.token
    (:require [crypto.random])
    (:require [clj-time.core :as time]))


(def tokens 
  "In memory token store"
  (atom {})) 


(defprotocol Expirable
  "Check if object is valid"
  (is-valid? [ t ] "is the object still valid"))

(extend-protocol Expirable clojure.lang.IPersistentMap 
  (is-valid? [t] (if-let [expiry (:expires t)]
                          (time/after? expiry (time/now) )
                          true)))

(extend-protocol Expirable nil 
  (is-valid? [t] false))

(defrecord OAuthToken
  [token client subject expires scope object])

(defn generate-token 
  "generate a unique token"
  [] (crypto.random/base32 20))

(defn oauth-token
  "The oauth-token defines supports various functions to verify the validity

  The following keys are defined:

  * token - a unique token identifying it
  * client - a map/record of the client app who was issued the token
  * subject - the subject who authorized the token - eg. user
  * expires - Optional time of expiry
  * scope   - An optional vector of scopes authorized
  * object  - An optional object authorized. Eg. account, photo"

  ([client subject]
    (oauth-token client subject nil nil nil)
    )
  ([client subject expires scope object]
    (oauth-token (generate-token) client subject expires scope object)
    )
  ([token client subject expires scope object]
    (OAuthToken. token client subject expires scope object)
    )
  )

(defn create-token 
  "create a unique token and store it in the token store"
  ([client subject]
    (create-token (oauth-token client subject)))
  ([client subject expires scope object]
    (create-token (oauth-token client subject expires scope object)))
  ([ token ]
    (do 
      (swap! tokens assoc (:token token) token)
      token)))
  
(defn find-valid-token
  "return a token from the store if it is valid."
  [token]
  (if-let [t (@tokens token)]
    (if (is-valid? t) t )))
