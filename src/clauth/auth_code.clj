(ns clauth.auth-code
    (:use [clauth.store]
          [clauth.token])
    (:require [crypto.random]
              [clj-time.core :as time]
              [clj-time.coerce]
              [cheshire.core]))


(defrecord OAuthCode
  [code client subject expires scope object])

(defn oauth-code
  "The oauth-code defines supports various functions to verify the validity

  The following keys are defined:

  * auth-code - a unique auth-code identifying it
  * client - a map/record of the client app who was issued the auth-code
  * subject - the subject who authorized the auth-code - eg. user
  * expires - Optional time of expiry
  * scope   - An optional vector of scopes authorized
  * object  - An optional object authorized. Eg. account, photo"

  ([attrs] ; Swiss army constructor. There must be a better way.
    (cond
      (nil? attrs) nil
      (instance? OAuthCode attrs) attrs
      (instance? java.lang.String attrs) (oauth-code (cheshire.core/parse-string attrs true))
      :default (OAuthCode. (attrs :code) (attrs :client) (attrs :subject) (attrs :expires) (attrs :scope) (attrs :object))))
  ([client subject]
    (oauth-code client subject nil nil)
    )
  ([client subject scope object]
    (oauth-code (generate-token) client subject scope object)
    )
  ([code client subject scope object]
    (OAuthCode. code client subject (clj-time.coerce/to-date (time/plus (time/now) (time/days 1))) scope object)
    )
  )

(defonce auth-code-store (atom (create-memory-store)))

(defn reset-auth-code-store!
  "mainly for used in testing. Clears out all auth-codes."
  []
  (reset-store! @auth-code-store))

(defn fetch-auth-code
  "Find OAuth auth-code based on the auth-code string"
  [t]
  (oauth-code (fetch @auth-code-store t)))

(defn revoke-auth-code!
  "Revoke the auth code so it can no longer be used"
  [code]
  (revoke! @auth-code-store (:code code)))

(defn store-auth-code
  "Store the given OAuthCode and return it."
  [t]
  (store! @auth-code-store :code t))

(defn auth-codes
  "Sequence of auth-codes"
  []
  (map oauth-code (entries @auth-code-store)))

(defn create-auth-code 
  "create a unique auth-code and store it in the auth-code store"
  ([client subject]
    (create-auth-code (oauth-code client subject)))
  ([client subject scope object]
    (create-auth-code (oauth-code client subject scope object)))
  ([ auth-code ]
    (store-auth-code auth-code)
    ))
  
(defn find-valid-auth-code
  "return a auth-code from the store if it is valid."
  [t]
  (if-let [oauth-code (fetch-auth-code t)]
    (if (is-valid? oauth-code) oauth-code )))
