(ns clauth.user
  (:require [clauth.store :as store]
            [cheshire.core :as cheshire])
  (:import [org.mindrot.jbcrypt BCrypt]))

(defonce user-store (atom (store/create-memory-store)))

(defn bcrypt
  "Perform BCrypt hash of password"
  [password]
  (BCrypt/hashpw password (BCrypt/gensalt)))

(defn valid-password?
  "Verify that candidate password matches the hashed bcrypted password"
  [candidate hashed]
  (BCrypt/checkpw candidate hashed))

(defn new-user
  "Create new user record"
  ([attrs]
     attrs)
  ([login password & [name url]]
     {:login login :password (bcrypt password) :name name :url url}))

(defn reset-user-store!
  "mainly for used in testing. Clears out all users."
  []
  (store/reset-store! @user-store))

(defn fetch-user
  "Find user based on login"
  [t]
  (new-user (store/fetch @user-store t)))

(defn store-user
  "Store the given User and return it."
  [t]
  (store/store! @user-store :login t))

(defn users
  "Sequence of users"
  []
  (store/entries @user-store))

(defn register-user
  "create a unique user and store it in the user store"
  ([attrs]
     (store-user (new-user attrs)))
  ([login password] (register-user login password nil nil))
  ([login password name url]
     (register-user (new-user login password name url))))

(defn authenticate-user
  "authenticate user application using login and password"
  [login password]
  (if-let [user (fetch-user login)]
    (if (valid-password? password (:password user))
      user)))
