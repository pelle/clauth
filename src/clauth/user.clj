(ns clauth.user
    (:use [clauth.store])
    (:import [org.mindrot.jbcrypt BCrypt]))


(defonce user-store (atom (create-memory-store)))

(defrecord User
  [login password name url])

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
  ([attrs] ; Swiss army constructor. There must be a better way.
    (cond
      (nil? attrs) nil
      (instance? User attrs) attrs
      (instance? java.lang.String attrs) (new-user (cheshire.core/parse-string attrs true))
      :default (User. (attrs :login) (attrs :password) (attrs :name) (attrs :url))))

  ([ login password ] (new-user login password nil nil))
  ([ login password name url ] (User. login (bcrypt password) name url)))
  
(defn reset-user-store!
  "mainly for used in testing. Clears out all users."
  []
  (reset-store! @user-store))

(defn fetch-user
  "Find user based on login"
  [t]
  (new-user (fetch @user-store t)))

(defn store-user
  "Store the given User and return it."
  [t]
  (store! @user-store :login t))

(defn users
  "Sequence of users"
  []
  (entries @user-store))

(defn register-user 
  "create a unique user and store it in the user store"
  ([ login password ] (register-user login password nil nil))
  ([ login password name url ]
    (let [user (new-user login password name url)]
      (store-user user))))

(defn authenticate-user
  "authenticate user application using login and password"
  [login password]
  (if-let [ user (fetch-user login)]
    (if (valid-password? password (:password user))
      user
    )))
