(defproject clauth "1.0.0-SNAPSHOT"
  :description "OAuth2 based authentication library for Ring"
  :url "http://github.com/pelle/clauth"

  :dependencies [[org.clojure/clojure "1.3.0"] 
                 [crypto-random "1.0.0"]
                 [commons-codec "1.6"]
                 [ring/ring-core "1.0.2"]]

  :dev-dependencies [[ring/ring-jetty-adapter "1.0.0"]
                     [lein-marginalia "0.7.0"]])
