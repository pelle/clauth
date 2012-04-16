(defproject clauth "1.0.0-beta4"
  :description "OAuth2 based authentication library for Ring"
  :url "http://github.com/pelle/clauth"

  :dependencies [[org.clojure/clojure "1.3.0"] 
                 [crypto-random "1.1.0"]
                 [commons-codec "1.6"]
                 [ring/ring-core "1.1.0-beta3"]
                 [cheshire "3.1.0"]
                 [clj-time "0.3.7"]
                 [org.mindrot/jbcrypt "0.3m"]
                 [hiccup "1.0.0-RC1"]]

  :dev-dependencies [[ring/ring-jetty-adapter "1.0.0"]
                     [lein-marginalia "0.7.0"]
                     [org.clojars.tavisrudd/redis-clojure "1.3.1"]
                     [hiccup-bootstrap "0.1.0"]]
  :main clauth.demo)
