(defproject clauth "1.0.0-rc9"
  :description "OAuth2 based authentication library for Ring"
  :url "http://github.com/pelle/clauth"

  :dependencies [[org.clojure/clojure "1.4.0"] 
                 [crypto-random "1.1.0"]
                 [commons-codec "1.6"]
                 [ring/ring-core "1.1.0"]
                 [cheshire "4.0.0"]
                 [clj-time "0.3.7"]
                 [org.mindrot/jbcrypt "0.3m"]
                 [hiccup "1.0.0"]]

  :dev-dependencies [[ring/ring-jetty-adapter "1.1.0"]
                     [lein-marginalia "0.7.0"]
                     [org.clojars.tavisrudd/redis-clojure "1.3.1"]
                     [hiccup-bootstrap "0.1.0"]]
  :clean-non-project-classes true )
 