(defproject clauth "1.0.0-rc17"
  :description "OAuth2 based authentication library for Ring"
  :url "http://github.com/pelle/clauth"
  :dependencies [[org.clojure/clojure "1.5.1"]
                 [crypto-random "1.2.0"]
                 [commons-codec "1.10"]
                 [ring/ring-core "1.4.0"]
                 [cheshire "5.5.0"]
                 [clj-time "0.11.0"]
                 [de.svenkubiak/jBCrypt "0.4.1"]
                 [hiccup "1.0.5"]]

  :profiles {:dev {
                   :dependencies [[ring/ring-jetty-adapter "1.4.0"]
                     [lein-marginalia "0.8.0"]
                     [com.taoensso/carmine "2.12.2"]
                     [hiccup-bootstrap "0.1.2"]]}}
  :clean-non-project-classes true )

