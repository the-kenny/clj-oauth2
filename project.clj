(defproject clj-oauth2 "0.4.0-SNAPSHOT"
  :description "clj-http and ring middlewares for OAuth 2.0"
  :dependencies [[org.clojure/clojure "1.7.0"]
                 [cheshire "5.5.0"][org.clojure/data.json "0.1.1"]
                 [clj-http "0.3.2"]
                 [uri "1.1.0"]
                 [commons-codec/commons-codec "1.6"]
                 [ring "1.4.0"]]
  :repositories {"stuartsierra-releases" "http://stuartsierra.com/maven2"}
  :aot [clj-oauth2.OAuth2Exception
        clj-oauth2.OAuth2StateMismatchException])
