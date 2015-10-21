(defproject clj-oauth2 "0.5.0"
  :description "clj-http and ring middlewares for OAuth 2.0"
  :dependencies [[org.clojure/clojure "1.7.0"]
                 [cheshire "5.5.0"]
                 [clj-http "0.3.2"]
                 [uri "1.1.0"]
                 [commons-codec/commons-codec "1.6"]
                 [ring "1.4.0"]]
  :aot [clj-oauth2.OAuth2Exception
        clj-oauth2.OAuth2StateMismatchException])
