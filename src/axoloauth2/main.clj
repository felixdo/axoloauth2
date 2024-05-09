(ns axoloauth2.main
  (:require
   [axoloauth2.core :as axo]
   [babashka.cli :as cli])
  (:gen-class))

(defn -main [& args]
  (let [opts (cli/parse-opts args)]
    (if-let [[env _] (first opts)]
      (do
        (println (axo/get-or-refresh-token env :access_token))
        (shutdown-agents))
      (do
        (println "Usage: axoloauth2 [--[alias]]")
        (System/exit 1)))))
