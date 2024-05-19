(ns build
  (:refer-clojure :exclude [test])
  (:require [clojure.tools.build.api :as b]
            [deps-deploy.deps-deploy :as dd]
            ))

(def lib 'com.github.felixdo/axoloauth2)
(def version "0.1.0")
#_ ; alternatively, use MAJOR.MINOR.COMMITS:
(def version (format "1.0.%s" (b/git-count-revs nil)))
(def class-dir "target/classes")

(defn test "Run all the tests." [opts]
  (let [basis    (b/create-basis {:aliases [:test]})
        cmds     (b/java-command
                  {:basis      basis
                    :main      'clojure.main
                    :main-args ["-m" "cognitect.test-runner"]})
        {:keys [exit]} (b/process cmds)]
    (when-not (zero? exit) (throw (ex-info "Tests failed" {}))))
  opts)


(defn- jar-opts [opts]
  (assoc opts
          :lib lib :version version
          :jar-file (format "target/%s-%s.jar" lib version)
          :scm {:tag (str "v" version)}
          :basis (b/create-basis {})
          :class-dir class-dir
          :target "target"
          :src-dirs ["src"]))

(defn clean [_]
  (b/delete {:path "target"}))

(defn ci "Run the CI pipeline of tests (and build the JAR)." [opts]
  (test opts)
  (b/delete {:path "target"})
  (let [opts (jar-opts opts)]
    (println "\nWriting pom.xml...")
    (b/write-pom opts)
    (println "\nCopying source...")
    (b/copy-dir {:src-dirs ["resources" "src"] :target-dir class-dir})
    (b/copy-file {:src "LICENSE" :target (str class-dir "/LICENSE")})
    (println "\nBuilding JAR...")
    (b/jar opts))
  opts)

(defn install "Install the JAR locally." [opts]
  (let [opts (jar-opts opts)]
    (b/install opts))
  opts)

(defn deploy "Deploy the JAR to Clojars." [opts]
  (let [{:keys [jar-file] :as opts} (jar-opts opts)]
    (dd/deploy {:installer :remote :artifact (b/resolve-path jar-file)
                :pom-file (b/pom-path (select-keys opts [:lib :class-dir]))}))
  opts)


(defn uber [_]
  (clean nil)
  (let [basis (b/create-basis {})]
    (b/copy-dir {:src-dirs ["src" "resources"]
                 :target-dir class-dir})
    (b/compile-clj {:basis basis
                    :ns-compile '[axoloauth2.main]
                    :class-dir class-dir})
    (b/uber {:class-dir class-dir
             :uber-file (format "target/%s-%s-standalone.jar" (name lib) version)
             :basis basis })))
