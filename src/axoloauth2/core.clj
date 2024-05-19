(ns axoloauth2.core
  (:import (java.security SecureRandom MessageDigest)
           (java.time OffsetDateTime Instant)
           (java.util Base64)
           (java.nio.file Files)
           (java.nio.file.attribute PosixFilePermission)
           )
  (:require
   [cheshire.core :as json]
   [clojure.string :as s]
   [clojure.java.browse :as browse]
   [clojure.java.io :as io]
   [babashka.http-client :as http]
   [babashka.fs :as fs]
   [clojure.edn :as edn]
   ))

(defonce xdg-app "axoloauth2")

(defn redirect-uri [port redirect-path]
  (str "http://localhost:" port redirect-path))

(defonce config-base
  (fs/xdg-config-home xdg-app))

(defn config-path
  [alias]
  (fs/path config-base (str (name alias) ".edn")))

(defonce cache-base
  (fs/xdg-cache-home xdg-app))

(defn cache-path
  [alias]
  (fs/path cache-base (str (name alias) ".json")))

(defn read-token-cache [alias]
  (let [f (fs/file (cache-path alias))]
    (when (fs/regular-file? f)
      (with-open [r (io/reader f)]
        (json/parse-stream r true)))))

(defn write-token-cache
  [alias content]
  (let [f (fs/file (cache-path alias))]
    (fs/create-dirs (fs/parent f))
    (with-open [w (io/writer f)]
      (json/generate-stream content w))
    (Files/setPosixFilePermissions
     (.toPath f)
     #{PosixFilePermission/OWNER_READ
       PosixFilePermission/OWNER_WRITE}))
  content)

(defn decode-base64 [to-decode]
  (String. (.decode (Base64/getDecoder) to-decode)))

(defn expires
  "expecting a jwt token get its expiration time"
  [token]
  (let [payload (json/parse-string (decode-base64 (second (s/split token #"\."))) true)
        exp (Instant/ofEpochSecond (:exp payload))]
    exp
    ))

(defn expired?
  "expecting a jwt token, checks if exp has passed, i.e. if the token has expired"
  [token]
  (or
   (nil? token)
   (let [now (Instant/now)
         exp (expires token)]
     (.isAfter now exp))))

(defn get-oauth2-token
  [config code redirect-port code-verifier]
  (-> (http/post (:token_uri config)
                 {:basic-auth [(:client_id config) (:client_secret config)]
                  :form-params {
                                :code code
                                :redirect_uri (redirect-uri redirect-port (:redirect_path config))
                                :grant_type "authorization_code"
                                :code_verifier code-verifier
                                :client_id (:client_id config)
                                }
                  })
      :body
      (json/parse-string true)))

(defn refresh-oauth2-token [config refresh-token]
  (-> (http/post (:token_uri config) {:basic-auth [(:client_id config) (:client_secret config)]
                                      :form-params
                                      {:grant_type "refresh_token"
                                       :refresh_token refresh-token}})
      :body
      (json/parse-string true)
      (select-keys [:access_token :id_token :refresh_token])))

(defn boring-login-response-body []
  (slurp (clojure.java.io/resource "axoloauth2/login.html")))

(defn cool-login-response-body []
  (let [cool-html (fs/path config-base "login.html")]
    (if (fs/regular-file? cool-html)
      (slurp (fs/file cool-html))
      (boring-login-response-body))))

(defn login-response []
  (str "HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: " (count (.. (cool-login-response-body) (getBytes "UTF-8")))"

" (cool-login-response-body)))


(defn make-auth-url [config port code-challenge state]
  (str
   (:auth_uri config)
   "?response_type=code"
   "&client_id=" (:client_id config)
   "&redirect_uri=" (redirect-uri port (:redirect_path config))
   "&scope=" (:scope config)
   "&state=" state
   "&code_challenge=" code-challenge
   "&code_challenge_method=S256"))

(defn make-pkce-verifier []
  (let [code (byte-array 32)]
    (.nextBytes (new SecureRandom) code)
    (.. (Base64/getUrlEncoder)
        withoutPadding
        (encodeToString code))))

(defn make-pkce-challenge
  [verifier]
  (let
      [bytes (.getBytes verifier "US-ASCII")
       md (MessageDigest/getInstance "SHA-256")
       ]
    (.update md bytes 0 (alength bytes))
    (let [digest (.digest md)]
      (.. (Base64/getUrlEncoder)
          withoutPadding
          (encodeToString digest)))))

(defn parse-query-string
  "Make keywordized map of the auth code query string.
   Fixme should url-decode, but it's no big deal as keys
   and values of the oauth redirect url shouldnt
   need any encoding"
  [request-path]
  (let [query (.getQuery (java.net.URL. (str "http://l" request-path)))]
    (reduce
     (fn [result kv]
       (let [[k v] (s/split kv #"=" 2)]
         (conj result [(keyword k) v])))
     {}
     (s/split query #"&"))
    )
  )

(defn verify-state [expected-state {:keys [state] :as all}]
  (if (= state expected-state)
    all
    (throw (IllegalStateException. "State in oauth2 redirect does not match expected state!"))))

(defn oauth2-redirect-listen
  "accepts incoming connection on server socket and extracts
  redirect query parameters as keywordized map. that map then
  - if all goes well - will contain for example the authorization
  code needed to get a token from the token endpoint"
  [server expect-state]
  (future
    (with-open [socket (.accept server)
                r (io/reader (.getInputStream socket))
                w (.getOutputStream socket)]
      (let [request-line (.readLine r)]
        (.write w (.getBytes (login-response)))
        (verify-state expect-state (parse-query-string
                                    (second (s/split request-line #"\s"))))))))

(defn get-authorization-code
  "Open browser and have user login in exchange for an authorization code.
   In addition to that authorization :code, the result also contains
   the dynamically allocated :redirect-port and the pkce :verifier code"
  [config]
  (let [server (new java.net.ServerSocket 0)
        port (.getLocalPort server)
        verifier (make-pkce-verifier)
        challenge (make-pkce-challenge verifier)
        state (make-pkce-verifier) ;; conveniently reuse the pkce generator also for the state..
        ]
    (.setSoTimeout server 60000)
    (try
      (let [f (oauth2-redirect-listen server state)
            u (make-auth-url config port challenge state)]
        (browse/browse-url u)
        (-> @f (assoc :redirect-port port :verifier verifier)))
      (finally
            (.close server)))))

(defn restart-oauth2-flow [config]
  (let [{:keys [code redirect-port verifier]} (get-authorization-code config)]
    (-> (get-oauth2-token config code redirect-port verifier)
        (select-keys [:access_token :refresh_token :id_token]))))

(defn read-config [alias]
  (with-open [r (java.io.PushbackReader. (io/reader (fs/file (config-path alias))))]
    (edn/read r)))

(defn get-or-refresh-token
  "Get a token of given type. config is a map storing required oauth parameters:
  If the previously stored token has expired try to refresh it and if the refresh token has also
  expired, run the authoriztion code flow, which will open a browser and ask for your password.
  Then persists the new tokens in .cookidoom-clj/freak/ and returns the token of the asked type which normally
  is :access_token"
  [alias token-type]
  (let [oldtoken (read-token-cache alias)
        refresh-token (:refresh_token oldtoken)
        oauth-config (read-config alias)
        newtoken (if (expired? (get oldtoken token-type))
                   (write-token-cache
                    alias
                    (if refresh-token
                      (refresh-oauth2-token oauth-config refresh-token)
                      (restart-oauth2-flow oauth-config)))
                   oldtoken)]
    (get newtoken token-type)))

(defn get-client-credentials-token
  "Debug helper to fetch token via client_credentials flow"
  [client-id client-secret token-endpoint]
  (http/post token-endpoint
               { :basic-auth [client-id client-secret ]
                :form-params
                {
                 :grant_type "client_credentials"
                 :client_id client-id
                 :client_secret client-secret
                 }}))

(comment
  (get-or-refresh-token :nonprod :access_token)
)
