;; This Source Code Form is subject to the terms of the Mozilla Public
;; License, v. 2.0. If a copy of the MPL was not distributed with this
;; file, You can obtain one at http://mozilla.org/MPL/2.0/.
;;
;; Copyright (c) KALEIDOS INC Sucursal en España SL

(ns app.auth
  (:require
   [app.common.data :as d]
   [app.common.exceptions :as ex]
   [app.common.logging :as l]
   [app.common.time :as ct]
   [app.config :as cf]
   [app.http.client :as http]
   [app.util.json :as json]
   [buddy.hashers :as hashers]
   [buddy.sign.jwk :as jwk]
   [buddy.sign.jwt :as jwt]
   [clojure.string :as str]
   [cuerdas.core :as cstr]
   [java-http-clj.core :as jhttp]))

(def ^:private default-options
  {:alg :argon2id
   :memory 32768 ;; 32 MiB
   :iterations 3
   :parallelism 2})

(def ^:private weak-options
  {:alg :pbkdf2+sha256
   :iterations 100})

(defn derive-password
  [password]
  (hashers/derive password default-options))

(defn derive-password-weak
  "Derives a password using a fast algorithm (pbkdf2+sha256, 100 iterations).
   Intended for demo users only."
  [password]
  (hashers/derive password weak-options))

(defn verify-password
  [attempt password]
  (try
    (hashers/verify attempt password default-options)
    (catch Throwable _
      {:update false
       :valid false})))

;; ----------------------------------------------------------------------
;; INFRA-SSO-2/3: JWT verification via Authentik JWKS (penpot)
;; Verifier contract (locked):
;; - RS256-only. Reject none, HS256/384/512, RS384/512, ES*, PS*, EdDSA.
;;   No fallback to OIDC client secret (alg-confusion closed).
;; - Exact iss https://auth.iswe.co.nz/application/o/penpot/ (trailing slash).
;; - Exact aud penpot as string. Arrays and other strings reject.
;; - exp required, enforced with 60s leeway. Missing exp rejects.
;; - nbf enforced with 60s leeway when present.
;; - JWKS from PENPOT_JWT_VERIFY_URL or PENPOT_OIDC_JWKS or
;;   PENPOT_OIDC_JWKS_URI, else discovered via .well-known, else
;;   issuer + /jwks/. Never hardcode jwks_uri.
;; - kid rotation: 10m cache TTL, refetch once on kid miss.
;; - sub authority: sub is Authentik user_email (per_provider issuer_mode,
;;   sub_mode user_email). Email -> profile lookup lives in
;;   app.http.session (case-insensitive lower(email) match). Unknown email
;;   logs no-profile and yields nil (not an error).
;; - Errors mapped: return nil, log hint, no stack to caller.
;; ----------------------------------------------------------------------

(def ^:private default-issuer "https://auth.iswe.co.nz/application/o/penpot/")
(def ^:private default-audience "penpot")
(def ^:private default-jwks-path "/jwks/")

(defn- jwt-issuer
  []
  (or (cf/get :jwt-issuer)
      default-issuer))

(defn- jwt-audience
  []
  (or (cf/get :jwt-audience)
      default-audience))

(defn- jwt-verify-url-raw
  "Resolve JWKS URL from env (not hardcode). Checks PENPOT_JWT_VERIFY_URL, PENPOT_OIDC_JWKS, PENPOT_OIDC_JWKS_URI in order."
  []
  (or (cf/get :jwt-verify-url)
      (cf/get :oidc-jwks)
      (cf/get :oidc-jwks-uri)
      nil))

(defn- discover-jwks-uri
  "Fetch .well-known/openid-configuration from issuer to discover jwks_uri. Returns string or nil."
  [cfg issuer]
  (try
    (let [well-known (str (cstr/rtrim issuer "/") "/.well-known/openid-configuration")
          rsp (http/req cfg {:method :get :uri well-known} {:skip-ssrf-check? true})]
      (when (= 200 (:status rsp))
        (let [data (-> (:body rsp) json/decode)
              jwks-uri (get data :jwks_uri)]
          (when (and jwks-uri (string? jwks-uri) (not (str/blank? jwks-uri)))
            (l/inf :hint "jwt: discovered jwks_uri" :well-known well-known :jwks-uri jwks-uri)
            jwks-uri))))
    (catch Throwable cause
      (l/wrn :hint "jwt: well-known discovery failed" :issuer issuer :cause cause)
      nil)))

(defn- resolve-jwks-url
  "Return effective JWKS URL: env var if set, else discovered via .well-known, else issuer + /jwks/."
  [cfg]
  (or (jwt-verify-url-raw)
      (some-> (discover-jwks-uri cfg (jwt-issuer)) not-empty)
      (str (cstr/rtrim (jwt-issuer) "/") default-jwks-path)))

(defonce ^:private jwks-cache (atom {:keys {} :expires-at 0}))

;; Session handler cfg carries no HTTP client (::manager + ::db/pool only),
;; so client/resolve-client would throw "invalid arguments". Keep one shared
;; java-http client for JWKS fetches (same builder call as app.http.client).
(defonce ^:private shared-http-client
  (delay (jhttp/build-client {:connect-timeout 10000 :follow-redirects :never})))

(defn- req-client
  [cfg]
  (or (::http/client cfg) @shared-http-client))

(defn- fetch-jwks-keys
  [cfg jwks-uri]
  (let [{:keys [status body]} (http/req (req-client cfg) {:method :get :uri jwks-uri} {:skip-ssrf-check? true})]
    (if (= 200 status)
      (let [data (json/decode body)
            keys (:keys data)]
        (reduce (fn [acc {:keys [kid] :as kdata}]
                  (let [pkey (ex/try! (jwk/public-key kdata))]
                    (if (ex/exception? pkey)
                      (do (l/wrn :hint "jwt: unable to create public key" :kid kid :cause pkey) acc)
                      (assoc acc kid pkey))))
                {}
                keys))
      (do (l/wrn :hint "jwt: unable to fetch JWKS" :jwks-uri jwks-uri :status status) {}))))

(defn- get-jwks
  [cfg]
  (l/inf :hint "jwt: get-jwks entry")
  (let [now (inst-ms (ct/now))
        {:keys [keys expires-at]} @jwks-cache]
    (if (and (seq keys) (< now expires-at))
      keys
      (let [jwks-uri (resolve-jwks-url cfg)
            _ (l/dbg :hint "jwt: fetching JWKS" :jwks-uri jwks-uri)
            new-keys (try (fetch-jwks-keys cfg jwks-uri) (catch Throwable e (l/wrn :hint "jwt: fetch JWKS exception" :cause e) {}))
            expires (+ now (* 10 60 1000))]
        (when (seq new-keys) (reset! jwks-cache {:keys new-keys :expires-at expires}))
        new-keys))))

(defn verify-jwt
  "Verify Bearer JWT via JWKS. Returns payload map or nil. RS256-only, exact iss/aud, exp required, nbf enforced, 60s leeway."
  [cfg token]
  (when (and token (string? token) (not (str/blank? token)))
    (l/inf :hint "jwt: Bearer presented" :have-header (some? (try (jwt/decode-header token) (catch Throwable _ nil))))
    (try
      (l/inf :hint "jwt: inside try")
      (let [issuer (jwt-issuer)
            audience (jwt-audience)
            leeway 60
            header (try (jwt/decode-header token) (catch Throwable _ nil))
            alg (:alg header)
            ;; Decode libraries vary in case (observed "rs256" live).
            ;; Normalize before the exact allow-list check.
            alg-str (when alg (str/upper-case (name alg)))]
        (l/inf :hint "jwt: bindings" :alg-str alg-str :kid (:kid header) :issuer issuer :audience audience)
        ;; RS256-only: reject none, HS*, and all other algs before any verify.
        (when (not= alg-str "RS256")
          (l/inf :hint "jwt: unsupported alg (RS256-only)" :alg alg-str)
          (throw (ex-info "unsupported alg" {:alg alg-str})))
        (let [kid (:kid header)
              jwks (get-jwks cfg)
              pkey (or (get jwks kid)
                       (when (= 1 (count jwks)) (first (vals jwks)))
                       (do (l/inf :hint "jwt: kid not in JWKS, refetch" :kid kid)
                           (reset! jwks-cache {:keys {} :expires-at 0})
                           (get (get-jwks cfg) kid)))]
          (when-not pkey
            (l/inf :hint "jwt: no matching JWKS key" :kid kid :alg alg-str :jwks-keys (keys jwks))
            (throw (ex-info "no jwks key" {:kid kid})))
          (let [payload (jwt/unsign token pkey {:alg :RS256})
                iss (:iss payload)
                aud (:aud payload)
                exp (:exp payload)
                nbf (:nbf payload)
                now (ct/now)
                now-ms (inst-ms now)
                leeway-ms (* leeway 1000)
                ;; Exact aud: string equal only. Arrays reject (exact set match).
                aud-ok (and (string? aud) (= aud audience))]
            (when (not= iss issuer)
              (l/inf :hint "jwt: invalid iss" :expected issuer :got iss)
              (throw (ex-info "invalid iss" {})))
            (when-not aud-ok
              (l/inf :hint "jwt: invalid aud" :expected audience :got aud)
              (throw (ex-info "invalid aud" {})))
            ;; exp required.
            (when (nil? exp)
              (l/inf :hint "jwt: missing exp")
              (throw (ex-info "missing exp" {})))
            (let [exp-inst (if (number? exp) (ct/inst (* 1000 (long exp))) exp)
                  exp-ms (inst-ms exp-inst)]
              (when (< (+ exp-ms leeway-ms) now-ms)
                (l/inf :hint "jwt: token expired" :exp exp)
                (throw (ex-info "expired" {}))))
            (when nbf
              (let [nbf-inst (if (number? nbf) (ct/inst (* 1000 (long nbf))) nbf)
                    nbf-ms (inst-ms nbf-inst)]
                (when (> (- nbf-ms leeway-ms) now-ms)
                  (l/inf :hint "jwt: token not yet valid (nbf)" :nbf nbf)
                  (throw (ex-info "nbf" {})))))
            (l/inf :hint "jwt: verified" :iss iss :aud aud :sub (:sub payload) :email (or (:email payload) (:preferred_username payload)))
            payload)))
      (catch Throwable cause
        ;; NOTE: backend log config drops WARN (zero W lines observed live).
        ;; Log at INFO so failures stay visible. Server-side only.
        (l/inf :hint "jwt: verification failed" :cause (ex-message cause) :data (ex-data cause))
        nil))))
