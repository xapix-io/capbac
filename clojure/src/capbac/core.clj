(ns capbac.core
  (:require [clojure.string :as str]
            [cheshire.core :as json])
  (:refer-clojure :exclude [assert])
  (:import java.util.Base64
           javax.crypto.Mac
           javax.crypto.spec.SecretKeySpec))

(defn base64-encode [bytes]
  (.encodeToString (Base64/getUrlEncoder) bytes))

(defn base64-encode-str [^String s]
  (base64-encode (.getBytes s)))

(defn sign [^String s ^String secret]
  (let [hmac (Mac/getInstance "HmacSHA256")
        secret-spec (SecretKeySpec. (.getBytes secret) "HmacSHA256")]
    (.init hmac secret-spec)
    (base64-encode(.doFinal hmac (.getBytes s)))))

(defn base64-decode ^bytes [^String s]
  (.decode (Base64/getUrlDecoder) s))

(defn throw-error
  ([t cause]
   (throw (ex-info (str t) {:type t} cause)))
  ([t]
   (throw (ex-info (str t) {:type t}))))

(defn assert [cond type]
  (when-not cond
    (throw-error type))
  cond)

(defn split-token [s]
  (try
    (str/split s #"\.")
    (catch Exception e
      (throw-error ::invalid e))))

(defn try-parse-json [keywordize-keys? s]
  (try
    (-> s
        (base64-decode)
        (String.)
        (json/parse-string keywordize-keys?))
    (catch Exception e
      (throw-error ::invalid e))))

(defn make [{:keys [keywordize-keys?
                    root-secet
                    cap-secrets-provider] :as opts}]
  opts)

;; API

(defn wrap
  ([token sub-capability cap-key secret]
   (wrap token sub-capability cap-key secret {}))
  ([token sub-capability cap-key secret {:keys [expire-at]}]
   (let [header (if expire-at
                  {:expire-at expire-at}
                  {})
         intermediate (str token
                           "." (base64-encode-str (json/encode header))
                           "." (base64-encode-str (json/encode sub-capability))
                           "." cap-key)]
     (str intermediate "." (sign intermediate secret)))))

(defn forge [{:keys [root-secret]} capability]
  (let [encoded (base64-encode-str (json/encode capability))]
    (str encoded "." (sign encoded root-secret))))

(defn check-root [{:keys [root-secret keywordize-keys?]} token]
  (let [[capability sign-string :as all] (split-token token)]
    (assert (= 2 (count all)) ::invalid)
    (assert (= sign-string (sign capability root-secret)) ::bad-sign)
    (try-parse-json keywordize-keys? capability)))

(defn check* [{:keys [cap-secrets-provider
                      keywordize-keys?]}
              now
              {:keys [acc sub-capabilities]}
              [header capability cap-key sign-string]]
  (let [acc' (str acc "." header "." capability "." cap-key)
        secret (assert (cap-secrets-provider cap-key) ::bad-sign)]
    (prn "---SECRET" secret sign-string (sign acc' secret)
         acc')
    (assert (= sign-string (sign acc' secret)) ::bad-sign)
    (when-let [expire-at (:expire-at (try-parse-json true header))]
      (assert (< now expire-at) ::expired))
    (let [sub-capability (try-parse-json keywordize-keys? capability)]
      {:acc (str acc' "." sign-string)
       :sub-capabilities (conj sub-capabilities sub-capability)})))

(defn check [capbac now token]
  (let [[capability root-sign & parts] (split-token token)
        _ (assert (and capability root-sign) ::invalid)
        root-token (str capability "." root-sign)
        _ (assert (= 0 (rem (count parts) 4)) ::invalid)]
    [root-token
     (:sub-capabilities
      (reduce (partial check* capbac now) {:acc root-token
                                           :sub-capabilities []}
              (partition 4 parts)))]))

(defn check-all [capbac now token]
  (let [[root-token subc] (check capbac now token)]
    (cons (check-root capbac root-token)
          subc)))

(comment
  (forge "ololo" {:domain "foo"})


  (def my-cap-key-token
    {:root? true
     :capability [(.getBytes "my-token")]
     :sign (base64-decode "2jeRWZKc4FineoX2P1v7Fs16j1xpfBfo6bgPqQBApEE=")})

  (def token
    {:capability-restriction [(.getBytes "only-this-token")]
     :expire-at 123
     :cap-key-token my-cap-key-token
     :sign (base64-decode "2jeRWZKc4FineoX2P1v7Fs16j1xpfBfo6bgPqQBApEE=")
     :token
     {:root? true
      :capability [(.getBytes "cap-key-tokens")]
      :sign (base64-decode "2jeRWZKc4FineoX2P1v7Fs16j1xpfBfo6bgPqQBApEE=")}})
  (encode-token token))
