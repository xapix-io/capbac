(ns capbac.core
  (:require [clojure.string :as str]
            [cheshire.core :as json])
  (:refer-clojure :exclude [assert])
  (:import java.util.Base64
           javax.crypto.Mac
           javax.crypto.spec.SecretKeySpec))

(defn base64-encode [bytes]
  (.encodeToString (.withoutPadding (Base64/getUrlEncoder)) bytes))

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

(defn blacksmith [{:keys [keywordize-keys?
                          root-key
                          cap-secrets-provider] :as opts}]
  opts)

(defn wrap* [acc capability cap-key secret {:keys [expire-at]}]
  (let [headers (->
                 {:cpk cap-key}
                 (cond-> expire-at
                   (assoc :exp expire-at)))
        intermediate (str acc (base64-encode-str (json/encode headers))
                          "." (base64-encode-str (json/encode capability)))]
    (str intermediate "." (sign intermediate secret))))

;; API

(defn wrap
  ([token sub-capability cap-key secret]
   (wrap token sub-capability cap-key secret {}))
  ([token sub-capability cap-key secret options]
   (wrap* (str token ".") sub-capability cap-key secret options)))

(defn forge
  ([blacksmith capability]
   (forge blacksmith capability {}))
  ([{:keys [root-key cap-secrets-provider]} capability options]
   (let [secret (assert (cap-secrets-provider root-key) ::invalid-root-key)]
     (wrap* "" capability root-key secret options))))

(defn check* [{:keys [cap-secrets-provider
                      keywordize-keys?
                      root-key]}
              now
              {:keys [acc capabilities root?]}
              [headers capability sign-string]]
  (let [acc' (str acc headers "." capability)
        {:keys [cpk exp]} (try-parse-json true headers)
        _ (when root?
            (assert (= cpk root-key) ::invalid))
        secret (assert (cap-secrets-provider cpk) ::bad-sign)]
    (assert (= sign-string (sign acc' secret)) ::bad-sign)
    (when exp
      (assert (< now exp) ::expired))
    (let [capability' (try-parse-json keywordize-keys? capability)]
      {:root? false
       :acc (str acc' "." sign-string ".")
       :capabilities (conj capabilities capability')})))

(defn check [capbac now token]
  (let [parts (split-token token)
        _ (assert (= 0 (rem (count parts) 3)) ::invalid)]
    (:capabilities
     (reduce (partial check* capbac now) {:acc ""
                                          :root? true
                                          :capabilities []}
             (partition 3 parts)))))

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
