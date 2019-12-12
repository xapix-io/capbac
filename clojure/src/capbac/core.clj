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

;; API

(defn restrict
  ([token sub-capability cap-key secret]
   (restrict token sub-capability cap-key secret {}))
  ([token sub-capability cap-key secret {:keys [expire-at]}]
   (let [headers (->
                  {:cpk cap-key}
                  (cond-> expire-at
                    (assoc :exp expire-at)))
         parsed-token (split-token token)
         token-without-sign (str/join "." (butlast parsed-token))
         intermediate (str token-without-sign
                           "." (base64-encode-str (json/encode headers))
                           "." (base64-encode-str (json/encode sub-capability)))]
     (str intermediate "." (sign (str intermediate "." (last parsed-token)) secret)))))

(defn lock [token key]
  (let [parsed-token (split-token token)
        token-without-sign (str/join "." (butlast parsed-token))]
    (str token-without-sign "." (sign token key))))

(defn forge
  ([blacksmith capability]
   (forge blacksmith capability {}))
  ([{:keys [root-key cap-secrets-provider]} capability {:keys [expire-at]}]
   (let [secret (assert (cap-secrets-provider root-key) ::invalid-root-key)
         headers (->
                  {:cpk root-key}
                  (cond-> expire-at
                    (assoc :exp expire-at)))
         intermediate (str (base64-encode-str (json/encode headers))
                           "." (base64-encode-str (json/encode capability)))]
     (str intermediate "." (sign intermediate secret)))))

(defn check* [{:keys [cap-secrets-provider
                      keywordize-keys?
                      root-key]}
              now
              {:keys [lock-keys]}
              {:keys [acc capabilities root?
                      intermediate-sign]}
              parts]
  (case (count parts)
    1
    (let [intermediate-sign (if (seq lock-keys)
                              (reduce (fn [sign-string lock-key]
                                        (sign (str acc sign-string) lock-key))
                                      intermediate-sign lock-keys)
                              intermediate-sign)
          [sign-string] parts]
      (assert (= sign-string intermediate-sign) ::bad-sign)
      capabilities)

    2
    (let [[headers capability] parts
          acc' (str acc headers "." capability)
          {:keys [cpk exp]} (try-parse-json true headers)
          _ (when root?
              (assert (= cpk root-key) ::invalid))
          secret (assert (cap-secrets-provider cpk) ::bad-sign)]
      (when exp
        (assert (< now exp) ::expired))
      (let [capability' (try-parse-json keywordize-keys? capability)]
        {:root? false
         :acc (str acc' ".")
         :intermediate-sign (if intermediate-sign
                              (sign (str acc' "." intermediate-sign) secret)
                              (sign acc' secret))
         :capabilities (conj capabilities capability')}))))

(defn check
  ([capbac now token] (check capbac now token {}))
  ([capbac now token {:keys [lock-keys] :as options}]
   (let [parts (split-token token)
         _ (assert (and (<= 3 (count parts))
                        (= 1 (rem (count parts) 2))) ::invalid)]
     (reduce (partial check* capbac now options) {:acc ""
                                                  :root? true
                                                  :capabilities []}
             (partition 2 2 nil parts)))))

(defn reverse-diap [vec from to]
  (mapv #(nth vec (dec %)) (range to from -1)))

(defn reverse-diap [vec from to]
  (mapv #(nth vec %)
        (concat (range 0 from)
                (range to (dec from) -1)
                (range (inc to) (count vec)))))

(defn swap-diap*
  [v i j]
  (let [a (min i j)
        b (max i j)]
    (loop [c a
           r (transient v)]
      (if (> c b)
        (persistent! r)
        (recur (inc c) (assoc! r c (v (+ a (- b c)))))))))

(comment
  (range 4 (dec 2) -1)
  (def v (vec (shuffle (range 100))))
  #_(def v [1 2 3 4 5 6])
  (use 'criterium.core)

  (with-progress-reporting
    (quick-bench (reverse-diap v 20 40) :verbose))

  (with-progress-reporting
    (swap-diap* v 20 40))
  
  
  )

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
