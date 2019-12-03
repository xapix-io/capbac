(ns capbac.core
  (:require [clojure.string :as str])
  (:import java.util.Base64
           javax.crypto.Mac
           javax.crypto.spec.SecretKeySpec))

(defn sign [s secret]
  (let [hmac (Mac/getInstance "HmacSHA256")
        secret-spec (SecretKeySpec. (.getBytes secret) "HmacSHA256")]
    (.init hmac secret-spec)
    (.doFinal hmac (.getBytes s))))

(defn base64-encode [bytes]
  (.encodeToString (Base64/getEncoder) bytes))

(defn base64-decode [s]
  (.decode (Base64/getDecoder) s))

(declare encode-token)

(defn encode-capability [ba]
  (base64-encode ba))

(defn encode-expire-at [expire-at]
  (when expire-at
    (str expire-at ".e")))

(defn encode-capability-restriction [parts]
  (when (seq parts)
    (str/join (concat (map encode-capability parts) [(count parts) ".r"]))))

(defn encode-root [{:keys [capability sign expire-at]}]
  (->>
   (concat (map encode-capability capability)
           [(count capability)
            "c"
            (base64-encode sign)
            "r"])
   (str/join ".")))

(defn encode-wrap [{:keys [token capability-restriction cap-key-token sign expire-at]}]
  (->>
   (concat (encode-token token)
           (encode-token cap-key-token)
           (base64-encode sign)
           "w"
           (encode-capability-restriction capability-restriction)
           (encode-expire-at expire-at))
   (str/join ".")))

(defn encode-token [token]
  (if (:root? token)
    (encode-root token)
    (encode-wrap token)))

(comment

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

