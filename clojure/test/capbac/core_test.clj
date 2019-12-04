(ns capbac.core-test
  (:require [capbac.core :as capbac]
            [clojure.test :refer [deftest is]]))

(deftest basic-flow
  (let [cap-secrets {"api1" "secret1"}
        capbac {:root-secret "very-secret"
                :cap-secrets-provider cap-secrets
                :keywordize-keys? true}
        capability {:domain "myorg.com"}
        root-token (capbac/forge capbac capability)]
    (is (= "eyJkb21haW4iOiJteW9yZy5jb20ifQ==.3aL7pmmyRWW-aoPoZNTdmgR-F_Z1f3rHPG5gJ2464K8=" root-token))
    (is (= capability
           (capbac/check-root capbac root-token)))

    (is (thrown-with-msg? Exception #":capbac.core/bad-sign"
                          (capbac/check-root capbac (subs root-token 0 (dec (.length root-token))))))

    (let [token1 (capbac/wrap root-token {:path "/foo"} "api1" "secret1")]
      (is (= [root-token [{:path "/foo"}]]
             (capbac/check capbac 0 token1)))

      (let [capbac' (update capbac :cap-secrets-provider dissoc "api1")]
        (is (thrown-with-msg? Exception #":capbac.core/bad-sign"
                              (capbac/check capbac' 0 token1))))

      (let [token2 (capbac/wrap token1 {:path "/foo/bar"} "api1" "secret1"
                                {:expire-at 100})]
        (is (= [root-token [{:path "/foo"}
                            {:path "/foo/bar"}]]
               (capbac/check capbac 0 token2)))

        (is (thrown-with-msg? Exception #":capbac.core/expired"
                              (capbac/check capbac 120 token2)))

        (is (= [{:domain "myorg.com"}
                {:path "/foo"}
                {:path "/foo/bar"}]
               (capbac/check-all capbac 0 token2)))))))
