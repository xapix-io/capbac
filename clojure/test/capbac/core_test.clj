(ns capbac.core-test
  (:require [capbac.core :as capbac]
            [clojure.test :refer [deftest is testing]]))

(deftest basic-flow
  (let [cap-secrets {"root" "very-secret"
                     "api1" "secret1"}
        blacksmith (capbac/blacksmith
                    {:root-key "root"
                     :cap-secrets-provider cap-secrets
                     :keywordize-keys? true})
        capability {:domain "myorg.com"}
        root-token (capbac/forge blacksmith capability)]
    (is (= "eyJjcGsiOiJyb290In0.eyJkb21haW4iOiJteW9yZy5jb20ifQ.SEcC9GaGfAqRQUyePnLNpYp71-Jbft9-94oZGmVjr0M" root-token))
    (is (= [{:domain "myorg.com"}]
           (capbac/check blacksmith 0 root-token)))

    (is (thrown-with-msg? Exception #":capbac.core/bad-sign"
                          (capbac/check blacksmith 0 (subs root-token 0 (dec (count root-token))))))

    (testing "different root key"
      (let [root-token (capbac/forge (assoc blacksmith :root-key "api1") capability)]
        (is (thrown-with-msg? Exception #":capbac.core/invalid"
                              (capbac/check blacksmith 0 (subs root-token 0 (dec (count root-token))))))))

    (let [token1 (capbac/wrap root-token {:path "/foo"} "api1" "secret1")]
      (is (= [{:domain "myorg.com"}
              {:path "/foo"}]
             (capbac/check blacksmith 0 token1)))

      (let [blacksmith' (update blacksmith :cap-secrets-provider dissoc "api1")]
        (is (thrown-with-msg? Exception #":capbac.core/bad-sign"
                              (capbac/check blacksmith' 0 token1))))

      (let [token2 (capbac/wrap token1 {:path "/foo/bar"} "api1" "secret1"
                                {:expire-at 100})]
        (is (= [{:domain "myorg.com"}
                {:path "/foo"}
                {:path "/foo/bar"}]
               (capbac/check blacksmith 0 token2)))

        (is (thrown-with-msg? Exception #":capbac.core/expired"
                              (capbac/check blacksmith 120 token2)))))))
