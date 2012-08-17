(ns clauth.test.store
  (:require [clojure.test :refer :all]
            [clauth.store :as base]))

(deftest memory-store-implementaiton
  (let [st (base/create-memory-store)]
    (is (= 0 (count (base/entries st))))
    (is (= [] (base/entries st)))
    (is (nil? (base/fetch st "item")))
    (let [item (base/store! st :key {:key  "item" :hello "world"})]
      (is (= 1 (count (base/entries st))))
      (is (= item (base/fetch st "item")))
      (is (= [item] (base/entries st)))
      (let [_ (base/revoke! st "item")]
        (is (nil? (base/fetch st "item"))))
      (do (base/reset-store! st)
          (is (= 0 (count (base/entries st))))
          (is (= [] (base/entries st)))
          (is (nil? (base/fetch st "item")))))))
