(ns clauth.test.store
  (:use [clauth.store]
        [clojure.test]))
  


  (deftest memory-store-implementaiton
    (let [st (create-memory-store)]
      (is (= 0 (count (entries st))))
      (is (= [] (entries st)))
      (is (nil? (fetch st "item")))

      (let [item (store! st :key {:key  "item" :hello "world"})]
        (is (= 1 (count (entries st))))
        (is (= item (fetch st "item")))
        (is (= [item] (entries st)))
        (let [_ (revoke! st "item")]
          (is (nil? (fetch st "item"))))
        (do
          (reset-store! st)
          (is (= 0 (count (entries st))))
          (is (= [] (entries st)))
          (is (nil? (fetch st "item")))))))

 