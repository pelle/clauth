(ns clauth.test.middleware
  (:use [clauth.middleware])
  (:use [clojure.test]))

   (deftest bearer-token-from-header
     
     ;; authorization success adds oauth-token on request map
     (is (= "secrettoken" (:oauth-token
                     ((wrap-bearer-token (fn [req] req)
                                                 #{"secrettoken"})
                        {:headers {"authorization"
                           (str "Bearer secrettoken")}}))) "find matching token")

     (is (nil? (:oauth-token
                     ((wrap-bearer-token (fn [req] req)
                                                 #{"secrettoken"})
                        {:headers {"authorization"
                           (str "Bearer wrongtoken")}}))) "should only return matching token")

      (is (nil? (:oauth-token
                     ((wrap-bearer-token (fn [req] req)
                                                 #{"secrettoken"})
                        {:headers {}}))) "should not set if no token present"))

   (deftest bearer-token-from-params
     
     ;; authorization success adds oauth-token on request map
     (is (= "secrettoken" (:oauth-token
                     ((wrap-bearer-token (fn [req] req)
                                                 #{"secrettoken"})
                        {:headers {} :params {:access_token "secrettoken"}}))) "find matching token")

     (is (nil? (:oauth-token
                     ((wrap-bearer-token (fn [req] req)
                                                 #{"secrettoken"})
                        {:headers {} :params {:access_token "wrongtoken"}}))) "should only return matching token")

      (is (nil? (:oauth-token
                     ((wrap-bearer-token (fn [req] req)
                                                 #{"secrettoken"})
                        {:headers {}}))) "should not set if no token present"))
