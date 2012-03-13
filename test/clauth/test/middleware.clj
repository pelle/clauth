(ns clauth.test.middleware
  (:use [clauth.middleware])
  (:use [clojure.test]))

   (deftest bearer-token-from-header
     
     ;; authorization success adds oauth-token on request map
     (is (= "secrettoken" (:oauth-token
                     ((wrap-bearer-token (fn [req] req)
                                                 #{"secrettoken"})
                        {:headers {"authorization" "Bearer secrettoken"}}))) "find matching token")

     (is (nil? (:oauth-token
                     ((wrap-bearer-token (fn [req] req)
                                                 #{"secrettoken"})
                        {:headers {"authorization" "Bearer wrongtoken"}}))) "should only return matching token")

      (is (nil? (:oauth-token
                     ((wrap-bearer-token (fn [req] req)
                                                 #{"secrettoken"})
                        {:headers {}}))) "should not set if no token present"))

   (deftest bearer-token-from-params
     
     ;; authorization success adds oauth-token on request map
     (is (= "secrettoken" (:oauth-token
                     ((wrap-bearer-token (fn [req] req)
                                                 #{"secrettoken"})
                        {:params {"access_token" "secrettoken"}}))) "find matching token")

     (is (nil? (:oauth-token
                     ((wrap-bearer-token (fn [req] req)
                                                 #{"secrettoken"})
                        { :params {"access_token" "wrongtoken"}}))) "should only return matching token")

      (is (nil? (:oauth-token
                     ((wrap-bearer-token (fn [req] req)
                                                 #{"secrettoken"})
                        {}))) "should not set if no token present"))

   (deftest bearer-token-from-cookies
     
     ;; authorization success adds oauth-token on request map
     (is (= "secrettoken" (:oauth-token
                     ((wrap-bearer-token (fn [req] req)
                                                 #{"secrettoken"})
                        {:cookies {"access_token" { :value "secrettoken"}}}))) "find matching token")

     (is (nil? (:oauth-token
                     ((wrap-bearer-token (fn [req] req)
                                                 #{"secrettoken"})
                        {:cookies {"access_token" { :value "wrongtoken"}}}))) "should only return matching token")

      (is (nil? (:oauth-token
                     ((wrap-bearer-token (fn [req] req)
                                                 #{"secrettoken"})
                        {}))) "should not set if no token present"))


   (deftest require-token
     
     ;; authorization success adds oauth-token on request map
     (is (= 200 (:status
                     ((require-bearer-token! (fn [req] {:status 200} )
                                                 #{"secrettoken"})
                        {:headers {"authorization" "Bearer secrettoken"}}))) "find matching token")

     (is (= 401 (:status
                     ((require-bearer-token! (fn [req] {:status 200})
                                                 #{"secrettoken"})
                        {:headers {"authorization" "Bearer wrongtoken"}}))) "should only return matching token")

      (is (= 401 (:status
                     ((require-bearer-token! (fn [req] {:status 200})
                                                 #{"secrettoken"})
                        {:headers {}}))) "should not set if no token present"))
