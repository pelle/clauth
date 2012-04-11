(ns clauth.test.middleware
  (:use [clauth.middleware])
  (:use [clojure.test]))

   (deftest bearer-token-from-header
     
     ;; authorization success adds oauth-token on request map
     (is (= "secrettoken" (:access-token
                     ((wrap-bearer-token (fn [req] req)
                                                 #{"secrettoken"})
                        {:headers {"authorization" "Bearer secrettoken"}}))) "find matching token")

     (is (nil? (:access-token
                     ((wrap-bearer-token (fn [req] req)
                                                 #{"secrettoken"})
                        {:headers {"authorization" "Bearer wrongtoken"}}))) "should only return matching token")

      (is (nil? (:access-token
                     ((wrap-bearer-token (fn [req] req)
                                                 #{"secrettoken"})
                        {:headers {}}))) "should not set if no token present"))



   (deftest bearer-token-from-params
     
     ;; authorization success adds oauth-token on request map
     (is (= "secrettoken" (:access-token
                     ((wrap-bearer-token (fn [req] req)
                                                 #{"secrettoken"})
                        {:params {"access_token" "secrettoken"}}))) "find matching token")

     (is (nil? (:access-token
                     ((wrap-bearer-token (fn [req] req)
                                                 #{"secrettoken"})
                        { :params {"access_token" "wrongtoken"}}))) "should only return matching token")

      (is (nil? (:access-token
                     ((wrap-bearer-token (fn [req] req)
                                                 #{"secrettoken"})
                        {}))) "should not set if no token present"))

   (deftest bearer-token-from-cookies
     
     ;; authorization success adds oauth-token on request map
     (is (= "secrettoken" (:access-token
                     ((wrap-bearer-token (fn [req] req)
                                                 #{"secrettoken"})
                        {:cookies {"access_token" { :value "secrettoken"}}}))) "find matching token")

     (is (nil? (:access-token
                     ((wrap-bearer-token (fn [req] req)
                                                 #{"secrettoken"})
                        {:cookies {"access_token" { :value "wrongtoken"}}}))) "should only return matching token")

      (is (nil? (:access-token
                     ((wrap-bearer-token (fn [req] req)
                                                 #{"secrettoken"})
                        {}))) "should not set if no token present"))

   (deftest bearer-token-from-session
     
     ;; authorization success adds oauth-token on request map
     (is (= "secrettoken" (:access-token
                     ((wrap-bearer-token (fn [req] req)
                                                 #{"secrettoken"})
                        { :session { :access_token "secrettoken" }}))) "find matching token")

     (is (nil? (:access-token
                     ((wrap-bearer-token (fn [req] req)
                                                 #{"secrettoken"})
                        { :session { :access_token "wrongtoken" }}))) "should only return matching token")

      (is (nil? (:access-token
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


    (deftest request-is-html
        (is (not (is-html? {})))
        (is (not (is-html? {:headers {"accept" "*/*"}})))
        (is (not (is-html? {:headers {"accept" "application/json"}})))
        (is (is-html? {:headers {"accept" "text/html"}}))
        (is (is-html? {:headers {"accept" "application/xhtml+xml"}}))
        (is (is-html? {:headers {"accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}})))


    (deftest request-if-html
        (is (not (if-html {} true false)))
        (is (not (if-html {:headers {"accept" "*/*"}} true false)))
        (is (not (if-html {:headers {"accept" "application/json"}} true false)))
        (is (if-html {:headers {"accept" "text/html"}} true false))
        (is (if-html {:headers {"accept" "application/xhtml+xml"}} true false))
        (is (if-html {:headers {"accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}} true false)))

    (deftest csrf-token-extraction
        (is (nil? (csrf-token {})))
        (is (= "token" (csrf-token { :session { :csrf-token "token" }}))))

    (deftest csrf-is-added-to-session
        (let [handler (csrf-protect! (fn [req] req ))]
            (is (not (nil? (:csrf-token (:session (with-csrf-token {}))))))
            (is (= "existing" (:csrf-token (:session (with-csrf-token { :session {:csrf-token "existing"}})))))))

    (deftest protects-against-csrf
        (let [handler (csrf-protect! (fn [req] req ))]
            (is (not (nil? (:csrf-token (:session (handler { :request-method :get }))))))
            (is (= "existing" (:csrf-token (:session (handler { :request-method :get :session {:csrf-token "existing"}}))))))

        (let [handler (csrf-protect! (fn [req] {:status 200 } ))]
            (is (= 403 (:status
                        (handler { :request-method :post }))))
            (is (= 200 (:status
                        (handler { :request-method :get }))))
            (is (= 200 (:status
                        (handler {  :request-method :post 
                                    :session {:csrf-token "secrettoken"} 
                                    :params {"csrf-token" "secrettoken"} }))))
            (is (= 403 (:status
                        (handler {  :request-method :post 
                                    :session {:csrf-token "secrettoken"} 
                                    :params {"csrf-token" "badtoken"} }))))
            (is (= 403 (:status
                        (handler {  :request-method :post 
                                    :session {csrf-token "secrettoken"}}))))
            ))
