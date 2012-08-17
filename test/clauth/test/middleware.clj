(ns clauth.test.middleware
  (:require [clojure.test :refer :all]
            [clauth.middleware :as base]))

(deftest bearer-token-from-header
  ;; authorization success adds oauth-token on request map
  (is (= "secrettoken"
         (:access-token
          ((base/wrap-bearer-token (fn [req] req) #{"secrettoken"})
           {:headers {"authorization" "Bearer secrettoken"}})))
      "find matching token")

  (is (nil? (:access-token
             ((base/wrap-bearer-token (fn [req] req) #{"secrettoken"})
              {:headers {"authorization" "Bearer wrongtoken"}})))
      "should only return matching token")

  (is (nil? (:access-token
             ((base/wrap-bearer-token (fn [req] req) #{"secrettoken"})
              {:headers {}}))) "should not set if no token present"))

(deftest bearer-token-from-params
  ;; authorization success adds oauth-token on request map
  (is (= "secrettoken"
         (:access-token
          ((base/wrap-bearer-token (fn [req] req) #{"secrettoken"})
           {:params {:access_token "secrettoken"}})))
      "find matching token")

  (is (nil? (:access-token
             ((base/wrap-bearer-token (fn [req] req) #{"secrettoken"})
              { :params {:access_token "wrongtoken"}})))
      "should only return matching token")

  (is (nil? (:access-token
             ((base/wrap-bearer-token (fn [req] req) #{"secrettoken"})
              {}))) "should not set if no token present"))

(deftest bearer-token-from-cookies
  ;; authorization success adds oauth-token on request map
  (is (= "secrettoken"
         (:access-token
          ((base/wrap-bearer-token (fn [req] req) #{"secrettoken"})
           {:cookies {"access_token" { :value "secrettoken"}}})))
      "find matching token")

  (is (nil? (:access-token
             ((base/wrap-bearer-token (fn [req] req) #{"secrettoken"})
              {:cookies {"access_token" { :value "wrongtoken"}}})))
      "should only return matching token")

  (is (nil? (:access-token
             ((base/wrap-bearer-token (fn [req] req) #{"secrettoken"})
              {}))) "should not set if no token present"))

(deftest bearer-token-from-session
  ;; authorization success adds oauth-token on request map
  (is (= "secrettoken"
         (:access-token
          ((base/wrap-bearer-token (fn [req] req) #{"secrettoken"})
           {:session {:access_token "secrettoken"}})))
      "find matching token")

  (is (nil? (:access-token
             ((base/wrap-bearer-token (fn [req] req) #{"secrettoken"})
              {:session {:access_token "wrongtoken"}})))
      "should only return matching token")

  (is (nil? (:access-token
             ((base/wrap-bearer-token (fn [req] req) #{"secrettoken"})
              {}))) "should not set if no token present"))

(deftest require-token
  ;; authorization success adds oauth-token on request map
  (is (= 200 (:status
              ((base/require-bearer-token!
                (fn [req] {:status 200}) #{"secrettoken"})
               {:headers {"authorization" "Bearer secrettoken"}})))
      "find matching token")

  (let [response ((base/require-bearer-token!
                   (fn [req] {:status 200}) #{"secrettoken"})
                  {:headers {"accept" "text/html"}
                   :query-string "test=123"
                   :uri "/protected"})]
    (is (= 302 (:status response)) "redirect")
    (is (= "/login" ((:headers response) "Location")) "to login")
    (is (= "/protected?test=123" ((:session response) :return-to))
        "set return-to"))

  (is (= 401 (:status
              ((base/require-bearer-token!
                (fn [req] {:status 200}) #{"secrettoken"})
               {:headers {"authorization" "Bearer wrongtoken"}})))
      "should only return matching token")

  (is (= 401 (:status
              ((base/require-bearer-token!
                (fn [req] {:status 200}) #{"secrettoken"})
               {:headers {}}))) "should not set if no token present"))

(deftest require-user-session
  (is (= 200 (:status
              ((base/require-user-session!
                (fn [req] {:status 200}) #{"secrettoken"})
               {:session {:access_token "secrettoken"}}))) "allow from session")

  (let [response ((base/require-user-session!
                   (fn [req] {:status 200}) #{"secrettoken"})
                  {:headers {"accept" "text/html"}
                   :query-string "test=123"
                   :uri "/protected"})]
    (is (= 302 (:status response)) "redirect")
    (is (= "/login" ((:headers response) "Location")) "to login")
    (is (= "/protected?test=123" ((:session response) :return-to))
        "set return-to"))

  (is (= 403 (:status
              ((base/require-user-session!
                (fn [req] {:status 200}) #{"secrettoken"})
               {:headers {"authorization" "Bearer secrettoken"}})))
      "Disallow from auth header")
  (is (= 403 (:status
              ((base/require-user-session!
                (fn [req] {:status 200}) #{"secrettoken"})
               {:cookies {"access_token" {:value "secrettoken"}}})))
      "Disallow from cookies")
  (is (= 403 (:status
              ((base/require-user-session!
                (fn [req] {:status 200}) #{"secrettoken"})
               {:params {:access_token "secrettoken"}})))
      "Disallow from params"))

(deftest request-is-html
  (is (not (base/is-html? {})))
  (is (not (base/is-html? {:headers {"accept" "*/*"}})))
  (is (not (base/is-html? {:headers {"accept" "application/json"}})))
  (is (base/is-html? {:headers {"accept" "text/html"}}))
  (is (base/is-html? {:headers {"accept" "application/xhtml+xml"}}))
  (is (base/is-html?
       {:headers
        {"accept"
         "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}})))

(deftest request-is-form
  (is (not (base/is-form? {})))
  (is (not (base/is-form? {:content-type "application/json"
                           :access-token "abcde"
                           :session {:access_token "abcde"}})))
  (is (not (base/is-form? {:content-type "application/xml"
                           :access-token "abcde"
                           :session {:access_token "abcde"}})))
  (is (base/is-form? {:content-type "application/x-www-form-urlencoded"
                      :access-token "abcde"
                      :session {:access_token "abcde"}}))
  (is (base/is-form? {:content-type "multipart/form-data"
                      :access-token "abcde"
                      :session {:access_token "abcde"}}))
  (is (not (base/is-form? {:content-type "application/json"})))
  (is (not (base/is-form? {:content-type "application/xml"})))
  (is (base/is-form? {:content-type "application/x-www-form-urlencoded"}))
  (is (base/is-form? {:content-type "multipart/form-data"}))
  (is (not (base/is-form? {:content-type "application/json"
                           :access-token "abcde"})))
  (is (not (base/is-form? {:content-type "application/xml"
                           :access-token "abcde"})))
  (is (not (base/is-form? {:content-type "application/x-www-form-urlencoded"
                           :access-token "abcde"})))
  (is (not (base/is-form? {:content-type "multipart/form-data"
                           :access-token "abcde"}))))

(deftest request-if-html
  (is (not (base/if-html {} true false)))
  (is (not (base/if-html {:headers {"accept" "*/*"}} true false)))
  (is (not (base/if-html {:headers {"accept" "application/json"}} true false)))
  (is (base/if-html {:headers {"accept" "text/html"}} true false))
  (is (base/if-html {:headers {"accept" "application/xhtml+xml"}} true false))
  (is (base/if-html
       {:headers
        {"accept"
         "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}}
       true false)))

(deftest request-if-form
  (is (not (base/if-form {} true false)))
  (is (not (base/if-form {:content-type "application/json"} true false)))
  (is (not (base/if-form {:content-type "application/xml"} true false)))
  (is (base/if-form {:content-type "application/x-www-form-urlencoded"
                     :access-token "abcde"
                     :session {:access_token "abcde"}}
                    true false))
  (is (base/if-form {:content-type "multipart/form-data"
                     :access-token "abcde"
                     :session {:access_token "abcde"}}
                    true false)))

(deftest csrf-token-extraction
  (is (nil? (base/csrf-token {})))
  (is (= "token" (base/csrf-token {:session {:csrf-token "token"}})))
  (is (= "token" (base/csrf-token {:csrf-token "token"}))))

(deftest csrf-is-added-to-session
  ;; Should add a csrf-token entry to request if none is in session
  (is (not (nil? (:csrf-token (base/with-csrf-token {})))))
  ;; should not add to request if one is already in request
  (is (nil? (:csrf-token (base/with-csrf-token
                           {:session {:csrf-token "existing"}})))))

(deftest protects-against-csrf
  (let [handler (base/csrf-protect! (fn [req] req))]
    (is (not (nil?
              (:csrf-token
               (:session
                (handler {:request-method :get
                          :headers { "accept" "text/html"}
                          :access-token "abcde"
                          :session {:access_token "abcde"}}))))))

    (is (= "existing"
           (:csrf-token
            (:session
             (handler {:request-method :get
                       :session {:csrf-token "existing"}}))))))

  (let [handler (base/csrf-protect! (fn [req] {:status 200}))]
    (is (= 403 (:status
                (handler {:request-method :post
                          :content-type "application/x-www-form-urlencoded"
                          :access-token "abcde"
                          :session {:access_token "abcde"}})))
        "should fail for html post without token")

    (is (= 200 (:status
                (handler
                 {:request-method :post
                  :content-type "application/json"
                  :access-token "abcde"
                  :session {:access_token "abcde"}})))
        "should allow non html")

    (is (= 200 (:status
                (handler {:request-method :get
                          :headers {"accept" "text/html"}
                          :access-token "abcde"
                          :session {:access_token "abcde"}}))))

    (is (not (nil? (:csrf-token
                    (:session
                     (handler {:request-method :get
                               :headers {"accept" "text/html"}}))))))

    (let [response (handler {:request-method :get
                             :headers {"accept" "text/html"}
                             :session {:csrf-token "existing"}})]
      (is (nil? (:session response))))

    (is (= 200 (:status
                (handler {:request-method :post
                          :content-type "application/x-www-form-urlencoded"
                          :access-token "abcde"
                          :session {:csrf-token "secrettoken"
                                    :access_token "abcde"}
                          :params  {:csrf-token "secrettoken"}}))))
    (is (= 403 (:status
                (handler {:request-method :post
                          :content-type "application/x-www-form-urlencoded"
                          :access-token "abcde"
                          :session {:csrf-token "secrettoken"
                                    :access_token "abcde"}
                          :params  {:csrf-token "badtoken"}}))))
    (is (= 403 (:status
                (handler {:request-method :post
                          :content-type "application/x-www-form-urlencoded"
                          :access-token "abcde"
                          :session {base/csrf-token "secrettoken"
                                    :access_token "abcde"}}))))))
