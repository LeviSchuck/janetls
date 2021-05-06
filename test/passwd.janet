(import testament :prefix "" :exit true)
(import ../janetls :prefix "" :exit true)

(def normal "$scrypt$$n=16384,r=8,p=1$MTIzNDU$daYyE5b+1DsHai3mnDrpa3fIU/PvWA46y9bp0y3e6/5o2KK9/a28gFQL/tsV+6zXyCj33CWZ9Sf4Eo4ehLpctA")
(def small "$scrypt$$n=1024,r=8,p=1$MTIzNDU$blfy0eEU4yQz1tEefeOHMrkYnuyf4jkUsFIM14+uoCw/9aFgoQl/ybIwfH/qrssGdN9FAiflJwavsTk8cz4VXQ")

(deftest "Regression Test"
  (is (= (passwd/scrypt "Hello password" {:salt "12345"}) normal))
  (is (= (passwd/scrypt "Hello password" {:salt "12345" :n 1024}) small))
  (is (passwd/verify-scrypt normal "Hello password"))
  (is (passwd/verify-scrypt small "Hello password"))
  (is (not (passwd/verify-scrypt normal "Hello Password")))
  (is (not (passwd/verify-scrypt small "Hello Password")))
  )

(deftest "Can verify self"
  (def pass (passwd/scrypt "Hello password"))
  (is (passwd/verify-scrypt normal "Hello password"))
  (is (not (passwd/verify-scrypt normal "Hello Password")))
  )

(run-tests!)
