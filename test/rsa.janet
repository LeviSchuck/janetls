(import testament :prefix "" :exit true)
# Testament framework documentation
# https://github.com/pyrmont/testament/blob/master/api.md
(import ../build/janetls :prefix "" :exit true)

# Generate a default key, RSASSA-PKCS1-v1_5 using SHA-256
(def key (rsa/generate))

(def data "hello mike")
(def other-data "goodbye joe")

(deftest "Default key is 2048 bits" (is (= 2048 (:bits key))))
(deftest "Default key is 256 bytes" (is (= 256 (:bytes key))))

(deftest "Default key is pkcs1-v1.5" (is (= :pkcs1-v1.5 (:version key))))
(deftest "Default key has uses sha-256" (is (= :sha256 (:digest key))))
(deftest "Default key is private" (is (= true (:private? key))))
(deftest "Default key is not public" (is (= false (:public? key))))
(deftest "Default key has no mgf" (is (= :none (:mgf key))))

(deftest "Default key can sign and verify" (do
  (def sig (:sign key data))
  (def sig2 (:sign key other-data))
  (is (:verify key data sig))
  (is (= false (:verify key data sig2)))
  ))

(def key2 (rsa/generate {
  :bits 1024
  :version :pkcs1-v2.1
  :mgf1 :sha1
  :digest :sha1
  }))

(deftest "Custom key is 1024 bits" (is (= 1024 (rsa/get-size-bits key2))))
(deftest "Custom key is 128 bytes" (is (= 128 (rsa/get-size-bytes key2))))

(deftest "Custom key is pkcs1-v2.1" (is (= :pkcs1-v2.1 (rsa/get-version key2))))
(deftest "Custom key has uses sha-1" (is (= :sha1 (rsa/get-digest key2))))
(deftest "Custom key is private" (is (= true (rsa/private? key2))))
(deftest "Custom key is not public" (is (= false (rsa/public? key2))))
(deftest "Custom key has sha1 mgf" (is (= :sha1 (rsa/get-mgf key2))))

(deftest "Custom key can sign and verify" (do
  (def sig (rsa/sign key2 data))
  (def sig2 (:sign key other-data))
  (is (rsa/verify key2 data sig))
  (is (= false (rsa/verify key data sig2)))
  ))

(run-tests!)
