(import testament :prefix "" :exit true)
# Testament framework documentation
# https://github.com/pyrmont/testament/blob/master/api.md
(import ../build/janetls :prefix "" :exit true)

(def r (random/start))

# Generate a default key, RSASSA-PKCS1-v1_5 using SHA-256
(def key (rsa/generate))

(def data "hello mike")
(def other-data "goodbye joe")
(def some-random-data (:get r 32))

(def encrypted-data (:encrypt key data))
(def encrypted-other-data (:encrypt key other-data))
(def encrypted-random-data (:encrypt key some-random-data))

(deftest "Default key is 2048 bits" (is (= 2048 (:bits key))))
(deftest "Default key is 256 bytes" (is (= 256 (:bytes key))))

(deftest "Default key is pkcs1-v1.5" (is (= :pkcs1-v1.5 (:version key))))
(deftest "Default key has uses sha-256" (is (= :sha256 (:digest key))))
(deftest "Default key is private" (is (= true (:private? key))))
(deftest "Default key is not public" (is (= false (:public? key))))
(deftest "Default key has no mask" (is (= :none (:mask key))))

(deftest "Default key can sign and verify" (do
  (def sig (:sign key data))
  (def sig2 (:sign key other-data))
  (is (:verify key data sig))
  (is (= false (:verify key data sig2)))
  ))

(deftest "Default key encrypted data is expected length" (= (:bytes key) (length encrypted-data)))
(deftest "Default key encrypted data decrypts" (= data (:decrypt key encrypted-data)))
(deftest "Default key encrypted other data decrypts" (= other-data (:decrypt key encrypted-other-data)))
(deftest "Default key encrypted some random data decrypts" (= some-random-data (:decrypt key encrypted-random-data)))

(def key2 (rsa/generate {
  :bits 1024
  :version :pkcs1-v2.1
  :mgf1 :sha1
  :digest :sha1
  :random r
  }))

(deftest "Custom key is 1024 bits" (is (= 1024 (rsa/get-size-bits key2))))
(deftest "Custom key is 128 bytes" (is (= 128 (rsa/get-size-bytes key2))))

(deftest "Custom key is pkcs1-v2.1" (is (= :pkcs1-v2.1 (rsa/get-version key2))))
(deftest "Custom key has uses sha-1" (is (= :sha1 (rsa/get-digest key2))))
(deftest "Custom key is private" (is (= true (rsa/private? key2))))
(deftest "Custom key is not public" (is (= false (rsa/public? key2))))
(deftest "Custom key has sha1 mask" (is (= :sha1 (rsa/get-mask key2))))

(deftest "Custom key can sign and verify" (do
  (def sig (rsa/sign key2 data))
  (def sig2 (:sign key other-data))
  (is (rsa/verify key2 data sig))
  (is (= false (rsa/verify key data sig2)))
  ))

(def encrypted-data2 (:encrypt key2 data))
(def encrypted-other-data2 (:encrypt key2 other-data))
(def encrypted-random-data2 (:encrypt key2 some-random-data))

(deftest "Custom key encrypted data is expected length" (= (:bytes key2) (length encrypted-data2)))
(deftest "Custom key encrypted data decrypts" (= data (:decrypt key2 encrypted-data2)))
(deftest "Custom key encrypted other data decrypts" (= other-data (:decrypt key2 encrypted-other-data2)))
(deftest "Custom key encrypted some random data decrypts" (= some-random-data (:decrypt key2 encrypted-random-data2)))

(def key3 (rsa/generate))
(deftest "Encryption between different keys differs" (is (not= (:encrypt key3 data) encrypted-data)))
(deftest "Decryption between different keys fails" (is (= nil (:decrypt key3 encrypted-data))))

(deftest "Refuses incorrect lengths" (assert-thrown (:decrypt key2 encrypted-data)))

(deftest "RSA Import and Export works" (do
  (def pub (rsa/export-public key))
  (def priv (rsa/export-private key))
  (is (not= nil pub))
  (is (not= nil priv))
  (is (not= nil (get pub :n)))
  (is (not= nil (get pub :e)))
  (is (not= nil (get pub :version)))
  (is (= :public (get pub :information-class)))
  (is (= :rsa (get pub :type)))
  # Private parameters are not included
  (is (= nil (get pub :d)))
  (is (= nil (get pub :p)))
  (is (= nil (get pub :q)))

  (is (not= nil (get priv :n)))
  (is (not= nil (get priv :e)))
  (is (not= nil (get priv :version)))
  (is (= :private (get priv :information-class)))
  (is (= :rsa (get priv :type)))
  # Private parameters are included
  (is (not= nil (get priv :d)))
  (is (not= nil (get priv :p)))
  (is (not= nil (get priv :q)))

  (def pub-key (rsa/import pub))
  (is (not= nil pub-key))
  (is (:public? pub-key))
  (is (not (:private? pub-key)))

  (def private-key (rsa/import priv))
  (is (not= nil private-key))
  (is (:private? private-key))
  (is (not (:public? private-key)))


  (def sig (rsa/sign key data))

  # Signature made with original key is accepted by all
  (is (:verify key data sig))
  (is (:verify pub-key data sig))
  (is (:verify private-key data sig))

  (def sig2 (:sign private-key data))
  # Signature made by the imported private key is accepted by all
  (is (:verify key data sig2))
  (is (:verify pub-key data sig2))
  (is (:verify private-key data sig2))

  # Public keys cannot sign
  (assert-thrown (:sign pub-key data))
  ))

(run-tests!)
