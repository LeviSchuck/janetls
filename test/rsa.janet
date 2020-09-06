(import testament :prefix "" :exit true)
# Testament framework documentation
# https://github.com/pyrmont/testament/blob/master/api.md
(import ../build/janetls :prefix "" :exit true)

# Generate a default key, RSASSA-PKCS1-v1_5 using SHA-256
(def key (rsa/generate))

(deftest "Default key is 2048 bits" (is (= 2048 (:bits key))))
(deftest "Default key is 256 bytes" (is (= 256 (:bytes key))))

(deftest "Default key is pkcs1-v1.5" (is (= :pkcs1-v1.5 (:version key))))
(deftest "Default key has uses sha-256" (is (= :sha256 (:digest key))))
(deftest "Default key is private" (is (= true (:private? key))))
(deftest "Default key is not public" (is (= false (:public? key))))
(deftest "Default key has no mgf" (is (= :none (:mgf key))))

(run-tests!)
