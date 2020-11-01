# https://github.com/ircmaxell/quality-checker/blob/master/tmp/gh_18/PHP-PasswordLib-master/test/Data/Vectors/aes-ecb.test-vectors
(import testament :prefix "" :exit true)
(import ../janetls :exit true :prefix "")

(setdyn :pretty-format "%.99N")

(def key (hex/decode "00000000000000000000000000000000"))
(def key2 (hex/decode "0000000000000000000000000000000000000000000000000000000000000000"))
(def ad "user:123;post:9999")
(def data (util/random 18))

(deftest "encrypt decrypt" (do
  (def [iv ciphertext tag] (cipher/encrypt :aes-gcm key nil ad data))
  (def plaintext (cipher/decrypt :aes-gcm key iv ad ciphertext tag))
  (is (= data (freeze plaintext)))
  (def [iv ciphertext tag] (cipher/encrypt :chacha20-poly1305 key2 nil ad data))
  (def plaintext (cipher/decrypt :chacha20-poly1305 key2 iv ad ciphertext tag))
  (is (= data (freeze plaintext)))
  (def [iv ciphertext] (cipher/encrypt :aes-ctr key nil nil data))
  (def plaintext (cipher/decrypt :aes-ctr key iv nil ciphertext))
  (is (= data (freeze plaintext)))
  (def [iv ciphertext] (cipher/encrypt :aes-cbc key nil nil data))
  (def plaintext (cipher/decrypt :aes-cbc key iv nil ciphertext))
  (is (= data (freeze plaintext)))
  (def [iv ciphertext] (cipher/encrypt :aes-cbc key nil nil data))
  (def plaintext (cipher/decrypt :aes-cbc key iv nil ciphertext))
  (is (= data (freeze plaintext)))
  (def [iv ciphertext] (cipher/encrypt :chacha20 key2 nil nil data))
  (def plaintext (cipher/decrypt :chacha20 key2 iv nil ciphertext))
  (is (= data (freeze plaintext)))
  ))

(deftest "new encrypt decrypt" (do
  (def [cipher key iv ciphertext tag] (cipher/new-encrypt :aes-gcm ad data))
  (def plaintext (cipher/decrypt :aes-gcm key iv ad ciphertext tag))
  (is (= data (freeze plaintext)))
  (def [cipher key iv ciphertext tag] (cipher/new-encrypt :chacha20-poly1305 ad data))
  (def plaintext (cipher/decrypt :chacha20-poly1305 key iv ad ciphertext tag))
  (is (= data (freeze plaintext)))
  (def [cipher key iv ciphertext] (cipher/new-encrypt :aes-ctr nil data))
  (def plaintext (cipher/decrypt :aes-ctr key iv nil ciphertext))
  (is (= data (freeze plaintext)))
  (def [cipher key iv ciphertext] (cipher/new-encrypt :aes-cbc nil data))
  (def plaintext (cipher/decrypt :aes-cbc key iv nil ciphertext))
  (is (= data (freeze plaintext)))
  (def [cipher key iv ciphertext] (cipher/new-encrypt :aes-cbc nil data))
  (def plaintext (cipher/decrypt :aes-cbc key iv nil ciphertext))
  (is (= data (freeze plaintext)))
  (def [cipher key iv ciphertext] (cipher/new-encrypt :chacha20 nil data))
  (def plaintext (cipher/decrypt :chacha20 key iv nil ciphertext))
  (is (= data (freeze plaintext)))
  ))

(deftest "cipher object use" (do
  (def iv (hex/decode "000000000000000000000000"))
  (def ad "data")
  (def cipher (cipher/start :aes-gcm :encrypt key iv ad))
  (def ciphertext (buffer))
  (:update cipher "hello world" ciphertext)
  (:finish cipher ciphertext)
  (is (= "6bedb6a20f96d4fd8144a6" (hex/encode ciphertext)))
  (def tag (:tag cipher))
  (is (= "b49cec3c9db76513b9abde61d0c01b0e" (hex/encode tag)))

  (def decipher (cipher/start :aes-gcm :decrypt key iv ad))
  (def plaintext (buffer))
  (:update decipher ciphertext plaintext)
  (:finish decipher plaintext)
  (is (= "hello world" (freeze plaintext)))
  (is (:tag decipher tag))
  ))

(run-tests!)
