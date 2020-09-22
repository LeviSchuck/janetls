(import testament :prefix "" :exit true)
(import ../janetls :exit true :prefix "")

(def ecdsa-key (ecdsa/generate))
(def rsa-key (rsa/generate))
(def pk-rsa (pk/import (rsa/export-private rsa-key)))
(def pk-ecdsa (pk/import (ecdsa/export-private ecdsa-key)))
(def public-rsa (pk/import (rsa/export-public rsa-key)))
(def public-ecdsa (pk/import (ecdsa/export-public ecdsa-key)))

(def data (util/random 16))

(deftest "RSA can sign and verify"
  (def sig (:sign pk-rsa data {:encoding :hex}))
  (is (:verify pk-rsa data sig {:encoding :hex}))
  (is (:verify public-rsa data sig {:encoding :hex}))
  # Check that decoding is actually working too.
  (is (:verify public-rsa data (encoding/decode sig :hex)))
  # And raw works
  (def sig (:sign pk-rsa data))
  (is (:verify public-rsa data sig))
  )
(deftest "ECDSA can sign and verify"
  (def sig (:sign pk-ecdsa data {:encoding :hex}))
  (is (:verify pk-ecdsa data sig {:encoding :hex}))
  (is (:verify public-ecdsa data sig {:encoding :hex}))
  )

(deftest "RSA can encrypt and decrypt"
  (def ciphertext (:encrypt pk-rsa data {:encoding :hex}))
  (is (= data (:decrypt pk-rsa ciphertext {:encoding :hex})))
  # Encrypting is a public key operation, so the public key cannot decrypt
  (assert-thrown (:decrypt public-rsa data {:encoding :hex}))
  # check that encrypting also works.
  (def ciphertext (:encrypt public-rsa data {:encoding :hex}))
  (is (= data (:decrypt pk-rsa ciphertext {:encoding :hex})))
  )

(deftest "ECDSA cannot encrypt and decrypt"
  (assert-thrown (:encrypt pk-ecdsa data {:encoding :hex}))
  (assert-thrown (:encrypt public-ecdsa data {:encoding :hex}))
  (assert-thrown (:decrypt pk-ecdsa data {:encoding :hex}))
  (assert-thrown (:decrypt public-ecdsa data {:encoding :hex}))
  )


(run-tests!)
