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

(def rsa-priv-key (base64/decode
"MIICXAIBAAKBgQDkCGRwBG1j/WPjDO+nkQfKxhQDckktMjq9QBS7RUQ+Y5fFidp
rkztiC8Y/JWGEKC6Z5Au/9chZrx0DeSoleiKtdVFQUvjvrgrVsamztTbnH5fkFZo
X4lc/S0FgT3q9tys2k/nwY0jYvUO2EaBY2CnR/drdFS+iw+l0aIy9yxEQmQIDAQA
BAoGAfJpFX5xbte6I/VFdRyANtPSljPiPGd4/kJgKfAYuczTyguN/8ZZjNYEfk/O
2JIPcawTckskX8EGqxfIYYKArf7rzvlEQvXiFbN/znIOfgAL8JtB5bi5bO5PXUaq
piaAb5NQoZ+3O+T3etnxHORrpC7socZRtZIb9tQT2aLbHoDECQQDzgh3yBX0o998
Dl1aWi28kgZOhpSAqw6ZyWvwgC+qz69w9QXkT/E1Gxmfy9uex9z2DDR/nMTc1nt9
QkNtzrm4lAkEA77sK+DkUE8an+lZNFW8D5c/HsemVExOCF7VrZf1otTAP+Je9LAH
BXV6VvCQyGrkR6IbkAxLWRJvOIL6+fyhsZQJBANEIBzC06YX7kaOBjEDbHONXoCW
InB5ZqU5NMFVKJYWhmIO06nzvfl6c/qqgrLAmrtUKtTI/G0eaQ9TjJJ8fQ0kCQBr
BEx5UsGrslr6Xdw7XTuYM5Ep0uRBh8vjWZGADgfYGoSGrPY91urDC548Rsw3MbbU
3qKa3KXaKtNxurS/fwQkCQHeoIAy2aRltkFsaOfeghvX4kTQFAh7uLm+JV4xGrUU
sjtJfseYG44ETk8+m3AjwNq5jmkhif8YGeFBC8w0KdeQ="))

(def rsa-pub-key (base64/decode
"MIGJAoGBAOQIZHAEbWP9Y+MM76eRB8rGFANySS0yOr1AFLtFRD5jl8WJ2muTO2IL
xj8lYYQoLpnkC7/1yFmvHQN5KiV6Iq11UVBS+O+uCtWxqbO1Nucfl+QVmhfiVz9L
QWBPer23KzaT+fBjSNi9Q7YRoFjYKdH92t0VL6LD6XRojL3LERCZAgMBAAE="))


(deftest "rsa public export is identical"
  (def asn1-public-key (asn1/decode rsa-pub-key))
  (def {:value [{:value n} {:value e}]} asn1-public-key)
  (def pub (pk/import {:n n :e e :type :rsa}))
  (def exported (pk/export-public pub {:export-standard :pkcs1 :export-format :encoded :export-encoding :der}))
  (def {:der der} exported)
  (is (= der rsa-pub-key))
  )

(deftest "rsa private export is identical"
  (def asn1-private-key (asn1/decode rsa-priv-key))
  (def {:value [_ {:value n} {:value e} {:value d} {:value p} {:value q}]} asn1-private-key)
  (def priv (pk/import {:n n :e e :d d :p p :q q :type :rsa}))
  (def exported (pk/export-private priv {:export-standard :pkcs1 :export-format :encoded :export-encoding :der}))
  (def {:der der} exported)
  (is (= der rsa-priv-key))
  )

(run-tests!)
