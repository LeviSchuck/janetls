(import testament :prefix "" :exit true)
# Testament framework documentation
# https://github.com/pyrmont/testament/blob/master/api.md
(import ../build/janetls :prefix "" :exit true)

(def data "hello mike")

(def rsa-key (base64/decode
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

# Example created by..
# private.key file with:
# -----BEGIN RSA PRIVATE KEY-----
# (rsa-key contetns above)
# -----END RSA PRIVATE KEY-----
#
# To make the public file in PKCS#1 format
# openssl rsa -in private.key -out public.key -RSAPublicKey_out
#
# echo -n "hello mike" > test.txt
# openssl dgst -sha1 -sign private.key -out test.txt.sig test.txt
# openssl dgst -sha1 -verify <(openssl rsa -in private.key -pubout) -signature test.txt.sig test.txt
# > writing RSA key
# > Verified OK

(def openssl-sig (base64/decode
"VIjebW2SKxw5UxDkwkjsuTooqioPfKKVZH0nD4/oPAOQXu5SvUUrl55aN1Txywwwwlt+Ms2nxpdK
qcCcy57pPWmiw6QcGcGIsBApt+dsSshlxFl2TzrSPmESvXWMcbo385/l8UYBFXeZpn6+j5AFKQJQ
+xLAtIO76DsScT4tVFA="))

(deftest "Imported RSA private key can sign and verify" (do
  (def asn1-private-key (asn1/decode rsa-key))
  (def asn1-public-key (asn1/decode rsa-pub-key))

  (def {:value [_ {:value n} {:value e} {:value d} {:value p} {:value q}]} asn1-private-key)
  (def imported-private-key (rsa/import {:n n :e e :d d :p p :q q :digest :sha1}))
  (is (not= nil imported-private-key))

  (def {:value [{:value n2} {:value e2}]} asn1-public-key)
  (def imported-public-key (rsa/import {:n n2 :e e2 :digest :sha1}))
  (is (not= nil imported-public-key))

  (def exported-imported-private-public-key (:export-public imported-private-key))
  (def exported-imported-public-public-key (:export-public imported-public-key))
  (eachk component exported-imported-private-public-key
    (if (not= :random component) (is (=
      (get exported-imported-private-public-key component)
      (get exported-imported-public-public-key component)
      ))))

  (def sig (rsa/sign imported-private-key data))
  (def sig2 (rsa/sign imported-private-key data))
  (is (:verify imported-private-key data sig))
  (is (:verify imported-public-key data sig))
  (is (:verify imported-private-key data sig2))
  (is (:verify imported-public-key data sig2))
  # Compatible with openssl signed data (likely the same!)
  (is (:verify imported-private-key data openssl-sig))
  ))


(run-tests!)
