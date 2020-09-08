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

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# S E T U P
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# To make the private key in PKCS#1 format
# private.key file with (the same contents as rsa-key above)
# -----BEGIN RSA PRIVATE KEY-----
# MIICXAIBAAKBgQDkCGRwBG1j/WPjDO+nkQfKxhQDckktMjq9QBS7RUQ+Y5fFidp
# rkztiC8Y/JWGEKC6Z5Au/9chZrx0DeSoleiKtdVFQUvjvrgrVsamztTbnH5fkFZo
# X4lc/S0FgT3q9tys2k/nwY0jYvUO2EaBY2CnR/drdFS+iw+l0aIy9yxEQmQIDAQA
# BAoGAfJpFX5xbte6I/VFdRyANtPSljPiPGd4/kJgKfAYuczTyguN/8ZZjNYEfk/O
# 2JIPcawTckskX8EGqxfIYYKArf7rzvlEQvXiFbN/znIOfgAL8JtB5bi5bO5PXUaq
# piaAb5NQoZ+3O+T3etnxHORrpC7socZRtZIb9tQT2aLbHoDECQQDzgh3yBX0o998
# Dl1aWi28kgZOhpSAqw6ZyWvwgC+qz69w9QXkT/E1Gxmfy9uex9z2DDR/nMTc1nt9
# QkNtzrm4lAkEA77sK+DkUE8an+lZNFW8D5c/HsemVExOCF7VrZf1otTAP+Je9LAH
# BXV6VvCQyGrkR6IbkAxLWRJvOIL6+fyhsZQJBANEIBzC06YX7kaOBjEDbHONXoCW
# InB5ZqU5NMFVKJYWhmIO06nzvfl6c/qqgrLAmrtUKtTI/G0eaQ9TjJJ8fQ0kCQBr
# BEx5UsGrslr6Xdw7XTuYM5Ep0uRBh8vjWZGADgfYGoSGrPY91urDC548Rsw3MbbU
# 3qKa3KXaKtNxurS/fwQkCQHeoIAy2aRltkFsaOfeghvX4kTQFAh7uLm+JV4xGrUU
# sjtJfseYG44ETk8+m3AjwNq5jmkhif8YGeFBC8w0KdeQ=
# -----END RSA PRIVATE KEY-----
#
# To make the public file in PKCS#1 format
# openssl rsa -in private.key -out public.key -RSAPublicKey_out
#
# To get the private key to PKCS#8
# openssl pkcs8 -topk8 -inform PEM -outform PEM -in private.key -out private.pk8 -nocrypt
#
# To get the public key in PKCS#8
# openssl rsa -in private.key -pubout > public.pk8
#
# Same test data as in this file
# echo -n "hello mike" > test.txt
#
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# S I G N A T U R E
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
# To sign with PKCS#1 v1.5
# openssl dgst -sha1 -sign private.key -out test.txt.sig test.txt
# openssl dgst -sha1 -verify public.pk8 -signature test.txt.sig test.txt
# > Verified OK
#
# To sign with PKCS#1 v 2.1 (PSS)
# openssl dgst -sha1 -sign private.key -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -out test.txt.sig21 test.txt
# openssl dgst -sha1 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -verify public.pk8 -signature test.txt.sig21 test.txt
# > Verified OK
# Side note: if the MGF differs from the digest, the MGF can be specified with
# -sigopt rsa_mgf1_md:sha1
#
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# E N C R Y P T I O N
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
# To ENCRYPT a file in PKCS#1 v1.5
# openssl rsautl -encrypt -inkey public.pk8 -pubin -in test.txt -out test.txt.enc
#
# To DECRYPT a file in PKCS#1 v1.5
# openssl rsautl -decrypt -inkey private.pk8 -in test.txt.enc -out test.txt.out
#
# To ENCRYPT a file in PKCS#1 v2.1
# openssl rsautl -encrypt -inkey public.pk8 -pubin -oaep -in test.txt -out test.txt.oaep
#
# To DECRYPT a file in PKCS#1 v2.1
# openssl rsautl -decrypt -inkey private.pk8 -oaep -in test.txt.oaep -out test.txt.out
#
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# R E F E R E N C E S
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# https://developers.yubico.com/PIV/Guides/Generating_keys_using_OpenSSL.html
# https://www.czeskis.com/random/openssl-encrypt-file.html
# https://stackoverflow.com/questions/8290435/convert-pem-traditional-private-key-to-pkcs8-private-key
# https://megamorf.gitlab.io/cheat-sheets/cheat-sheet-openssl.html
# https://stackoverflow.com/questions/49236533/openssl-decrypt-using-private-key-setting-oaep
# https://stackoverflow.com/questions/44428095/how-to-verify-signature-with-pss-padding
# https://crypto.stackexchange.com/questions/31430/setting-the-mgf-hash-to-a-different-value-other-than-the-regular-hash-with-opens



(def openssl-sig-v15 (base64/decode
"VIjebW2SKxw5UxDkwkjsuTooqioPfKKVZH0nD4/oPAOQXu5SvUUrl55aN1Txywwwwlt+Ms2nxpdK
qcCcy57pPWmiw6QcGcGIsBApt+dsSshlxFl2TzrSPmESvXWMcbo385/l8UYBFXeZpn6+j5AFKQJQ
+xLAtIO76DsScT4tVFA="))

(def openssl-sig-v21 (base64/decode
"EF78CF1hGxNaAvsxw1oSGwSE9PkupFR3/sUlE9WwxGsE2r43nPQ1AqXWpl0CWj8nFVxROteqVmWq
l/OsOpY+WwTOB5IjrvVc15Imks9Vs9/UjgM8By5HOcVOEOqPddsu/uBbtmO5pyzrRSqnLAG3aTWf
X2CqUFvmpxaL9L7sm+I="))

(def openssl-enc-pkcs1-v15 (base64/decode
"DFj9U0olXojeiHfrO9o2gkmewznLQcX15Tu8SfEYevee1p5onJLACD4HtNnwobje5bBbrg9LTocB
Lm+V5fSP2H76ZVVvXNWNFkqPo9aV5+la3ZpKejgwQqAOmxRe6mGU7/cAhUuW65n7CZT5I3DnFtax
LUAoexWpmXOrMow7Z6c="))

(def openssl-enc-pkcs1-v21 (base64/decode
"yuxradajGK+RjJHzQRmLUyLYEZKXdVWO1ssxIDj4K6V9FE6JbUTCK9BaxEC2JmJ1MLSNrIZZwpT5
Ub50azLE/vUM3kNFJ+D6dNAROClmpQdM2prlSiFaXdXe1+hJLN5/uPYvTVj89Fuqd4YBjVU8+bgg
cM42i5CWJyUPchegKgE="))

(defn import-keys [] (do
  (def asn1-private-key (asn1/decode rsa-key))
  (def asn1-public-key (asn1/decode rsa-pub-key))

  (def {:value [_ {:value n} {:value e} {:value d} {:value p} {:value q}]} asn1-private-key)
  (def {:value [{:value n2} {:value e2}]} asn1-public-key)
  (def private-v1.5 (rsa/import {:n n :e e :d d :p p :q q :digest :sha1 :version :pkcs1-v1.5}))
  (def public-v1.5 (rsa/import {:n n2 :e e2 :digest :sha1 :version :pkcs1-v1.5}))
  (def private-v2.1 (rsa/import {:n n :e e :d d :p p :q q :digest :sha1 :version :pkcs1-v2.1 :mask :sha1}))
  (def public-v2.1 (rsa/import {:n n2 :e e2 :digest :sha1 :version :pkcs1-v2.1 :mask :sha1}))
  # Final return value
  [private-v1.5 public-v1.5 private-v2.1 public-v2.1]
  ))

(deftest "Imported RSA private key can sign and verify" (do
  (def [private-v1.5 public-v1.5 private-v2.1 public-v2.1] (import-keys))

  (is (not= nil private-v1.5))
  (is (not= nil public-v1.5))
  (is (not= nil private-v2.1))
  (is (not= nil public-v2.1))
  (def exp-private (:export-public private-v1.5))
  (def exp-public (:export-public public-v1.5))
  (eachk component exp-private
    (if (not= :random component) (is (=
      (get exp-private component)
      (get exp-public component)
      ))))

  (def sig (rsa/sign private-v1.5 data))
  (def sig2 (rsa/sign private-v1.5 data))
  (is (:verify private-v1.5 data sig))
  (is (:verify public-v1.5 data sig))
  (is (:verify private-v1.5 data sig2))
  (is (:verify public-v1.5 data sig2))
  # Compatible with openssl signed data (likely the same!)
  (is (:verify private-v1.5 data openssl-sig-v15))
  # Now for v2.1
  (def sig3 (rsa/sign private-v2.1 data))
  (def sig4 (rsa/sign private-v2.1 data))
  (is (:verify private-v2.1 data sig3))
  (is (:verify public-v2.1 data sig3))
  (is (:verify private-v2.1 data sig4))
  (is (:verify public-v2.1 data sig4))
  (print "About to try openssl sig")
  # Compatible with openssl signed data, will be different due to how PSS works
  (is (:verify public-v2.1 data openssl-sig-v21))
  ))

(deftest "Imported RSA private key can encrypt and decrypt" (do
  (def [private-v1.5 public-v1.5 private-v2.1 public-v2.1] (import-keys))
  # nil checks in prior test.

  ))


(run-tests!)
