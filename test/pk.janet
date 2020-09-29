(import testament :prefix "" :exit true)
(import ../janetls :exit true :prefix "")

(setdyn :pretty-format "%.99N")

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

(deftest "RSA can be wrapped and behaves as if imported"
  (def wrapped (pk/wrap rsa-key))
  (def sig (:sign wrapped data {:encoding :hex}))
  (is (:verify pk-rsa data sig {:encoding :hex}))
  (is (:verify public-rsa data sig {:encoding :hex}))
  )

(deftest "ECDSA can be wrapped and behaves as if imported"
  (def wrapped (pk/wrap ecdsa-key))
  (def sig (:sign wrapped data {:encoding :hex}))
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

(def rsa-private-pkcs1-pem
"
-----BEGIN RSA PRIVATE KEY-----\n
MIICXAIBAAKBgQDkCGRwBG1j/WPjDO+nkQfKxhQDckktMjq9QBS7RUQ+Y5fFidpr\n
kztiC8Y/JWGEKC6Z5Au/9chZrx0DeSoleiKtdVFQUvjvrgrVsamztTbnH5fkFZoX\n
4lc/S0FgT3q9tys2k/nwY0jYvUO2EaBY2CnR/drdFS+iw+l0aIy9yxEQmQIDAQAB\n
AoGAfJpFX5xbte6I/VFdRyANtPSljPiPGd4/kJgKfAYuczTyguN/8ZZjNYEfk/O2\n
JIPcawTckskX8EGqxfIYYKArf7rzvlEQvXiFbN/znIOfgAL8JtB5bi5bO5PXUaqp\n
iaAb5NQoZ+3O+T3etnxHORrpC7socZRtZIb9tQT2aLbHoDECQQDzgh3yBX0o998D\n
l1aWi28kgZOhpSAqw6ZyWvwgC+qz69w9QXkT/E1Gxmfy9uex9z2DDR/nMTc1nt9Q\n
kNtzrm4lAkEA77sK+DkUE8an+lZNFW8D5c/HsemVExOCF7VrZf1otTAP+Je9LAHB\n
XV6VvCQyGrkR6IbkAxLWRJvOIL6+fyhsZQJBANEIBzC06YX7kaOBjEDbHONXoCWI\n
nB5ZqU5NMFVKJYWhmIO06nzvfl6c/qqgrLAmrtUKtTI/G0eaQ9TjJJ8fQ0kCQBrB\n
Ex5UsGrslr6Xdw7XTuYM5Ep0uRBh8vjWZGADgfYGoSGrPY91urDC548Rsw3MbbU3\n
qKa3KXaKtNxurS/fwQkCQHeoIAy2aRltkFsaOfeghvX4kTQFAh7uLm+JV4xGrUUs\n
jtJfseYG44ETk8+m3AjwNq5jmkhif8YGeFBC8w0KdeQ=\n
-----END RSA PRIVATE KEY-----
")

(def rsa-priv-pkcs8 (base64/decode
"MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAOQIZHAEbWP9Y+MM
76eRB8rGFANySS0yOr1AFLtFRD5jl8WJ2muTO2ILxj8lYYQoLpnkC7/1yFmvHQN5
KiV6Iq11UVBS+O+uCtWxqbO1Nucfl+QVmhfiVz9LQWBPer23KzaT+fBjSNi9Q7YR
oFjYKdH92t0VL6LD6XRojL3LERCZAgMBAAECgYB8mkVfnFu17oj9UV1HIA209KWM
+I8Z3j+QmAp8Bi5zNPKC43/xlmM1gR+T87Ykg9xrBNySyRfwQarF8hhgoCt/uvO+
URC9eIVs3/Ocg5+AAvwm0HluLls7k9dRqqmJoBvk1Chn7c75Pd62fEc5GukLuyhx
lG1khv21BPZotsegMQJBAPOCHfIFfSj33wOXVpaLbySBk6GlICrDpnJa/CAL6rPr
3D1BeRP8TUbGZ/L257H3PYMNH+cxNzWe31CQ23OubiUCQQDvuwr4ORQTxqf6Vk0V
bwPlz8ex6ZUTE4IXtWtl/Wi1MA/4l70sAcFdXpW8JDIauRHohuQDEtZEm84gvr5/
KGxlAkEA0QgHMLTphfuRo4GMQNsc41egJYicHlmpTk0wVUolhaGYg7TqfO9+Xpz+
qqCssCau1Qq1Mj8bR5pD1OMknx9DSQJAGsETHlSwauyWvpd3DtdO5gzkSnS5EGHy
+NZkYAOB9gahIas9j3W6sMLnjxGzDcxttTeoprcpdoq03G6tL9/BCQJAd6ggDLZp
GW2QWxo596CG9fiRNAUCHu4ub4lXjEatRSyO0l+x5gbjgROTz6bcCPA2rmOaSGJ/
xgZ4UELzDQp15A=="))

(def rsa-private-pkcs8-pem
"
-----BEGIN PRIVATE KEY-----\n
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAOQIZHAEbWP9Y+MM\n
76eRB8rGFANySS0yOr1AFLtFRD5jl8WJ2muTO2ILxj8lYYQoLpnkC7/1yFmvHQN5\n
KiV6Iq11UVBS+O+uCtWxqbO1Nucfl+QVmhfiVz9LQWBPer23KzaT+fBjSNi9Q7YR\n
oFjYKdH92t0VL6LD6XRojL3LERCZAgMBAAECgYB8mkVfnFu17oj9UV1HIA209KWM\n
+I8Z3j+QmAp8Bi5zNPKC43/xlmM1gR+T87Ykg9xrBNySyRfwQarF8hhgoCt/uvO+\n
URC9eIVs3/Ocg5+AAvwm0HluLls7k9dRqqmJoBvk1Chn7c75Pd62fEc5GukLuyhx\n
lG1khv21BPZotsegMQJBAPOCHfIFfSj33wOXVpaLbySBk6GlICrDpnJa/CAL6rPr\n
3D1BeRP8TUbGZ/L257H3PYMNH+cxNzWe31CQ23OubiUCQQDvuwr4ORQTxqf6Vk0V\n
bwPlz8ex6ZUTE4IXtWtl/Wi1MA/4l70sAcFdXpW8JDIauRHohuQDEtZEm84gvr5/\n
KGxlAkEA0QgHMLTphfuRo4GMQNsc41egJYicHlmpTk0wVUolhaGYg7TqfO9+Xpz+\n
qqCssCau1Qq1Mj8bR5pD1OMknx9DSQJAGsETHlSwauyWvpd3DtdO5gzkSnS5EGHy\n
+NZkYAOB9gahIas9j3W6sMLnjxGzDcxttTeoprcpdoq03G6tL9/BCQJAd6ggDLZp\n
GW2QWxo596CG9fiRNAUCHu4ub4lXjEatRSyO0l+x5gbjgROTz6bcCPA2rmOaSGJ/\n
xgZ4UELzDQp15A==\n
-----END PRIVATE KEY-----
")

(def rsa-pub-key (base64/decode
"MIGJAoGBAOQIZHAEbWP9Y+MM76eRB8rGFANySS0yOr1AFLtFRD5jl8WJ2muTO2IL
xj8lYYQoLpnkC7/1yFmvHQN5KiV6Iq11UVBS+O+uCtWxqbO1Nucfl+QVmhfiVz9L
QWBPer23KzaT+fBjSNi9Q7YRoFjYKdH92t0VL6LD6XRojL3LERCZAgMBAAE="))

(def rsa-public-pkcs1-pem
"
-----BEGIN RSA PUBLIC KEY-----\n
MIGJAoGBAOQIZHAEbWP9Y+MM76eRB8rGFANySS0yOr1AFLtFRD5jl8WJ2muTO2IL\n
xj8lYYQoLpnkC7/1yFmvHQN5KiV6Iq11UVBS+O+uCtWxqbO1Nucfl+QVmhfiVz9L\n
QWBPer23KzaT+fBjSNi9Q7YRoFjYKdH92t0VL6LD6XRojL3LERCZAgMBAAE=\n
-----END RSA PUBLIC KEY-----
")

(def rsa-pub-pkcs8 (base64/decode
"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkCGRwBG1j/WPjDO+nkQfKxhQD
ckktMjq9QBS7RUQ+Y5fFidprkztiC8Y/JWGEKC6Z5Au/9chZrx0DeSoleiKtdVFQ
UvjvrgrVsamztTbnH5fkFZoX4lc/S0FgT3q9tys2k/nwY0jYvUO2EaBY2CnR/drd
FS+iw+l0aIy9yxEQmQIDAQAB"))

(def rsa-public-pkcs8-pem
"
-----BEGIN PUBLIC KEY-----\n
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkCGRwBG1j/WPjDO+nkQfKxhQD\n
ckktMjq9QBS7RUQ+Y5fFidprkztiC8Y/JWGEKC6Z5Au/9chZrx0DeSoleiKtdVFQ\n
UvjvrgrVsamztTbnH5fkFZoX4lc/S0FgT3q9tys2k/nwY0jYvUO2EaBY2CnR/drd\n
FS+iw+l0aIy9yxEQmQIDAQAB\n
-----END PUBLIC KEY-----
")

(def ec-private-sec1 (base64/decode
"MHcCAQEEIH4et747bbOv+eLWNSW01tr9zuYSYGSjBT6T4NTpNTLYoAoGCCqGSM4
9AwEHoUQDQgAEly/EM+lE5907zBNwYy2QQ6UVKQC0wEYF/pxNtkoMO4CzC+XtZWh
RVMsgtfPaOgcCb5EamDXYV68Ius9v7VZ9jQ=="))

(def ec-private-sec1-pem
"
-----BEGIN EC PRIVATE KEY-----\n
MHcCAQEEIH4et747bbOv+eLWNSW01tr9zuYSYGSjBT6T4NTpNTLYoAoGCCqGSM49\n
AwEHoUQDQgAEly/EM+lE5907zBNwYy2QQ6UVKQC0wEYF/pxNtkoMO4CzC+XtZWhR\n
VMsgtfPaOgcCb5EamDXYV68Ius9v7VZ9jQ==\n
-----END EC PRIVATE KEY-----
")

# There is no public sec1 key..

(def ec-private-pkcs8 (base64/decode
"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgfh63vjtts6/54tY1
JbTW2v3O5hJgZKMFPpPg1Ok1MtihRANCAASXL8Qz6UTn3TvME3BjLZBDpRUpALTA
RgX+nE22Sgw7gLML5e1laFFUyyC189o6BwJvkRqYNdhXrwi6z2/tVn2N"))

(def ec-private-pkcs8-pem
"-----BEGIN PRIVATE KEY-----\n
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgfh63vjtts6/54tY1\n
JbTW2v3O5hJgZKMFPpPg1Ok1MtihRANCAASXL8Qz6UTn3TvME3BjLZBDpRUpALTA\n
RgX+nE22Sgw7gLML5e1laFFUyyC189o6BwJvkRqYNdhXrwi6z2/tVn2N\n
-----END PRIVATE KEY-----
")

(def ec-public-pkcs8 (base64/decode
"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEly/EM+lE5907zBNwYy2QQ6UVKQC0
wEYF/pxNtkoMO4CzC+XtZWhRVMsgtfPaOgcCb5EamDXYV68Ius9v7VZ9jQ=="))

(def ec-public-pkcs8-pem
"-----BEGIN PUBLIC KEY-----\n
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEly/EM+lE5907zBNwYy2QQ6UVKQC0\n
wEYF/pxNtkoMO4CzC+XtZWhRVMsgtfPaOgcCb5EamDXYV68Ius9v7VZ9jQ==\n
-----END PUBLIC KEY-----
")


(deftest "rsa public export is identical"
  (def asn1-public-key (asn1/decode rsa-pub-key))
  (def {:value [{:value n} {:value e}]} asn1-public-key)
  (def pub (pk/import {:n n :e e :type :rsa}))
  (def exported (pk/export-public pub {:export-standard :pkcs1 :export-format :encoded :export-encoding :der}))
  (def {:der der} exported)
  (is (= der rsa-pub-key))

  (def {:der der} (pk/export-public pub {:export-standard :pkcs8 :export-format :encoded :export-encoding :der}))
  (is (= der rsa-pub-pkcs8))

  (def pub (pk/import {:der rsa-pub-key}))
  (def {:der der} (pk/export-public pub {:export-standard :pkcs8 :export-format :encoded :export-encoding :der}))
  (is (= der rsa-pub-pkcs8))

  (def pub (pk/import {:der rsa-pub-pkcs8}))
  (def {:der der} (pk/export-public pub {:export-standard :pkcs8 :export-format :encoded :export-encoding :der}))
  (is (= der rsa-pub-pkcs8))

  (def pub (pk/import {:pem rsa-public-pkcs1-pem}))
  (def {:der der} (pk/export-public pub {:export-standard :pkcs8 :export-format :encoded :export-encoding :der}))
  (is (= der rsa-pub-pkcs8))
  (def {:pem pem} (pk/export-public pub {:export-standard :pkcs1 :export-format :encoded :export-encoding :pem}))
  (is (= pem rsa-public-pkcs1-pem))
  )

(deftest "rsa private export is identical"
  (def asn1-private-key (asn1/decode rsa-priv-key))
  (def {:value [_ {:value n} {:value e} {:value d} {:value p} {:value q}]} asn1-private-key)
  (def priv (pk/import {:n n :e e :d d :p p :q q :type :rsa}))
  (def exported (pk/export-private priv {:export-standard :pkcs1 :export-format :encoded :export-encoding :der}))
  (def {:der der} exported)
  (is (= der rsa-priv-key))

  (def {:der der} (pk/export-private priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :der}))
  (is (= der rsa-priv-pkcs8))

  (def priv (pk/import {:der rsa-priv-key}))
  (def {:der der} (pk/export-private priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :der}))
  (is (= der rsa-priv-pkcs8))

  (def priv (pk/import {:der rsa-priv-pkcs8}))
  (def {:der der} (pk/export-private priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :der}))
  (is (= der rsa-priv-pkcs8))

  (def priv (pk/import {:pem rsa-private-pkcs1-pem}))
  (def {:der der} (pk/export-private priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :der}))
  (is (= der rsa-priv-pkcs8))
  (def {:pem pem} (pk/export-private priv {:export-standard :pkcs1 :export-format :encoded :export-encoding :pem}))
  (is (= pem rsa-private-pkcs1-pem))
  )

(deftest "ec private export is identical"
  (def asn1-private-key (asn1/decode ec-private-sec1))
  (def {:value [_ {:value d} {:value [{:value oid}]} ]} asn1-private-key)
  (def curve (oid/to-curve oid))
  (def priv (pk/import {:d d :curve-group curve :type :ecdsa}))
  (def exported (pk/export-private priv {:export-standard :sec1 :export-format :encoded :export-encoding :der}))
  (def {:der der} exported)
  (is (= der ec-private-sec1))

  (def {:der der} (pk/export-private priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :der}))
  (is (= der ec-private-pkcs8))

  (def priv (pk/import {:der ec-private-sec1}))
  (def {:der der} (pk/export-private priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :der}))
  (is (= der ec-private-pkcs8))

  (def priv (pk/import {:der ec-private-pkcs8}))
  (def {:der der} (pk/export-private priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :der}))
  (is (= der ec-private-pkcs8))

  (def priv (pk/import {:pem ec-private-sec1-pem}))
  (def {:der der} (pk/export-private priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :der}))
  (is (= der ec-private-pkcs8))
  (def {:pem pem} (pk/export-private priv {:export-standard :sec1 :export-format :encoded :export-encoding :pem}))
  (is (= pem ec-private-sec1-pem))
  )

(deftest "ec public export is identical"
  (def asn1-private-key (asn1/decode ec-private-sec1))
  (def {:value [_ {:value d} {:value [{:value oid}]} ]} asn1-private-key)
  (def curve (oid/to-curve oid))
  (def priv (pk/import {:d d :curve-group curve :type :ecdsa}))
  (def exported (pk/export-public priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :der}))
  (def {:der der} exported)
  (is (= der ec-public-pkcs8))

  (def priv (pk/import {:der ec-public-pkcs8}))
  (def exported (pk/export-public priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :der}))
  (def {:der der} exported)
  (is (= der ec-public-pkcs8))

  (def priv (pk/import {:pem ec-public-pkcs8-pem}))
  (def exported (pk/export-public priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :der}))
  (def {:der der} exported)
  (is (= der ec-public-pkcs8))
  )

(deftest "pem export is identical"
  # RSA
  (def asn1-private-key (asn1/decode rsa-priv-key))
  (def {:value [_ {:value n} {:value e} {:value d} {:value p} {:value q}]} asn1-private-key)
  (def priv (pk/import {:n n :e e :d d :p p :q q :type :rsa}))
  (def {:pem pem} (pk/export-private priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :pem}))
  (is (= rsa-private-pkcs8-pem pem))

  (def {:pem pem} (pk/export-private priv {:export-standard :pkcs1 :export-format :encoded :export-encoding :pem}))
  (is (= rsa-private-pkcs1-pem pem))

  (def {:pem pem} (pk/export-public priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :pem}))
  (is (= rsa-public-pkcs8-pem pem))

  (def {:pem pem} (pk/export-public priv {:export-standard :pkcs1 :export-format :encoded :export-encoding :pem}))
  (is (= rsa-public-pkcs1-pem pem))

  # EC
  (def asn1-private-key (asn1/decode ec-private-sec1))
  (def {:value [_ {:value d} {:value [{:value oid}]} ]} asn1-private-key)
  (def curve (oid/to-curve oid))
  (def priv (pk/import {:d d :curve-group curve :type :ecdsa}))

  (def {:pem pem} (pk/export-private priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :pem}))
  (is (= ec-private-pkcs8-pem pem))

  (def {:pem pem} (pk/export-private priv {:export-standard :sec1 :export-format :encoded :export-encoding :pem}))
  (is (= ec-private-sec1-pem pem))

  (def {:pem pem} (pk/export-public priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :pem}))
  (is (= ec-public-pkcs8-pem pem))
)

(defn ck [key]
  (def sig (:sign key data))
  (is sig)
  (is (:verify key data sig))
  )

(deftest "Generating is fine"
  (ck (pk/generate))
  (ck (pk/generate :rsa))
  (ck (pk/generate :rsa 1024))
  (ck (pk/generate :rsa 2048))
  (ck (pk/generate :ecdsa))
  (ck (pk/generate :ecdsa :secp192r1))
  (ck (pk/generate :ecdsa :secp256r1))
  (ck (pk/generate :ecdsa :secp384r1))
  (ck (pk/generate :ecdsa :secp521r1))
  (assert-thrown (pk/generate :rsa "hello"))
  (assert-thrown (pk/generate :rsa 1025))
  (assert-thrown (pk/generate :ecdsa :secp521k1))
  )

(run-tests!)
