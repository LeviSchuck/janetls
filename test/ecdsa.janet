(import testament :prefix "" :exit true)
# Testament framework documentation
# https://github.com/pyrmont/testament/blob/master/api.md
(import ../build/janetls :exit true :prefix "")

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# S E T U P
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# private.key file with (the same contents as ec-private below)
# -----BEGIN RSA PRIVATE KEY-----
# MHcCAQEEIH4et747bbOv+eLWNSW01tr9zuYSYGSjBT6T4NTpNTLYoAoGCCqGSM4
# 9AwEHoUQDQgAEly/EM+lE5907zBNwYy2QQ6UVKQC0wEYF/pxNtkoMO4CzC+XtZWh
# RVMsgtfPaOgcCb5EamDXYV68Ius9v7VZ9jQ==
# -----END RSA PRIVATE KEY-----
#
# To get the public key
# openssl ec -in private.key -pubout -out public.pem
#
# Same test data as in this file
# echo -n "hello mike" > test.txt
#
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# S I G N A T U R E
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
# To sign with ECDSA
# openssl dgst -sha256 -sign private.key -out test.txt.sig test.txt
# openssl dgst -verify public.pem -signature test.txt.sig test.txt
# > Verified OK
#
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# E N C R Y P T I O N
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
# Not Applicable, ECDSA is sign / verify only
#
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# R E F E R E N C E S
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# https://superuser.com/questions/1258478/how-to-get-ecsda-with-p-256-and-sha256-in-openssl
# https://wiki.openssl.org/index.php/Command_Line_Elliptic_Curve_Operations



(def ec-private (base64/decode
"MHcCAQEEIH4et747bbOv+eLWNSW01tr9zuYSYGSjBT6T4NTpNTLYoAoGCCqGSM4
9AwEHoUQDQgAEly/EM+lE5907zBNwYy2QQ6UVKQC0wEYF/pxNtkoMO4CzC+XtZWh
RVMsgtfPaOgcCb5EamDXYV68Ius9v7VZ9jQ=="))
(def ec-public (base64/decode
"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEly/EM+lE5907zBNwYy2QQ6UVKQC0
wEYF/pxNtkoMO4CzC+XtZWhRVMsgtfPaOgcCb5EamDXYV68Ius9v7VZ9jQ=="))

(def ec-sig (base64/decode
"MEUCIEi14Vdi33Pz2WR08GfYL9i2FguLc+CQ+9OOs9y+HtBBAiEAhxy+f56c1IRt
2paIdC8fK69OWHgxjqmCK19yjdv+ZQo="))

(def junk-sig (base64/decode
"junkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunk
junkjunkjunkjunkjunkju"))

(def other-sig (base64/decode
"MEYCIQCZdes6iHAwar75ObRmGarDHVdjYG5nUe8cg/p5TfPwPQIhAOFu/4A7w4m5FNFrwy0qFvO5
A2y8LaBzwu/iGUz2Wgio"))

(def data "hello mike")

# (def ec-key-full {
#   :value [
#     {:value (bignum/parse "1") :type :integer}
#     {:value "~\x1E\xB7\xBE;m\xB3\xAF\xF9\xE2\xD65%\xB4\xD6\xDA\xFD\xCE\xE6\x12`d\xA3\x05>\x93\xE0\xD4\xE952\xD8" :type :octet-string}
#     {:tag 0
#       :value [
#         {:value [1 2 840 10045 3 1 7] :type :object-identifier}
#       ]
#       :type :context-specific
#       :constructed true
#     }
#     {:tag 1 :value [
#       {:bits 520 :value "\x04\x97/\xC43\xE9D\xE7\xDD;\xCC\x13pc-\x90C\xA5\x15)\0\xB4\xC0F\x05\xFE\x9CM\xB6J\f;\x80\xB3\v\xE5\xEDehQT\xCB \xB5\xF3\xDA:\x07\x02o\x91\x1A\x985\xD8W\xAF\x08\xBA\xCFo\xEDV}\x8D" :type :bit-string}
#       ]
#       :type :context-specific
#       :constructed true
#     }
#   ]
#   :type :sequence
# })

# (def private {:value [
#   {:value [{:value (1 2 840 10045 2 1) :type :object-identifier} {:value (1 2 840 10045 3 1 7) :type :object-identifier}] :type :sequence}
#   {:bits 520 :value "\x04\x8D\xF1\xF0\x90\xE8\r0\xC2\xE6\xA3\x08\x1D\xCD\xE9\xCD\e\xBC\x85\xC6\xC1\xA7\xC8a\xEB\xF1\x9A\n\x99\x897\x84\xDF\xBA&\xEC\xAD\xF2\xE5\x1C\xA3z\xE4`\xC1\xDF8`\xDC%\xCD\xD8A>\xB2.\xA25\xF1\x8A\xEE\xE4B)\xAA" :type :bit-string}
#   ] :type :sequence})

(defn import-keys [] (do
  (def asn1-private-key (asn1/decode ec-private))
  (def asn1-public-key (asn1/decode ec-public))

  (def {:value [_ {:value d} _ _]} asn1-private-key)
  (def {:value [_ {:value p}]} asn1-public-key)
  (def private (ecdsa/import {:curve :p256 :d d}))
  (def public (ecdsa/import {:curve :p256 :p p}))
  # Final return value
  [private public]
  ))

(deftest "OpenSSL signature verifies OK" (do
  (def [private public] (import-keys))
  # Note that OpenSSL signatures are actually ASN.1 encoded
  # as SEQUENCE [R, S]
  # This library will attempt to detect that and use it.
  (is (ecdsa/verify private data ec-sig))
  (is (ecdsa/verify public data ec-sig))
  ))

(deftest "Can sign and verify own signatures" (do
  (def [private public] (import-keys))
  (def sig (:sign private data))
  (is (:verify private data sig))
  (is (:verify public data sig))
  (def re-private (ecdsa/import (ecdsa/export-private private)))
  (def re-public (ecdsa/import (ecdsa/export-public public)))
  (def sig2 (:sign re-private data))
  (is (:verify private data sig2))
  (is (:verify public data sig2))
  (is (:verify re-private data sig2))
  (is (:verify re-public data sig2))
  ))

(deftest "Public key cannot sign" (do
  (def [_ public] (import-keys))
  (assert-thrown (:sign public data))
  ))

(deftest "Handles negative verifications" (do
  (def [_ public] (import-keys))
  # Incorrect length
  (assert-thrown (:verify public data "junk"))
  # Correct length but junk
  (is (not (:verify public data junk-sig)))
  # an actual signature but from another key
  (is (not (:verify public data other-sig)))
  ))

(deftest "Generated keys can verify and sign themselves" (do
  (def k (ecdsa/generate))
  (def sig (:sign k data))
  (is (:verify k data sig))
  (def kp (ecdsa/import (ecdsa/export-public k)))
  (is (:verify kp data sig))
  ))

(deftest "Generated keys cannot cross verify and sign" (do
  (def k1 (ecdsa/generate))
  (def k2 (ecdsa/generate))
  (def sig1 (:sign k1 data))
  (def sig2 (:sign k2 data))
  (is (not (:verify k1 data sig2)))
  (is (not (:verify k2 data sig1)))
  (is (:verify k1 data sig1))
  (is (:verify k2 data sig2))
  ))

(deftest "Other functions on ecdsa" (do
  (def k (ecdsa/generate))
  (def kp (ecdsa/import (ecdsa/export-public k)))
  (is (= :secp256r1 (:curve-group k)))
  (is (= :secp256r1 (ecdsa/curve-group kp)))
  (is (ecdsa/private? k))
  (is (not (ecdsa/public? k)))
  (is (ecdsa/public? kp))
  (is (not (ecdsa/private? kp)))
  (is (= :sha256 (:digest k)))
  (is (= :sha256 (ecdsa/digest kp)))
  (is (= 256 (:bits k)))
  (is (= 256 (ecdsa/bits kp)))
  (is (= 32 (:bytes k)))
  (is (= 32 (ecdsa/bytes kp)))
  ))

(run-tests!)
