(import testament :prefix "" :exit true)
# Testament framework documentation
# https://github.com/pyrmont/testament/blob/master/api.md
(import ../build/janetls :exit true :prefix "")

(def secret (hex/decode "89002409a65f3cf3aa05597f54e7b71133fae49e60229af87764e8c7390fda64"))
# Notice that the point is uncompressed, it starts with 04 in hex.
(def point (hex/decode "04d884172ad2e2e606206bfb185c46b3068e2bd1545cb2bdfb897d20b7701c92b777b4d528b6b6d017aa0232e0fab5d00835897f749107825cb7f54ef52b6a68c3"))

# Using a python lib to verify behiavor and values
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/
# >>> x = """-----BEGIN EC PRIVATE KEY-----
# MHcCAQEEIIkAJAmmXzzzqgVZf1TntxEz+uSeYCKa+Hdk6Mc5D9pkoAoGCCqGSM49
# AwEHoUQDQgAE2IQXKtLi5gYga/sYXEazBo4r0VRcsr37iX0gt3Ackrd3tNUotrbQ
# F6oCMuD6tdAINYl/dJEHgly39U71K2poww==
# -----END EC PRIVATE KEY-----"""
# >>> x = str.encode(x)
# >>> k = serialization.load_pem_private_key(x, password=None)
# >>> k2 = k.public_key()
# >>> k2.public_numbers()
# <EllipticCurvePublicNumbers(curve=secp256r1, x=97932959001228944715530423801310881484445799714271353323835471892332318331575, y=54144732622680584404553551109381818697054152464078391517485354706964507683011>
# >>> k3 = k.private_numbers()
# >>> k3.private_value
# 61967108978936518767801664883965821004203860727145275278412563824610481527396

(def point-x (bignum/parse                       "97932959001228944715530423801310881484445799714271353323835471892332318331575"))
(def point-y (bignum/parse                       "54144732622680584404553551109381818697054152464078391517485354706964507683011"))
(def secret-value (bignum/to-bytes (bignum/parse "61967108978936518767801664883965821004203860727145275278412563824610481527396")))

(def group (ecp/load-curve-group :secp256r1))

(deftest "Curve group has zero" (is (not= nil (ecp/zero group))))
(deftest "Curve group zero is recognized as zero" (is (ecp/zero? (ecp/zero group))))
(deftest "Curve group has generator" (is (not= nil (ecp/generator group))))
(deftest "Curve group generator is not recognized as zero" (is (not (ecp/zero? (ecp/generator group)))))

# https://medium.com/@billatnapier/barebones-p256-1700ff5a4
(def p256-x (bignum/parse "48439561293906451759052585252797914202762949526041747995844080717082404635286"))
(def p256-y (bignum/parse "36134250956749795798585127919587881956611106672985015071877198253568414405109"))

(deftest "Curve group generator X is as expected" (do
  (is (= p256-x (ecp/x (ecp/generator group))))
  (is (= p256-x (:x (ecp/generator group))))
  ))
(deftest "Curve group generator Y is as expected" (do
  (is (= p256-y (ecp/y (ecp/generator group))))
  (is (= p256-y (:y (ecp/generator group))))
  ))

(deftest "Parsed point matches python cryptography.hazmat" (do
  (def p (:import-point group point))
  (is (= point-x (:x p)))
  (is (= point-x (ecp/x p)))
  (is (= point-y (:y p)))
  (is (= point-y (ecp/y p)))
  (is (= point (ecp/export-point p)))
  (is (= point (:export p)))
  (is (= p (ecp/import-point group point)))
  ))

(deftest "Parsed secret matches python cryptography.hazmat" (do
  (def k (ecp/import-keypair group secret))
  (is (not= nil k))
  (is (= secret-value (:secret k)))
  (is (= secret-value (ecp/secret k)))
  (is (= secret (ecp/export-keypair k)))
  (is (= secret (:export k)))
  (is (= k (ecp/import-keypair group secret)))
  # It derives the public point correctly
  (def p (:point k))
  (is (= point-x (:x p)))
  (is (= point-x (ecp/x p)))
  (is (= point-y (:y p)))
  (is (= point-y (ecp/y p)))
  (def p2 (ecp/point k))
  (is (= point-x (:x p2)))
  (is (= point-x (ecp/x p2)))
  (is (= point-y (:y p2)))
  (is (= point-y (ecp/y p2)))
  ))

(deftest "Generating keys are unique" (do
  (def k1 (ecp/generate group))
  (def k2 (ecp/generate group))
  (is (not= k1 k2))
  (is (not= (:point k1) (:point k2)))
  (is (not= (:secret k1) (:secret k2)))
  ))

(deftest "Generated keys can be exported and imported" (do
  (def k (ecp/generate group))
  (def ex (:export k))
  (def k2 (ecp/import-keypair group ex))
  (is (= k k2))
  ))

(run-tests!)
