(import testament :prefix "" :exit true)
(import ../janetls :exit true :prefix "")

(setdyn :pretty-format "%.99N")

# https://cryptobook.nakov.com/asymmetric-key-ciphers/ecdh-key-exchange-examples
# I cannot find any examples online, therefore the following tests will
# Be created by referencing a known implementation
# python cryptography uses openssl as a backend
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec.html#cryptography.hazmat.primitives.asymmetric.ec.ECDH

# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives.asymmetric import ec
# from cryptography.hazmat.backends import default_backend
#
# pubkey = """-----BEGIN PUBLIC KEY-----
# MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENP9hG3V3eIhxysDOmbinYfiqZwNr
# Jvqi+Ue6Jvit1FEBWSScTQFkLzpTBElN5bbqmqY+HGVnAEKyqfjQDu4ITg==
# -----END PUBLIC KEY-----"""
# privkey = """-----BEGIN EC PRIVATE KEY-----
# MHcCAQEEIIkAJAmmXzzzqgVZf1TntxEz+uSeYCKa+Hdk6Mc5D9pkoAoGCCqGSM49
# AwEHoUQDQgAE2IQXKtLi5gYga/sYXEazBo4r0VRcsr37iX0gt3Ackrd3tNUotrbQ
# F6oCMuD6tdAINYl/dJEHgly39U71K2poww==
# -----END EC PRIVATE KEY-----"""
# backend = default_backend()
# private = serialization.load_pem_private_key(str.encode(privkey), password=None, backend=backend)
# public = serialization.load_pem_public_key(str.encode(pubkey), backend=backend)
# shared_key = private.exchange(ec.ECDH(), public)
# print(bytes.hex(shared_key))
# # 4522afc823e522f6f280f1bb5d16b63995e219662345ac60e62dcb8726a2e0dc

# (def pubkey `-----BEGIN PUBLIC KEY-----
# MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENP9hG3V3eIhxysDOmbinYfiqZwNr
# Jvqi+Ue6Jvit1FEBWSScTQFkLzpTBElN5bbqmqY+HGVnAEKyqfjQDu4ITg==
# -----END PUBLIC KEY-----`)
# (def privkey `-----BEGIN EC PRIVATE KEY-----
# MHcCAQEEIIkAJAmmXzzzqgVZf1TntxEz+uSeYCKa+Hdk6Mc5D9pkoAoGCCqGSM49
# AwEHoUQDQgAE2IQXKtLi5gYga/sYXEazBo4r0VRcsr37iX0gt3Ackrd3tNUotrbQ
# F6oCMuD6tdAINYl/dJEHgly39U71K2poww==
# -----END EC PRIVATE KEY-----`)
# (def p1 (pk/export (pk/import {:pem privkey})))
# (print (hex/encode (p1 :d)))
# (def p2 (pk/export (pk/import {:pem pubkey})))
# (print (hex/encode (p2 :p)))

(def private-value (hex/decode "89002409a65f3cf3aa05597f54e7b71133fae49e60229af87764e8c7390fda64"))
(def public-value (hex/decode "0434ff611b7577788871cac0ce99b8a761f8aa67036b26faa2f947ba26f8add4
510159249c4d01642f3a5304494de5b6ea9aa63e1c65670042b2a9f8d00eee084e"))

(def expected "4522afc823e522f6f280f1bb5d16b63995e219662345ac60e62dcb8726a2e0dc")

(deftest "Matches openssl (via python) implementation"
  (def priv (ecp/import-keypair :secp256r1 private-value))
  (def pub (ecp/import-point :secp256r1 public-value))
  (is (= expected (hex/encode (ecdh/compute priv pub))))
  )

(deftest "Same result with newly generated keys"
  (def key1 (ecdh/generate-key :secp256r1))
  (def key2 (ecdh/generate-key :secp256r1))
  (is (= (hex/encode (ecdh/compute key1 key2)) (hex/encode (ecdh/compute key2 key1))))
  )

(run-tests!)
