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

(def pubkey `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENP9hG3V3eIhxysDOmbinYfiqZwNr
Jvqi+Ue6Jvit1FEBWSScTQFkLzpTBElN5bbqmqY+HGVnAEKyqfjQDu4ITg==
-----END PUBLIC KEY-----`)
(def privkey `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIkAJAmmXzzzqgVZf1TntxEz+uSeYCKa+Hdk6Mc5D9pkoAoGCCqGSM49
AwEHoUQDQgAE2IQXKtLi5gYga/sYXEazBo4r0VRcsr37iX0gt3Ackrd3tNUotrbQ
F6oCMuD6tdAINYl/dJEHgly39U71K2poww==
-----END EC PRIVATE KEY-----`)



(def expected "4522afc823e522f6f280f1bb5d16b63995e219662345ac60e62dcb8726a2e0dc")

(deftest "Matches openssl (via python) implementation"
  (def priv ((pk/import {:pem privkey}) :key))
  (def pub ((pk/import {:pem pubkey}) :key))
  (is (= expected (hex/encode (ecdh/compute priv pub))))
  )

(deftest "Same result with newly generated keys"
  (def key1 (ecdh/generate-key :secp256r1))
  (def key2 (ecdh/generate-key :secp256r1))
  (is (= (hex/encode (ecdh/compute key1 key2)) (hex/encode (ecdh/compute key2 key1))))
  )

(run-tests!)
