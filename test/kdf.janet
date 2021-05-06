(import testament :prefix "" :exit true)
(import ../janetls :exit true :prefix "")

(setdyn :pretty-format "%.99N")

# # Reference implementation: python cryptography
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
# from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHMAC
# from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
# from cryptography.hazmat.backends import default_backend

# salt = b"01234567890ABCDEF"
# otherinfo = b"otherinfo"
# password = b"my insecure password"

# kdf = PBKDF2HMAC(
#     algorithm=hashes.SHA256(),
#     length=32,
#     salt=salt,
#     iterations=100000,
#     backend=default_backend(),
# )
# print(bytes.hex(kdf.derive(password)))
# # a452e899dec18f48c8ca16a759357ba4d459812e65078ebbcb3b00288f776fa4

# ckdf = ConcatKDFHash(
#     algorithm=hashes.SHA256(),
#     length=32,
#     otherinfo=otherinfo,
#     backend=default_backend(),
# )
# print(bytes.hex(ckdf.derive(password)))
# # 47912f4a88de7541bc94ad7ab4d414c3d0640287ab75466bcedbeb66a80ef532

# ckdf = ConcatKDFHMAC(
#     algorithm=hashes.SHA256(),
#     length=32,
#     salt=salt,
#     otherinfo=otherinfo,
#     backend=default_backend(),
# )
# print(bytes.hex(ckdf.derive(password)))
# # 1c44744def7499522273d8629287e3ef00789bf3e89b81ab0b702c928277827b

# hkdf = HKDF(
#   algorithm=hashes.SHA256(),
#   length=32,
#   salt=salt,
#   info=otherinfo,
#   backend=default_backend(),
# )
# print(bytes.hex(hkdf.derive(password)))
# # a18935eeefb1276cfa7968be32755e52fea28e562ab1a8cc71a11177e460e6ff

# xkdf = X963KDF(
#   algorithm=hashes.SHA256(),
#   length=32,
#   sharedinfo=otherinfo,
#   backend=default_backend(),
# )
# print(bytes.hex(xkdf.derive(password)))
# # 82d346004fc090f784b3dfe876110fb33f29dd39cf0c90285d1f06e2cf084b7a

(def salt "01234567890ABCDEF")
(def otherinfo "otherinfo")
(def password "my insecure password")


# HKDF test vectors
# https://tools.ietf.org/html/rfc5869#appendix-A.1
(deftest "HKDF HMAC"
  # Test vector
  (def input (hex/decode "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"))
  (def test-otherinfo (hex/decode "f0f1f2f3f4f5f6f7f8f9"))
  (def test-salt (hex/decode "000102030405060708090a0b0c"))
  (def result (hex/encode (kdf/hkdf :sha256 input 42 test-otherinfo test-salt)))
  (is (= "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865" result))
  # Reference
  (def result (hex/encode (kdf/hkdf :sha256 password 32 otherinfo salt)))
  (is (= "a18935eeefb1276cfa7968be32755e52fea28e562ab1a8cc71a11177e460e6ff" result))
  )

# PBKDF2 test vectors
# https://www.ietf.org/rfc/rfc6070.html
(deftest "PBKDF2 HMAC"
  # Test vector
  (def result (hex/encode (kdf/pbkdf2 :sha1 "password" 20 "salt" 2)))
  (is (= "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957" result))
  # Reference
  (def result (hex/encode (kdf/pbkdf2 :sha256 password 32 salt 100000)))
  (is (= "a452e899dec18f48c8ca16a759357ba4d459812e65078ebbcb3b00288f776fa4" result))
  )

# Concat KDF algorithm

(deftest "Concat KDF Hash"
  # Reference
  (def result (hex/encode (kdf/concatkdf :sha256 password 32 otherinfo)))
  (is (= "47912f4a88de7541bc94ad7ab4d414c3d0640287ab75466bcedbeb66a80ef532" result))
  )

(deftest "Concat KDF HMAC"
  # Reference
  (def result (hex/encode (kdf/concatkdf :sha256 password 32 otherinfo salt)))
  (is (= "1c44744def7499522273d8629287e3ef00789bf3e89b81ab0b702c928277827b" result))
  )

(deftest "ANSI X9.63 KDF"
  # Reference
  (def result (hex/encode (kdf/ansi-x963 :sha256 password 32 otherinfo)))
  (is (= "82d346004fc090f784b3dfe876110fb33f29dd39cf0c90285d1f06e2cf084b7a" result))
  )

(deftest "Scrypt"
  # Reference https://tools.ietf.org/html/rfc7914#section-12
  (def result (hex/encode (kdf/scrypt "" "" 64 16 1 1)))
  (is (= "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906" result))
  (def result (hex/encode (kdf/scrypt "password" "NaCl" 64 1024 8 16)))
  (is (= "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640" result))
  (def result (hex/encode (kdf/scrypt "pleaseletmein" "SodiumChloride" 64 16384 8 1)))
  (is (= "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887" result))
  (def result (hex/encode (kdf/scrypt "pleaseletmein" "SodiumChloride" 64  1048576 8 1)))
  (is (= "2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4" result))
  )

(run-tests!)
