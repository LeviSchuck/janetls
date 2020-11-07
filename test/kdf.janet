(import testament :prefix "" :exit true)
(import ../janetls :exit true :prefix "")

(setdyn :pretty-format "%.99N")
# https://tools.ietf.org/html/rfc5869#appendix-A.1

(hex/encode (kdf/hkdf :sha256 (hex/decode "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b") 42 (hex/decode "000102030405060708090a0b0c") (hex/decode "f0f1f2f3f4f5f6f7f8f9")))
"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"

# https://www.ietf.org/rfc/rfc6070.html
(hex/encode (kdf/pbkdf2 :sha1 "password" "salt" 20 2))
"ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"
(run-tests!)
