(import testament :prefix "" :exit true)
(import ../janetls :exit true :prefix "")

(setdyn :pretty-format "%.99N")
# https://tools.ietf.org/html/rfc5869#appendix-A.1

(hex/encode (kdf/hkdf :sha256 (hex/decode "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b") 42 (hex/decode "000102030405060708090a0b0c") (hex/decode "f0f1f2f3f4f5f6f7f8f9")))
"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"

# https://www.ietf.org/rfc/rfc6070.html
(hex/encode (kdf/pbkdf2 :sha1 "password" "salt" 20 2))
"ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"

# https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-56ar.pdf
# Section 5.8.1 (page 46-48)
# OR
# https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf
# Section 5.8.2.1 (page 55)
# PLUS "one-step key-derivation"
# https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr1.pdf
# Section 4.1 (page 11-14)
(hex/encode (kdf/concatkdf :sha1 "hello" "e" "" 41 false))
"cb822fecff9f3b64c740a9c05beb1357cb3b961eee43dbc3fdcb4dbf3ee10f78d46cd9e63ca485a2e1"
(run-tests!)
