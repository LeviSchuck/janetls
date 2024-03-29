# Copyright (c) 2020 Levi Schuck
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

(declare-project
  :name "janetls"
  :description "Secure primitives for Janet"
  :author "Levi Schuck"
  :license "MIT"
  :url "https://github.com/LeviSchuck/janetls"
  :repo "git+https://github.com:LeviSchuck/janetls"
  :dependencies ["https://github.com/pyrmont/testament"]
  )

(def is-win (= :windows (os/which)))
(def debug-flags [])
# (def debug-flags ["-g" "-Og" "-Wall" "-Wpedantic"])

(declare-native
  :name "_janetls"
  :cflags [
    ;default-cflags
    "-Imbedtls/include/"
    "-Ilibscrypt/"
    "-Iinclude/"
    ;debug-flags
    ;(if is-win [] ["-Wno-unused-parameter"])
    ]
  :lflags [
    ;default-lflags
    # Advapi32 provides windows security primitives, available since server 2003
    ;(if is-win ["Advapi32.lib"] [])
    ;debug-flags
    ]
  :defines {
    "MBEDTLS_CONFIG_FILE" "\"janetls-config.h\""
  }
  :source @[
    "src/janetls.c"
    "src/janetls-md.c"
    "src/janetls-util.c"
    "src/janetls-options.c"
    "src/janetls-encode.c"
    "src/janetls-encoding.c"
    "src/janetls-bignum.c"
    "src/janetls-random.c"
    "src/janetls-byteslice.c"
    "src/janetls-asn1.c"
    "src/janetls-rsa.c"
    "src/janetls-ecp.c"
    "src/janetls-ecdsa.c"
    "src/janetls-cipher.c"
    "src/janetls-aes.c"
    "src/janetls-chacha.c"
    "src/janetls-gcm.c"
    "src/janetls-chachapoly.c"
    "src/janetls-ecdh.c"
    "src/janetls-nistkw.c"
    "src/janetls-kdf.c"
    # mbed tls Message Digest
    "mbedtls/library/md.c"
    "mbedtls/library/md5.c"
    "mbedtls/library/sha1.c"
    "mbedtls/library/sha256.c"
    "mbedtls/library/sha512.c"
    # For Cipher
    "mbedtls/library/aes.c"
    "mbedtls/library/chacha20.c"
    "mbedtls/library/poly1305.c"
    "mbedtls/library/chachapoly.c"
    "mbedtls/library/gcm.c"
    "mbedtls/library/cipher.c"
    "mbedtls/library/cipher_wrap.c"
    # For randomness, AES is used. It'll be in its own section later.
    "mbedtls/library/ctr_drbg.c"
    "mbedtls/library/entropy.c"
    "mbedtls/library/entropy_poll.c"
    # mbed tls big numbers
    "mbedtls/library/bignum.c"
    # RSA
    "mbedtls/library/rsa.c"
    "mbedtls/library/rsa_internal.c"
    "mbedtls/library/oid.c"
    "mbedtls/library/constant_time.c"
    # Elliptic Curve
    "mbedtls/library/ecp.c"
    "mbedtls/library/ecp_curves.c"
    "mbedtls/library/ecdsa.c"
    # Accessories
    "mbedtls/library/hkdf.c"
    "mbedtls/library/nist_kw.c"
    "mbedtls/library/ecdh.c"
    "mbedtls/library/pkcs5.c"
    # ECDSA requires ASN.1
    "mbedtls/library/asn1parse.c"
    "mbedtls/library/asn1write.c"
    # Everything in mbed tls requires error, platform, platform_util
    "mbedtls/library/error.c"
    "mbedtls/library/platform.c"
    "mbedtls/library/platform_util.c"
    # Scrypt
    "libscrypt/crypto_scrypt-nosse.c"
    ])

(declare-source
  :name "janetls"
  :source ["janetls"]
  )
