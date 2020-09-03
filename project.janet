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

(declare-native
  :name "janetls"
  :cflags [
    ;default-cflags
    "-Imbedtls/include/"
    "-Iinclude/"
    # "-g"
    # "-O0"
    ;(if is-win [] ["-Wno-unused-parameter"])
    ]
  :lflags [
    ;default-lflags
    # Advapi32 provides windows security primitives, available since server 2003
    ;(if is-win ["Advapi32.lib"] [])
    # "-g"
    # "-O0"
    ]
  :defines {
    "MBEDTLS_CONFIG_FILE" "\"janetls-config.h\""
  }
  :source @[
    "src/janetls.c"
    "src/janetls-md.c"
    "src/janetls-util.c"
    "src/janetls-encode.c"
    "src/janetls-encoding.c"
    "src/janetls-bignum.c"
    "src/janetls-random.c"
    "src/janetls-byteslice.c"
    "src/janetls-asn1.c"
    # mbed tls Message Digest
    "mbedtls/library/md.c"
    "mbedtls/library/md5.c"
    "mbedtls/library/sha1.c"
    "mbedtls/library/sha256.c"
    "mbedtls/library/sha512.c"
    # For randomness, AES is used. It'll be in its own section later.
    "mbedtls/library/aes.c"
    "mbedtls/library/ctr_drbg.c"
    "mbedtls/library/entropy.c"
    "mbedtls/library/entropy_poll.c"
    # mbed tls big numbers
    "mbedtls/library/bignum.c"
    # RSA
    "mbedtls/library/rsa.c"
    "mbedtls/library/oid.c"
    # Everything in mbed tls requires error, platform, platform_util
    "mbedtls/library/error.c"
    "mbedtls/library/platform.c"
    "mbedtls/library/platform_util.c"
    ])
