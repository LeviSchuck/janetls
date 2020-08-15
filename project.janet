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
  :url "https://github.com:LeviSchuck/janetls"
  :repo "git+https://github.com:LeviSchuck/janetls"
  :dependencies ["https://github.com/joy-framework/tester"]
  )

(def is-win (= :windows (os/which)))

(declare-native
  :name "janetls"
  :cflags [
    ;default-cflags
    "-Imbedtls/include/"
    "-Iinclude/"
    ;(if is-win [] ["-Wno-unused-parameter"])
    ]
  :defines {
    "MBEDTLS_CONFIG_FILE" "\"janetls-config.h\""
  }
  :source @[
    "src/janetls.c"
    "src/janetls-md.c"
    "src/janetls-util.c"
    "src/janetls-utils.c"
    # mbed tls Message Digest
    "mbedtls/library/md.c"
    "mbedtls/library/md5.c"
    "mbedtls/library/sha1.c"
    "mbedtls/library/sha256.c"
    "mbedtls/library/sha512.c"
    # Everything in mbed tls requires error, platform, platform_util
    "mbedtls/library/error.c"
    "mbedtls/library/platform.c"
    "mbedtls/library/platform_util.c"
    ])