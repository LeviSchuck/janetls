(declare-project
  :name "janetls"
  :description "Secure primitives for Janet"
  :author "Levi Schuck"
  :license "MIT"
  :url "https://github.com:LeviSchuck/janetls"
  :repo "git+https://github.com:LeviSchuck/janetls")

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