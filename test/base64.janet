(import testament :prefix "" :exit true)
# Testament framework documentation
# https://github.com/pyrmont/testament/blob/master/api.md

(import ../build/janetls :exit true)

(def examples
  ["H" "He" "Hel" "Hell" "Hello"
   "\x00" "\x00\x01"  "\x00\x01\x02"  "\x00\x01\x02\x03"
   "\xFF" "\xFF\xFE"  "\xFF\xFE\xFD"  "\xFF\xFE\xFD\xFC"
   ])

(deftest "Base64 test vector encodes as expected for standard"
  (let [str "Hello world" expected-str "SGVsbG8gd29ybGQ="]
    (is (= expected-str (janetls/base64/encode str :standard))
  )))
(deftest "Base64 test vector with high byte encodes as expected for standard"
  (let [str "Hello\xFFworld" expected-str "SGVsbG//d29ybGQ="]
    (is (= expected-str (janetls/base64/encode str :standard))
  )))
(deftest "Base64 test vector with high byte encodes as expected for standard unpadded"
  (let [str "Hello\xFFworld" expected-str "SGVsbG//d29ybGQ"]
    (is (= expected-str (janetls/base64/encode str :standard-unpadded))
  )))
(deftest "Base64 test vector with high byte encodes as expected for url"
  (let [str "Hello\xFFworld" expected-str "SGVsbG__d29ybGQ="]
    (is (= expected-str (janetls/base64/encode str :url))
  )))
(deftest "Base64 test vector with high byte encodes as expected for url unpadded"
  (let [str "Hello\xFFworld" expected-str "SGVsbG__d29ybGQ"]
    (is (= expected-str (janetls/base64/encode str :url-unpadded))
  )))
(deftest "Base64 test vector with high byte encodes as expected for imap"
  (let [str "Hello\xFFworld" expected-str "SGVsbG,,d29ybGQ"]
    (is (= expected-str (janetls/base64/encode str :imap))
  )))
(deftest "Encode and decode reflect for standard" (all identity (map
  |(is (= $0 (janetls/base64/decode (janetls/base64/encode $0 :standard) :standard)))
  examples)))
(deftest "Encode and decode reflect for standard unpadded" (all identity (map
  |(is (= $0 (janetls/base64/decode (janetls/base64/encode $0 :standard-unpadded) :standard-unpadded)))
  examples)))
(deftest "Encode and decode reflect for url" (all identity (map
  |(is (= $0 (janetls/base64/decode (janetls/base64/encode $0 :url) :url)))
  examples)))
(deftest "Encode and decode reflect for url unpadded" (all identity (map
  |(is (= $0 (janetls/base64/decode (janetls/base64/encode $0 :url-unpadded) :url-unpadded)))
  examples)))
(deftest "Encode and decode reflect for imap" (all identity (map
  |(is (= $0 (janetls/base64/decode (janetls/base64/encode $0 :imap) :imap)))
  examples)))
(deftest "Decoding fails on invalid input, too short"
  (assert-thrown (janetls/base64/decode "a")))
(deftest "Decoding fails on invalid input, too short on second chunk"
  (assert-thrown (janetls/base64/decode "aaaaa")))
(deftest "Decoding fails on invalid input, illegal character"
  (assert-thrown (janetls/base64/decode "a$oo")))

(run-tests!)
