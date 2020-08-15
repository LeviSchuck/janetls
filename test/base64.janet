(import tester :prefix "" :exit true)
(import ../build/janetls :exit true)

(def examples
  ["H" "He" "Hel" "Hell" "Hello"
   "\x00" "\x00\x01"  "\x00\x01\x02"  "\x00\x01\x02\x03"
   "\xFF" "\xFF\xFE"  "\xFF\xFE\xFD"  "\xFF\xFE\xFD\xFC"
   ])

(deftest
  (test "Base64 test vector encodes as expected for standard"
    (let [str "Hello world" expected-str "SGVsbG8gd29ybGQ="]
      (= expected-str (janetls/base64/encode str :standard)
    )))
  (test "Base64 test vector with high byte encodes as expected for standard"
    (let [str "Hello\xFFworld" expected-str "SGVsbG//d29ybGQ="]
      (= expected-str (janetls/base64/encode str :standard)
    )))
  (test "Base64 test vector with high byte encodes as expected for standard unpadded"
    (let [str "Hello\xFFworld" expected-str "SGVsbG//d29ybGQ"]
      (= expected-str (janetls/base64/encode str :standard-unpadded)
    )))
  (test "Base64 test vector with high byte encodes as expected for url"
    (let [str "Hello\xFFworld" expected-str "SGVsbG__d29ybGQ="]
      (= expected-str (janetls/base64/encode str :url)
    )))
  (test "Base64 test vector with high byte encodes as expected for url unpadded"
    (let [str "Hello\xFFworld" expected-str "SGVsbG__d29ybGQ"]
      (= expected-str (janetls/base64/encode str :url-unpadded)
    )))
  (test "Base64 test vector with high byte encodes as expected for imap"
    (let [str "Hello\xFFworld" expected-str "SGVsbG,,d29ybGQ"]
      (= expected-str (janetls/base64/encode str :imap)
    )))
  (test "Encode and decode reflect for standard" (all identity (map
    |(= $0 (janetls/base64/decode (janetls/base64/encode $0 :standard) :standard))
    examples)))
  (test "Encode and decode reflect for standard unpadded" (all identity (map
    |(= $0 (janetls/base64/decode (janetls/base64/encode $0 :standard-unpadded) :standard-unpadded))
    examples)))
  (test "Encode and decode reflect for url" (all identity (map
    |(= $0 (janetls/base64/decode (janetls/base64/encode $0 :url) :url))
    examples)))
  (test "Encode and decode reflect for url unpadded" (all identity (map
    |(= $0 (janetls/base64/decode (janetls/base64/encode $0 :url-unpadded) :url-unpadded))
    examples)))
  (test "Encode and decode reflect for imap" (all identity (map
    |(= $0 (janetls/base64/decode (janetls/base64/encode $0 :imap) :imap))
    examples)))
)