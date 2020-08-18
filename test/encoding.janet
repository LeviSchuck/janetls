(import testament :prefix "" :exit true)
# Testament framework documentation
# https://github.com/pyrmont/testament/blob/master/api.md
(import ../build/janetls :exit true)

# Raw
(deftest "Hello encoded as raw"
  (is (= "Hello\xF1" (janetls/encoding/encode "Hello\xF1" :raw))))
(deftest "Hello decoded from raw"
  (is (= "Hello\xF1" (janetls/encoding/decode "Hello\xF1" :raw))))
(deftest "Raw does not accept a variant"
  (assert-thrown (janetls/encoding/encode "Hello" :raw :standard)))

# Hex
(deftest "Hello encoded as hex"
  (is (= "48656c6c6ff1" (janetls/encoding/encode "Hello\xF1" :hex))))
(deftest "Hello decoded from hex"
  (is (= "Hello\xF1" (janetls/encoding/decode "48656c6c6ff1" :hex))))
(deftest "Hex does not accept a variant"
  (assert-thrown (janetls/encoding/encode "Hello" :hex :standard)))

# Base64
(deftest "Hello Carl encoded as base64"
  (is (= "SGVsbG/xQ2FybA==" (janetls/encoding/encode "Hello\xF1Carl" :base64))))
(deftest "Hello decoded from base64"
  (is (= "Hello\xF1Carl" (janetls/encoding/decode "SGVsbG/xQ2FybA==" :base64))))
(deftest "Hex does accept a variant, but not this one"
  (assert-thrown (janetls/encoding/encode "Hello\xF1Carl" :base64 :pinata)))
(deftest "Hello Carl encoded as base64 url"
  (is (= "SGVsbG_xQ2FybA==" (janetls/encoding/encode "Hello\xF1Carl" :base64 :url))))
(deftest "Hello decoded from base64 url"
  (is (= "Hello\xF1Carl" (janetls/encoding/decode "SGVsbG_xQ2FybA==" :base64 :url))))
(deftest "Hello Carl encoded as base64 url"
  (is (= "SGVsbG_xQ2FybA" (janetls/encoding/encode "Hello\xF1Carl" :base64 :url-unpadded))))
(deftest "Hello decoded from base64 url"
  (is (= "Hello\xF1Carl" (janetls/encoding/decode "SGVsbG_xQ2FybA" :base64 :url-unpadded))))

(defn contains? [x s] (not (empty? (filter |(= x $0) s))))

(deftest "Types contains hex" (is (contains? :hex (janetls/encoding/types))))
(deftest "Types contains base64" (is (contains? :base64 (janetls/encoding/types))))
(deftest "Types contains raw" (is (contains? :raw (janetls/encoding/types))))
(deftest "Types does not contain bacon" (is (not (contains? :bacon (janetls/encoding/types)))))

(run-tests!)
