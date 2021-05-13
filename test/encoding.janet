(import testament :prefix "" :exit true)
# Testament framework documentation
# https://github.com/pyrmont/testament/blob/master/api.md
(import ../janetls :exit true)

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
(deftest "Base64 does accept a variant, but not this one"
  (assert-thrown (janetls/encoding/encode "Hello\xF1Carl" :base64 :pinata)))
(deftest "Hello Carl encoded as base64 url"
  (is (= "SGVsbG_xQ2FybA==" (janetls/encoding/encode "Hello\xF1Carl" :base64 :url))))
(deftest "Hello decoded from base64 url"
  (is (= "Hello\xF1Carl" (janetls/encoding/decode "SGVsbG_xQ2FybA==" :base64 :url))))
(deftest "Hello Carl encoded as base64 url"
  (is (= "SGVsbG_xQ2FybA" (janetls/encoding/encode "Hello\xF1Carl" :base64 :url-unpadded))))
(deftest "Hello decoded from base64 url"
  (is (= "Hello\xF1Carl" (janetls/encoding/decode "SGVsbG_xQ2FybA" :base64 :url-unpadded))))

# Base32
(deftest "Hello Carla encoded as base32"
  (is (= "JBSWY3DPEBBWC4TMME======" (janetls/encoding/encode "Hello Carla" :base32))))
(deftest "Hello Carlaa encoded as base32"
  (is (= "JBSWY3DPEBBWC4TMMFQQ====" (janetls/encoding/encode "Hello Carlaa" :base32))))
(deftest "Hello Carlaaa encoded as base32"
  (is (= "JBSWY3DPEBBWC4TMMFQWC===" (janetls/encoding/encode "Hello Carlaaa" :base32))))
(deftest "Hello Carlaaaa encoded as base32"
  (is (= "JBSWY3DPEBBWC4TMMFQWCYI=" (janetls/encoding/encode "Hello Carlaaaa" :base32))))
(deftest "Hello Carlaaaaa encoded as base32"
  (is (= "JBSWY3DPEBBWC4TMMFQWCYLB" (janetls/encoding/encode "Hello Carlaaaaa" :base32))))

(deftest "Hello Carla decoded as base32"
  (is (= "Hello Carla" (janetls/encoding/decode "JBSWY3DPEBBWC4TMME======" :base32))))
(deftest "Hello Carlaa decoded as base32"
  (is (= "Hello Carlaa" (janetls/encoding/decode "JBSWY3DPEBBWC4TMMFQQ====" :base32))))
(deftest "Hello Carlaaa decoded as base32"
  (is (= "Hello Carlaaa" (janetls/encoding/decode "JBSWY3DPEBBWC4TMMFQWC===" :base32))))
(deftest "Hello Carlaaaa decoded as base32"
  (is (= "Hello Carlaaaa" (janetls/encoding/decode "JBSWY3DPEBBWC4TMMFQWCYI=" :base32))))
(deftest "Hello Carlaaaaa decoded as base32"
  (is (= "Hello Carlaaaaa" (janetls/encoding/decode "JBSWY3DPEBBWC4TMMFQWCYLB" :base32))))

(deftest "Hello decoded from base32"
  (is (= "Hello Carla" (janetls/encoding/decode "JBSWY3DPEBBWC4TMME======" :base32))))
(deftest "Base32 does accept a variant, but not this one"
  (assert-thrown (janetls/encoding/encode "Hello Carla" :base32 :pinata)))
(deftest "Hello Carla encoded as base32 z-base"
  (is (= "jb1sa5dxrbbsnhuccr" (janetls/encoding/encode "Hello Carla" :base32 :z-base))))
(deftest "Hello Carla decoded from base32 z-base"
  (is (= "Hello Carla" (janetls/encoding/decode "jb1sa5dxrbbsnhuccr" :base32 :z-base))))
(deftest "Hello Carla encoded as base32 standard unpadded"
  (is (= "JBSWY3DPEBBWC4TMME" (janetls/encoding/encode "Hello Carla" :base32 :standard-unpadded))))
(deftest "Hello decoded from base32 standard unpadded"
  (is (= "Hello Carla" (janetls/encoding/decode "JBSWY3DPEBBWC4TMME" :base32 :standard-unpadded))))

(deftest "Hello Carla decoded as base32 hex"
  (is (= "Hello Carla" (janetls/encoding/decode "91IMOR3F411M2SJCC4======" :base32 :hex))))
(deftest "Hello Carla decoded as base32 hex"
  (is (= "Hello Carla" (janetls/encoding/decode "91IMOR3F411M2SJCC4" :base32 :hex))))
(deftest "Hello Carla encoded as base32 hex"
  (is (= "91IMOR3F411M2SJCC4======" (janetls/encoding/encode "Hello Carla" :base32 :hex))))
(deftest "Hello Carla encoded as base32 hex unpadded"
  (is (= "91IMOR3F411M2SJCC4" (janetls/encoding/encode "Hello Carla" :base32 :hex-unpadded))))

(defn contains? [x s] (not (empty? (filter |(= x $0) s))))

(deftest "Types contains hex" (is (contains? :hex (janetls/encoding/types))))
(deftest "Types contains base64" (is (contains? :base64 (janetls/encoding/types))))
(deftest "Types contains base32" (is (contains? :base32 (janetls/encoding/types))))
(deftest "Types contains raw" (is (contains? :raw (janetls/encoding/types))))
(deftest "Types does not contain bacon" (is (not (contains? :bacon (janetls/encoding/types)))))

(run-tests!)
