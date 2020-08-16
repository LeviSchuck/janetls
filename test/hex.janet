(import testament :prefix "" :exit true)
# Testament framework documentation
# https://github.com/pyrmont/testament/blob/master/api.md
(import ../build/janetls :exit true)

(deftest "Raw hex comes out as hex"
  (is (= "0001ff" (janetls/hex/encode "\x00\x01\xFF"))))
(deftest "Hello encoded as hex"
  (is (= "48656c6c6f" (janetls/hex/encode "Hello"))))
(deftest "Hello decoded as hex"
  (is (= "Hello" (janetls/hex/decode "48656c6c6f"))))
(deftest "Hello decoded as hex, uppercase"
  (is (= "Hello" (janetls/hex/decode "48656C6C6F"))))
(deftest "Hex comes out as raw hex"
  (is (= "\x00\x01\xFF" (janetls/hex/decode "0001ff"))))
(deftest "Decoding fails on invalid input, not even - 1 character"
  (assert-thrown (janetls/hex/decode "0")))
(deftest "Decoding fails on invalid input, not even - 3 characters"
  (assert-thrown (janetls/hex/decode "000")))
(deftest "Decoding fails on invalid input, non hex character"
  (assert-thrown (janetls/hex/decode "0z")))

(run-tests!)
