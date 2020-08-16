(import tester :prefix "" :exit true)
(import ../build/janetls :exit true)

(deftest
  (test "Raw hex comes out as hex"
    (= "0001ff" (janetls/hex/encode "\x00\x01\xFF")))
  (test "Hello encoded as hex"
    (= "48656c6c6f" (janetls/hex/encode "Hello")))
  (test "Hello decoded as hex"
    (= "Hello" (janetls/hex/decode "48656c6c6f")))
  (test "Hello decoded as hex, uppercase"
    (= "Hello" (janetls/hex/decode "48656C6C6F")))
  (test "Hex comes out as raw hex"
    (= "\x00\x01\xFF" (janetls/hex/decode "0001ff")))
  (test "Decoding fails on invalid input, not even - 1 character"
    (string/has-prefix? "Could not decode hex string" (catch (janetls/hex/decode "0"))))
  (test "Decoding fails on invalid input, not even - 3 characters"
    (string/has-prefix? "Could not decode hex string" (catch (janetls/hex/decode "000"))))
  (test "Decoding fails on invalid input, non hex character"
    (string/has-prefix? "Could not decode hex string" (catch (janetls/hex/decode "0z"))))
  )