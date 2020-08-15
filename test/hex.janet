(import tester :prefix "" :exit true)
(import ../build/janetls :exit true)

(deftest
  (test "Raw hex comes out as hex"
    (= "0001ff" (janetls/hex/encode "\x00\x01\xFF")))
  (test "Hello encoded as hex"
    (= "48656c6c6f" (janetls/hex/encode "Hello")))
  )