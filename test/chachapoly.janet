(import testament :prefix "" :exit true)
(import ../janetls :exit true :prefix "")

(setdyn :pretty-format "%.99N")

# https://www.rfc-editor.org/rfc/rfc7539.html#appendix-A.2

(defn chachapoly-test [k nonce ad p c t] (do
  # To binary, replace some
  (def k (hex/decode k))
  (def pb (hex/decode p))
  (def adb (hex/decode ad))
  (def nonce (hex/decode nonce))
  (def cb (hex/decode c))
  (def tb (hex/decode t))
  (defn encdec [thing] (hex/encode (hex/decode thing)))
  # Chacha context
  (def encrypt (chachapoly/start :encrypt k nonce adb))
  (def decrypt (chachapoly/start :decrypt k nonce adb))
  (def eb (buffer))
  (def db (buffer))
  (chachapoly/update encrypt pb eb)
  (chachapoly/finish encrypt eb)
  (is (= (encdec c) (hex/encode eb)))
  (is (= (hex/encode nonce) (hex/encode (chachapoly/nonce encrypt))))
  (is (= (encdec ad) (hex/encode (chachapoly/ad encrypt))))
  (is (= (hex/encode k) (hex/encode (chachapoly/key encrypt))))
  (is (= (encdec t) (hex/encode (chachapoly/tag encrypt))))
  (:update decrypt cb db)
  (:finish decrypt db)
  (is (= (encdec p) (hex/encode db)))
  (is (= (hex/encode nonce) (hex/encode (:nonce decrypt))))
  (is (= (encdec ad) (hex/encode (:ad decrypt))))
  (is (= (hex/encode k) (hex/encode (:key decrypt))))
  (is (= (:tag decrypt (:tag encrypt))))
  (is (= (:tag decrypt tb)))
  ))
# In python, using Cryptography, a python library as reference
# >>> import cryptography.hazmat
# >>> from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
# >>> key = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
# >>> nonce = bytes.fromhex('000000000000000000000000')
# >>> chacha = ChaCha20Poly1305(key)
# >>> ct = chacha.encrypt(nonce, b"", b"")
# >>> bytes.hex(ct)
# '4eb972c9a8fb3a1b382bb4d36f5ffad1'

(deftest "Chacha20 Tests"
  (chachapoly-test "0000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000"
    ""
    ""
    ""
    "4eb972c9a8fb3a1b382bb4d36f5ffad1"
    )
  # From the RFC
  (chachapoly-test
    "1c9240a5eb55d38af333888604f6b5f0
    473917c1402b80099dca5cbc207075c0"
    "000000000102030405060708"
    "f33388860000000000004e91"
    "496e7465726e65742d44726166747320
    61726520647261667420646f63756d65
    6e74732076616c696420666f72206120
    6d6178696d756d206f6620736978206d
    6f6e74687320616e64206d6179206265
    20757064617465642c207265706c6163
    65642c206f72206f62736f6c65746564
    206279206f7468657220646f63756d65
    6e747320617420616e792074696d652e
    20497420697320696e617070726f7072
    6961746520746f2075736520496e7465
    726e65742d4472616674732061732072
    65666572656e6365206d617465726961
    6c206f7220746f206369746520746865
    6d206f74686572207468616e20617320
    2fe2809c776f726b20696e2070726f67
    726573732e2fe2809d"
    "64a0861575861af460f062c79be643bd
    5e805cfd345cf389f108670ac76c8cb2
    4c6cfc18755d43eea09ee94e382d26b0
    bdb7b73c321b0100d4f03b7f355894cf
    332f830e710b97ce98c8a84abd0b9481
    14ad176e008d33bd60f982b1ff37c855
    9797a06ef4f0ef61c186324e2b350638
    3606907b6a7c02b0f9f6157b53c867e4
    b9166c767b804d46a59b5216cde7a4e9
    9040c5a40433225ee282a1b0a06c523e
    af4534d7f83fa1155b0047718cbc546a
    0d072b04b3564eea1b422273f548271a
    0bb2316053fa76991955ebd63159434e
    cebb4e466dae5a1073a6727627097a10
    49e617d91d361094fa68f0ff77987130
    305beaba2eda04df997b714d6c6f2c29
    a6ad5cb4022b02709b"
    "eead9d67890cbb22392336fea1851f38"
    )
  )


(run-tests!)
