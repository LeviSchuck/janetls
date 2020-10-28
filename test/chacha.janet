(import testament :prefix "" :exit true)
(import ../janetls :exit true :prefix "")

(setdyn :pretty-format "%.99N")

# https://www.rfc-editor.org/rfc/rfc7539.html#appendix-A.2

(defn chacha-test [k nonce p c &opt bc] (do
  # To binary, replace some
  (def k (hex/decode k))
  (def pb (hex/decode p))
  (def nonce (hex/decode nonce))
  (def cb (hex/decode c))
  (default bc 0)
  # Chacha context
  (def encrypt (chacha/start :encrypt k nonce bc))
  (def decrypt (chacha/start :decrypt k nonce bc))
  (def eb (buffer))
  (def db (buffer))
  (chacha/update encrypt pb eb)
  (chacha/finish encrypt eb)
  (is (= c (hex/encode eb)))
  (is (= (hex/encode nonce) (hex/encode (chacha/nonce decrypt))))
  (is (= (hex/encode k) (hex/encode (chacha/key decrypt))))
  (:update decrypt cb db)
  (:finish decrypt db)
  (is (= p (hex/encode db)))
  (is (= (hex/encode nonce) (hex/encode (:nonce decrypt))))
  (is (= (hex/encode k) (hex/encode (:key decrypt))))
  ))

(deftest "Chacha20 Tests"
  (chacha-test "0000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000"
    ""
    ""
    )
  (chacha-test "0000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000"
    "76b8e0ada0f13d90405d6ae55386bd28
bdd219b8a08ded1aa836efcc8b770dc7
da41597c5157488d7724e03fb8d84a37
6a43b8f41518a11cc387b669b2ee6586"
    )
  (chacha-test "0000000000000000000000000000000000000000000000000000000000000001"
    "000000000000000000000002"
    "416e79207375626d697373696f6e2074
6f20746865204945544620696e74656e
6465642062792074686520436f6e7472
696275746f7220666f72207075626c69
636174696f6e20617320616c6c206f72
2070617274206f6620616e2049455446
20496e7465726e65742d447261667420
6f722052464320616e6420616e792073
746174656d656e74206d616465207769
7468696e2074686520636f6e74657874
206f6620616e20494554462061637469
7669747920697320636f6e7369646572
656420616e20224945544620436f6e74
7269627574696f6e222e205375636820
73746174656d656e747320696e636c75
6465206f72616c2073746174656d656e
747320696e2049455446207365737369
6f6e732c2061732077656c6c20617320
7772697474656e20616e6420656c6563
74726f6e696320636f6d6d756e696361
74696f6e73206d61646520617420616e
792074696d65206f7220706c6163652c
20776869636820617265206164647265
7373656420746f"
    "a3fbf07df3fa2fde4f376ca23e827370
41605d9f4f4f57bd8cff2c1d4b7955ec
2a97948bd3722915c8f3d337f7d37005
0e9e96d647b7c39f56e031ca5eb6250d
4042e02785ececfa4b4bb5e8ead0440e
20b6e8db09d881a7c6132f420e527950
42bdfa7773d8a9051447b3291ce1411c
680465552aa6c405b7764d5e87bea85a
d00f8449ed8f72d0d662ab052691ca66
424bc86d2df80ea41f43abf937d3259d
c4b2d0dfb48a6c9139ddd7f76966e928
e635553ba76c5c879d7b35d49eb2e62b
0871cdac638939e25e8a1e0ef9d5280f
a8ca328b351c3c765989cbcf3daa8b6c
cc3aaf9f3979c92b3720fc88dc95ed84
a1be059c6499b9fda236e7e818b04b0b
c39c1e876b193bfe5569753f88128cc0
8aaa9b63d1a16f80ef2554d7189c411f
5869ca52c5b83fa36ff216b9c1d30062
bebcfd2dc5bce0911934fda79a86f6e6
98ced759c3ff9b6477338f3da4f9cd85
14ea9982ccafb341b2384dd902f3d1ab
7ac61dd29c6f21ba5b862f3730e37cfd
c4fd806c22f221"
    1
    )
    (chacha-test "1c9240a5eb55d38af333888604f6b5f0
473917c1402b80099dca5cbc207075c0"
    "000000000000000000000002"
    "2754776173206272696c6c69672c2061
6e642074686520736c6974687920746f
7665730a446964206779726520616e64
2067696d626c6520696e207468652077
6162653a0a416c6c206d696d73792077
6572652074686520626f726f676f7665
732c0a416e6420746865206d6f6d6520
7261746873206f757467726162652e"
    "62e6347f95ed87a45ffae7426f27a1df
5fb69110044c0d73118effa95b01e5cf
166d3df2d721caf9b21e5fb14c616871
fd84c54f9d65b283196c7fe4f60553eb
f39c6402c42234e32a356b3e764312a6
1a5532055716ead6962568f87d3f3f77
04c6a8d1bcd1bf4d50d6154b6da731b1
87b58dfd728afa36757a797ac188d1"
    42
    )
  )


(run-tests!)