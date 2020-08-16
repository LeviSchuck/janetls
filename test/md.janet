(import testament :prefix "" :exit true)
# Testament framework documentation
# https://github.com/pyrmont/testament/blob/master/api.md
(import ../build/janetls :exit true)


(deftest "MD5 \"\" meets expectations"
  (is (= "d41d8cd98f00b204e9800998ecf8427e" (janetls/md/digest :md5 ""))))
(deftest "MD5 \"a\" meets expectations"
  (is (= "0cc175b9c0f1b6a831c399e269772661" (janetls/md/digest :md5 "a"))))
(deftest "MD5 \"abc\" meets expectations"
  (is (= "900150983cd24fb0d6963f7d28e17f72" (janetls/md/digest :md5 "abc"))))
(deftest "MD5 \"abcdefghijklmnopqrstuvwxyz\" meets expectations"
  (is (= "c3fcd3d76192e4007dfb496cca67e13b" (janetls/md/digest :md5 "abcdefghijklmnopqrstuvwxyz"))))
(deftest "SHA-1 \"\" meets expectations"
  (is (= "da39a3ee5e6b4b0d3255bfef95601890afd80709" (janetls/md/digest :sha1 ""))))
(deftest "SHA-1 \"a\" meets expectations"
  (is (= "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8" (janetls/md/digest :sha1 "a"))))
(deftest "SHA-1 \"abc\" meets expectations"
  (is (= "a9993e364706816aba3e25717850c26c9cd0d89d" (janetls/md/digest :sha1 "abc"))))
(deftest "SHA-1 \"abcdefghijklmnopqrstuvwxyz\" meets expectations"
  (is (= "32d10c7b8cf96570ca04ce37f2a19d84240d3a89" (janetls/md/digest :sha1 "abcdefghijklmnopqrstuvwxyz"))))
(deftest "SHA-256 \"\" meets expectations"
  (is (= "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" (janetls/md/digest :sha256 ""))))
(deftest "SHA-256 \"a\" meets expectations"
  (is (= "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb" (janetls/md/digest :sha256 "a"))))
(deftest "SHA-256 \"abc\" meets expectations"
  (is (= "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" (janetls/md/digest :sha256 "abc"))))
(deftest "SHA-256 \"abcdefghijklmnopqrstuvwxyz\" meets expectations"
  (is (= "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73" (janetls/md/digest :sha256 "abcdefghijklmnopqrstuvwxyz"))))
(deftest "SHA-512 \"\" meets expectations"
  (is (= "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" (janetls/md/digest :sha512 ""))))
(deftest "SHA-512 \"a\" meets expectations"
  (is (= "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75" (janetls/md/digest :sha512 "a"))))
(deftest "SHA-512 \"abc\" meets expectations"
  (is (= "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" (janetls/md/digest :sha512 "abc"))))
(deftest "SHA-512 \"abcdefghijklmnopqrstuvwxyz\" meets expectations"
  (is (= "4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1" (janetls/md/digest :sha512 "abcdefghijklmnopqrstuvwxyz"))))

(run-tests!)
