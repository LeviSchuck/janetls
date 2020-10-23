# https://github.com/ircmaxell/quality-checker/blob/master/tmp/gh_18/PHP-PasswordLib-master/test/Data/Vectors/aes-ecb.test-vectors
(import testament :prefix "" :exit true)
# Testament framework documentation
# https://github.com/pyrmont/testament/blob/master/api.md
(import ../janetls :exit true :prefix "")

(setdyn :pretty-format "%.99N")

(defn ecb [key cipher plain]
  (def encrypt (aes/encrypt :ecb (hex/decode key)))
  (defn ecb-encrypt [plain] (hex/encode (:update encrypt (hex/decode plain))))
  (def decrypt (aes/decrypt :ecb (hex/decode key)))
  (defn ecb-decrypt [plain] (hex/encode (:update decrypt (hex/decode plain))))
  (is (= cipher (ecb-encrypt plain)))
  (is (= plain (ecb-decrypt cipher))))

(deftest "Simple AES 128 ECB tests"
  (def key "2b7e151628aed2a6abf7158809cf4f3c")
  (ecb key "3ad77bb40d7a3660a89ecaf32466ef97" "6bc1bee22e409f96e93d7e117393172a")
  (ecb key "f5d3d58503b9699de785895a96fdbaaf" "ae2d8a571e03ac9c9eb76fac45af8e51")
  (ecb key "43b1cd7f598ece23881b00e3ed030688" "30c81c46a35ce411e5fbc1191a0a52ef")
  (ecb key "7b0c785e27e8ad3f8223207104725dd4" "f69f2445df4f9b17ad2b417be66c3710")
  )

(deftest "Simple AES 192 ECB tests"
  (def key "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")
  (ecb key "bd334f1d6e45f25ff712a214571fa5cc" "6bc1bee22e409f96e93d7e117393172a")
  (ecb key "974104846d0ad3ad7734ecb3ecee4eef" "ae2d8a571e03ac9c9eb76fac45af8e51")
  (ecb key "ef7afd2270e2e60adce0ba2face6444e" "30c81c46a35ce411e5fbc1191a0a52ef")
  (ecb key "9a4b41ba738d6c72fb16691603c18e0e" "f69f2445df4f9b17ad2b417be66c3710")
  )

(deftest "Simple AES 256 ECB tests"
  (def key "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
  (ecb key "f3eed1bdb5d2a03c064b5a7e3db181f8" "6bc1bee22e409f96e93d7e117393172a")
  (ecb key "591ccb10d410ed26dc5ba74a31362870" "ae2d8a571e03ac9c9eb76fac45af8e51")
  (ecb key "b6ed21b99ca6f4f9f153e7b1beafed1d" "30c81c46a35ce411e5fbc1191a0a52ef")
  (ecb key "23304b7a39f9f3ff067d8d8f9e24ecc7" "f69f2445df4f9b17ad2b417be66c3710")
  )

# https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
# Other test cases produced by using python crpytography.hazmat as reference
# with code similar to..
# >>> import cryptography.hazmat
# >>> from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# >>> from cryptography.hazmat.backends import default_backend as backend
# >>> key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
# >>> nonce = bytes.fromhex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')
# >>> cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend())
# >>> encryptor = cipher.encryptor()
# >>> buf = bytearray(32)
# >>> encryptor.update_into(bytes.fromhex('30c81c46a35ce411e5fbc1191a0a52ef'), buf)
# 16
# >>> bytes(buf[:16]).hex()
# 'dc44c3353b3c98a11729d76cf094f30b'



(defn ctr [key nonce cipher plain]
  (def encrypt (aes/encrypt :ctr (hex/decode key) (hex/decode nonce)))
  (defn ctr-encrypt [plain] (hex/encode (:update encrypt (hex/decode plain))))
  (def decrypt (aes/decrypt :ctr (hex/decode key) (hex/decode nonce)))
  (defn ctr-decrypt [plain] (hex/encode (:update decrypt (hex/decode plain))))
  (is (= cipher (ctr-encrypt plain)))
  (is (= plain (ctr-decrypt cipher))))

(deftest "Simple AES 128 CTR tests"
  (def key "2b7e151628aed2a6abf7158809cf4f3c")
  (def nonce "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
  (ctr key nonce
    "874d6191b620e3261bef6864990db6ce
9806f66b7970fdff8617187bb9fffdff
5ae4df3edbd5d35e5b4f09020db03eab
1e031dda2fbe03d1792170a0f3009cee"
    "6bc1bee22e409f96e93d7e117393172a
ae2d8a571e03ac9c9eb76fac45af8e51
30c81c46a35ce411e5fbc1191a0a52ef
f69f2445df4f9b17ad2b417be66c3710")
  (ctr key nonce "874d6191b620e3261bef6864990db6ce" "6bc1bee22e409f96e93d7e117393172a")
  (ctr key nonce "42a155248663d02c6c6579d9af312fb5" "ae2d8a571e03ac9c9eb76fac45af8e51")
  (ctr key nonce "dc44c3353b3c98a11729d76cf094f30b" "30c81c46a35ce411e5fbc1191a0a52ef")
  (ctr key nonce "1a13fb36472fe7a75ff9570e0cf296f4" "f69f2445df4f9b17ad2b417be66c3710")
  )

(run-tests!)
