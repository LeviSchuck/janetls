# https://github.com/ircmaxell/quality-checker/blob/master/tmp/gh_18/PHP-PasswordLib-master/test/Data/Vectors/aes-ecb.test-vectors
(import testament :prefix "" :exit true)
# Testament framework documentation
# https://github.com/pyrmont/testament/blob/master/api.md
(import ../janetls :exit true :prefix "")

(setdyn :pretty-format "%.99N")

(defn ecb [key cipher plain]
  (def encrypt (aes/encrypt (hex/decode key)))
  (defn ecb-encrypt [plain] (hex/encode (:update encrypt (hex/decode plain))))
  (def decrypt (aes/decrypt (hex/decode key)))
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

(run-tests!)
