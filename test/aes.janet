# https://github.com/ircmaxell/quality-checker/blob/master/tmp/gh_18/PHP-PasswordLib-master/test/Data/Vectors/aes-ecb.test-vectors
(import testament :prefix "" :exit true)
# Testament framework documentation
# https://github.com/pyrmont/testament/blob/master/api.md
(import ../janetls :exit true :prefix "")

(setdyn :pretty-format "%.99N")

(deftest "Simple AES 128 ECB tests"
  (def aes (aes/encrypt (hex/decode "2b7e151628aed2a6abf7158809cf4f3c")))
  (defn ecb [plain] (hex/encode (:update aes (hex/decode plain))))

  (is (= "3ad77bb40d7a3660a89ecaf32466ef97" (ecb "6bc1bee22e409f96e93d7e117393172a")))
  (is (= "f5d3d58503b9699de785895a96fdbaaf" (ecb "ae2d8a571e03ac9c9eb76fac45af8e51")))
  (is (= "43b1cd7f598ece23881b00e3ed030688" (ecb "30c81c46a35ce411e5fbc1191a0a52ef")))
  (is (= "7b0c785e27e8ad3f8223207104725dd4" (ecb "f69f2445df4f9b17ad2b417be66c3710")))
  )

(deftest "Simple AES 192 ECB tests"
  (def aes (aes/encrypt (hex/decode "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")))
  (defn ecb [plain] (hex/encode (:update aes (hex/decode plain))))

  (is (= "bd334f1d6e45f25ff712a214571fa5cc" (ecb "6bc1bee22e409f96e93d7e117393172a")))
  (is (= "974104846d0ad3ad7734ecb3ecee4eef" (ecb "ae2d8a571e03ac9c9eb76fac45af8e51")))
  (is (= "ef7afd2270e2e60adce0ba2face6444e" (ecb "30c81c46a35ce411e5fbc1191a0a52ef")))
  (is (= "9a4b41ba738d6c72fb16691603c18e0e" (ecb "f69f2445df4f9b17ad2b417be66c3710")))
  )

(deftest "Simple AES 256 ECB tests"
  (def aes (aes/encrypt (hex/decode "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")))
  (defn ecb [plain] (hex/encode (:update aes (hex/decode plain))))

  (is (= "f3eed1bdb5d2a03c064b5a7e3db181f8" (ecb "6bc1bee22e409f96e93d7e117393172a")))
  (is (= "591ccb10d410ed26dc5ba74a31362870" (ecb "ae2d8a571e03ac9c9eb76fac45af8e51")))
  (is (= "b6ed21b99ca6f4f9f153e7b1beafed1d" (ecb "30c81c46a35ce411e5fbc1191a0a52ef")))
  (is (= "23304b7a39f9f3ff067d8d8f9e24ecc7" (ecb "f69f2445df4f9b17ad2b417be66c3710")))
  )

(run-tests!)
