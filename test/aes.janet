# https://github.com/ircmaxell/quality-checker/blob/master/tmp/gh_18/PHP-PasswordLib-master/test/Data/Vectors/aes-ecb.test-vectors
(import testament :prefix "" :exit true)
# Testament framework documentation
# https://github.com/pyrmont/testament/blob/master/api.md
(import ../janetls :exit true :prefix "")

(setdyn :pretty-format "%.99N")

(deftest "Simple AES 128 ECB tests"
  (def aes (aes/encrypt (hex/decode "2b7e151628aed2a6abf7158809cf4f3c")))
  (is (= (hex/decode "3ad77bb40d7a3660a89ecaf32466ef97") (:update aes (hex/decode "6bc1bee22e409f96e93d7e117393172a"))))
  (is (= (hex/decode "f5d3d58503b9699de785895a96fdbaaf") (:update aes (hex/decode "ae2d8a571e03ac9c9eb76fac45af8e51"))))
  (is (= (hex/decode "30c81c46a35ce411e5fbc1191a0a52ef") (:update aes (hex/decode "30c81c46a35ce411e5fbc1191a0a52ef"))))
  (is (= (hex/decode "7b0c785e27e8ad3f8223207104725dd4") (:update aes (hex/decode "f69f2445df4f9b17ad2b417be66c3710"))))
  )
