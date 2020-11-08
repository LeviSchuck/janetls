
# https://tools.ietf.org/html/rfc3394
# https://tools.ietf.org/html/rfc5649
(import testament :prefix "" :exit true)
(import ../janetls :exit true :prefix "")

(setdyn :pretty-format "%.99N")

(def cek (hex/decode "00000000000000000000000000000000"))
(def kek (hex/decode "11111111111111111111111111111111"))
(deftest "wrap-unwrap works"
  (def wrapped (nistkw/wrap kek cek))
  (def unwrapped (nistkw/unwrap kek wrapped))
  (is (not= wrapped cek))
  (is (not= wrapped kek))
  (is (= cek unwrapped))
  (is (not= kek unwrapped))
  )

# https://tools.ietf.org/html/rfc3394#section-4.1
(deftest "RFC Test vectors"
  (def kek (hex/decode "000102030405060708090A0B0C0D0E0F"))
  (def cek (hex/decode "00112233445566778899AABBCCDDEEFF"))
  (def expected (hex/decode "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"))
  (is (= expected (nistkw/wrap kek cek false)))
  (is (= cek (nistkw/unwrap kek expected false)))

  (def kek (hex/decode "000102030405060708090A0B0C0D0E0F1011121314151617"))
  (def expected (hex/decode "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D"))
  (is (= expected (nistkw/wrap kek cek false)))
  (is (= cek (nistkw/unwrap kek expected false)))

  (def kek (hex/decode "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"))
  (def expected (hex/decode "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"))
  (is (= expected (nistkw/wrap kek cek false)))
  (is (= cek (nistkw/unwrap kek expected false)))

  (def kek (hex/decode "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"))
  (def cek (hex/decode "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F"))
  (def expected (hex/decode "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"))
  (is (= expected (nistkw/wrap kek cek false)))
  (is (= cek (nistkw/unwrap kek expected false)))
  )

(run-tests!)
