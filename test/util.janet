(import testament :prefix "" :exit true)
# Testament framework documentation
# https://github.com/pyrmont/testament/blob/master/api.md
(import ../janetls :prefix "" :exit true)

(deftest "Constant= checks"
  (is (constant= "abcd" "abcd"))
  (is (constant= "abcd" @"abcd"))
  (is (constant= @"abcd" :abcd))
  (is (constant= "abcd" :abcd))
  (is (not (constant= "abcd" "abc")))
  (is (not (constant= "abcd" 5)))
  (is (not (constant= "abcd" {:hi "hello"})))
  )

(deftest "CRC32" (do
  (is (= 0x414fa339 (crc32 "The quick brown fox jumps over the lazy dog")))
  (is (= 0x8e72caf4 (crc32 "The sky is orange in California")))
  ))

(run-tests!)
