(import testament :prefix "" :exit true)
# Testament framework documentation
# https://github.com/pyrmont/testament/blob/master/api.md
(import ../build/janetls :prefix "" :exit true)

(deftest "Constant= checks"
  (is (constant= "abcd" "abcd"))
  (is (constant= "abcd" @"abcd"))
  (is (constant= @"abcd" :abcd))
  (is (constant= "abcd" :abcd))
  (is (not (constant= "abcd" "abc")))
  (is (not (constant= "abcd" 5)))
  (is (not (constant= "abcd" {:hi "hello"})))
  )

(run-tests!)
