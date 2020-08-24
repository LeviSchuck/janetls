(import testament :prefix "" :exit true)
# Testament framework documentation
# https://github.com/pyrmont/testament/blob/master/api.md
(import ../build/janetls :exit true :prefix "")

(def sample "1234567890abcdefghijklmnopqrstuvwxyz")


(deftest "Start at 0 gets the beginning"
  (is (= "123" (:get (byteslice sample 0 3)))))
(deftest "Start at offset gets middle"
  (is (= "abc" (:get (byteslice sample 10 3)))))


(deftest "0 length is empty"
  (is (= "" (:get (byteslice sample 0 0)))))
(deftest "Absurd position is empty"
  (is (= "" (:get (byteslice sample 1000 0)))))

(deftest "Rejects negative position"
  (assert-thrown (byteslice sample -1 10)))
(deftest "Rejects negative length"
  (assert-thrown (byteslice sample 0 -10)))
(deftest "Rejects negative position and length"
  (assert-thrown (byteslice sample -1 -10)))

(run-tests!)
