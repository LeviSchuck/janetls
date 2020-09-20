(import testament :prefix "" :exit true)
# Testament framework documentation
# https://github.com/pyrmont/testament/blob/master/api.md
(import ../janetls :prefix "" :exit true)

(deftest "Parses a number" (is (= "10" (:to-string (bignum/parse 10)))))

(deftest "Parses a string" (is (= "10" (:to-string (bignum/parse "10")))))
(deftest "Parses a string base16: 10" (is (= "16" (:to-string (bignum/parse "10" 16)))))
(deftest "Parses a string base16: a" (is (= "10" (:to-string (bignum/parse "a" 16)))))
(deftest "Parses a string base16: A" (is (= "10" (:to-string (bignum/parse "A" 16)))))
(deftest "Parses a string base16: 9" (is (= "9" (:to-string (bignum/parse "9" 16)))))

(deftest "Rejects invalid text"
  (assert-thrown (bignum/parse "10.3")))
(deftest "Rejects fractional number"
  (assert-thrown (bignum/parse 10.3)))

(def zero (bignum/parse 0))
(def one (bignum/parse 1))
(def two (bignum/parse 2))
(def three (bignum/parse 3))
(def five (bignum/parse 5))
(def ten (bignum/parse 10))
(def hundred (bignum/parse 100))
(def million (bignum/parse 1000001))
(def neg-one (bignum/parse -1))
(def neg-ten (bignum/parse -10))

(deftest "Addition 1+1" (is (= two (:+ one one))))
(deftest "Addition 1+-1" (is (= zero (:+ one neg-one))))

(deftest "Subtraction 1-1" (is (= zero (:- one one))))
(deftest "Subtraction 1--1" (is (= two (:- one neg-one))))

(deftest "Multiply 1*1" (is (= one (:* one one))))
(deftest "Multiply 1*-1" (is (= neg-one (:* one neg-one))))

(deftest "Divide 1/1" (is (= one (:/ one one))))
(deftest "Divide 5/2" (is (= two (:/ five two))))
(deftest "Divide 10/1" (is (= ten (:/ ten one))))
(deftest "Divide 10/2" (is (= five (:/ ten two))))

(deftest "Divide Remainder 1/1" (is (= [one zero] (:/% one one))))
(deftest "Divide Remainder 5/2" (is (= [two one] (:/% five two))))
(deftest "Divide Remainder 10/1" (is (= [ten zero] (:/% ten one))))
(deftest "Divide Remainder 10/2" (is (= [five zero] (:/% ten two))))

(deftest "Modulo 10 3" (is (= one (:% ten three))))
(deftest "Modulo 11 3" (is (= two (:% (:+ ten one) three))))
(deftest "Modulo 12 3" (is (= zero (:% (:+ ten two) three))))

# Test cases selected from https://rosettacode.org/wiki/Modular_inverse
(deftest "Inverse modulo 42 ^ -1 (mod 2017) = 1969" (is (= (bignum/parse 1969) (:-% (bignum/parse 42) 2017))))
(deftest "Inverse modulo -48 ^ -1 (mod 2017) = 42" (is (= (bignum/parse 42) (:-% (bignum/parse -48) 2017))))
(deftest "Inverse modulo -486 ^ -1 (mod 217) = 121" (is (= (bignum/parse 121) (:-% (bignum/parse -486) 217))))
# Negative values are flipped
(deftest "Inverse modulo -486 ^ -1 (mod -217) = 121" (is (= (bignum/parse 121) (:-% (bignum/parse -486) -217))))
# inverse modulo seems to only work on primes
(deftest "Inverse modulo 4 ^ -1 (mod 2) = not possible" (is (= nil (bignum/inverse-modulo 4 2))))
(deftest "Inverse modulo 4 ^ -1 (mod 7) = 2" (is (= (bignum/parse 2) (bignum/inverse-modulo 4 7))))
(deftest "Inverse modulo 40 ^ -1 (mod 1) = 0" (is (= (bignum/parse 0) (bignum/inverse-modulo 40 1))))

(deftest "Exponent 1 ^ 10 = 1" (is (= one (bignum/exponent-modulo one ten million))))
(deftest "Exponent 10 ^ 1 = 10" (is (= ten (:^% ten one million))))
(deftest "Exponent 10 ^ 2 = 100" (is (= (bignum/parse 100) (:^% ten two million))))
(deftest "Exponent 5 ^ 2 = 25" (is (= (bignum/parse 25) (:^% five two million))))

(deftest "Bitlength of 1" (is (= 1 (bignum/bit-length 1))))
(deftest "Bitlength of 2" (is (= 2 (bignum/bit-length 2))))
(deftest "Bitlength of 3" (is (= 2 (bignum/bit-length 3))))
(deftest "Bitlength of 4" (is (= 3 (bignum/bit-length 4))))

(deftest "Byte Size of 4" (is (= 1 (bignum/size 4))))
(deftest "Byte Size of 40" (is (= 1 (bignum/size 40))))
(deftest "Byte Size of 400" (is (= 2 (bignum/size 400))))
(deftest "Byte Size of 4000" (is (= 2 (bignum/size 4000))))
(deftest "Byte Size of 40000" (is (= 2 (bignum/size 40000))))
(deftest "Byte Size of 400000" (is (= 3 (bignum/size 400000))))
(deftest "Byte Size of 4000000" (is (= 3 (bignum/size 4000000))))

# GCD test cases from https://users-cs.au.dk/chili/PBI04/ExamplePrograms/gcd_function_test.py

(deftest "GCD 13 13 = 13" (is (= (bignum/parse 13) (bignum/greatest-common-denominator 13 13))))
(deftest "GCD 37 600 = 1" (is (= one (bignum/greatest-common-denominator 37 600))))
(deftest "GCD 20 100 = 20" (is (= (bignum/parse 20) (bignum/greatest-common-denominator 20 100))))
(deftest "GCD 624129 2061517 = 18913" (is (= (bignum/parse 18913) (bignum/greatest-common-denominator 624129 2061517))))

(deftest "Prime test 2" (is (:prime? (bignum/parse 2))))
(deftest "Prime test 3" (is (:prime? (bignum/parse 3))))
(deftest "Prime test 5" (is (:prime? (bignum/parse 5))))
# A few more from https://www.mathsisfun.com/numbers/prime-numbers-to-10k.html
(deftest "Prime test 5807" (is (:prime? (bignum/parse 5807))))
(deftest "Prime test 7841" (is (:prime? (bignum/parse 7841))))
(deftest "Prime test 9679" (is (:prime? (bignum/parse 9679))))
# and some from https://www.utm.edu/staff/caldwell/primes/millions/
(deftest "Prime test 198,491,329 	" (is (:prime? (bignum/parse 198491329))))
(deftest "Prime test 217,645,199" (is (:prime? (bignum/parse 217645199))))
(deftest "Prime test 236,887,699" (is (:prime? (bignum/parse 236887699))))

# 65537 is a common exponent in RSA
(deftest "From Bytes works" (is (= "65537" (string (bignum/parse-bytes "\x01\x00\x01")))))
(deftest "To Bytes works" (is (= "\x01\x00\x01" (:to-bytes (bignum/parse 65537)))))

(deftest "Shift Left 2" (is (= (bignum/parse 400) (:<< hundred 2))))
(deftest "Shift Right 2" (is (= (bignum/parse 25) (:>> hundred 2))))

(deftest "To number works in range" (is (= 100 (:to-number hundred))))
(deftest "To number is nil out of range" (is (= nil (bignum/to-number "100000000000000000000000000"))))
(run-tests!)
