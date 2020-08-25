(import testament :prefix "" :exit true)
# Testament framework documentation
# https://github.com/pyrmont/testament/blob/master/api.md
(import ../build/janetls :exit true :prefix "")


(def five (bignum/parse 5))

(def silly-large-number (bignum/parse "10000000000000000000000000000055"))
(deftest "Decode Encode 127" (is (= silly-large-number (asn1/decode-127 (asn1/encode-127 silly-large-number)))))
(deftest "Encode 127 small is small" (is (= "\x05" (asn1/encode-127 5))))
(deftest "Encode 127 small is small" (is (= "\x05" (asn1/encode-127 (bignum/parse 5)))))
(deftest "Decode 127 small is small" (is (= five (asn1/decode-127 "\x05"))))
(deftest "Decode 127 small is small" (is (= 5 (asn1/decode-127 "\x05" :number))))

(deftest "Encode 127 medium is medium" (is (= "\x81\x01" (asn1/encode-127 129))))
(deftest "Decode 127 medium is medium" (is (= (bignum/parse 129) (asn1/decode-127 "\x81\x01"))))
(deftest "Decode 127 medium is medium" (is (= 129 (asn1/decode-127 "\x81\x01" :number))))
(deftest "Decode 127 medium is medium" (is (= (int/u64 129) (asn1/decode-127 "\x81\x01" :u64))))

(deftest "Fails on overflow number" (assert-thrown (asn1/decode-127 "100000000000000000000" :number)))
(deftest "Fails on overflow u64" (assert-thrown (asn1/decode-127 "100000000000000000000" :u64)))

(run-tests!)
