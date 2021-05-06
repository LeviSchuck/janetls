(import testament :prefix "" :exit true)
(import ../janetls :prefix "" :exit true)

(deftest "Generic to works"
  (is (= {:digest :sha1} (oid/to "1.3.14.3.2.26")))
  (is (= {:curve :secp256r1} (oid/to "1.2.840.10045.3.1.7")))
  )

(deftest "Generc from works"
  (is (= {:digest "1.3.14.3.2.26"} (oid/from :sha1)))
  (is (= {:digest "1.2.840.113549.2.5"} (oid/from :md5)))
  (is (= {:curve "1.2.840.10045.3.1.7"} (oid/from :secp256r1)))
  )

(run-tests!)
