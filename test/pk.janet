(import testament :prefix "" :exit true)
(import ../janetls :exit true :prefix "")

(setdyn :pretty-format "%.99N")

(def ecdsa-key (ecdsa/generate))
(def rsa-key (rsa/generate))
(def pk-rsa (pk/import (rsa/export-private rsa-key)))
(def pk-ecdsa (pk/import (ecdsa/export-private ecdsa-key)))
(def public-rsa (pk/import (rsa/export-public rsa-key)))
(def public-ecdsa (pk/import (ecdsa/export-public ecdsa-key)))

(def data (util/random 16))

(deftest "RSA can sign and verify"
  (def sig (:sign pk-rsa data {:encoding :hex}))
  (is (:verify pk-rsa data sig {:encoding :hex}))
  (is (:verify public-rsa data sig {:encoding :hex}))
  # Check that decoding is actually working too.
  (is (:verify public-rsa data (encoding/decode sig :hex)))
  # And raw works
  (def sig (:sign pk-rsa data))
  (is (:verify public-rsa data sig))
  )
(deftest "ECDSA can sign and verify"
  (def sig (:sign pk-ecdsa data {:encoding :hex}))
  (is (:verify pk-ecdsa data sig {:encoding :hex}))
  (is (:verify public-ecdsa data sig {:encoding :hex}))
  )

(deftest "RSA can be wrapped and behaves as if imported"
  (def wrapped (pk/wrap rsa-key))
  (def sig (:sign wrapped data {:encoding :hex}))
  (is (:verify pk-rsa data sig {:encoding :hex}))
  (is (:verify public-rsa data sig {:encoding :hex}))
  )

(deftest "ECDSA can be wrapped and behaves as if imported"
  (def wrapped (pk/wrap ecdsa-key))
  (def sig (:sign wrapped data {:encoding :hex}))
  (is (:verify pk-ecdsa data sig {:encoding :hex}))
  (is (:verify public-ecdsa data sig {:encoding :hex}))
  )

(deftest "RSA can encrypt and decrypt"
  (def ciphertext (:encrypt pk-rsa data {:encoding :hex}))
  (is (= data (:decrypt pk-rsa ciphertext {:encoding :hex})))
  # Encrypting is a public key operation, so the public key cannot decrypt
  (assert-thrown (:decrypt public-rsa data {:encoding :hex}))
  # check that encrypting also works.
  (def ciphertext (:encrypt public-rsa data {:encoding :hex}))
  (is (= data (:decrypt pk-rsa ciphertext {:encoding :hex})))
  )

(deftest "ECDSA cannot encrypt and decrypt"
  (assert-thrown (:encrypt pk-ecdsa data {:encoding :hex}))
  (assert-thrown (:encrypt public-ecdsa data {:encoding :hex}))
  (assert-thrown (:decrypt pk-ecdsa data {:encoding :hex}))
  (assert-thrown (:decrypt public-ecdsa data {:encoding :hex}))
  )

(def rsa-priv-key (base64/decode
"MIIEpQIBAAKCAQEA36UgG/QCHl7mwripADrCOwX4UIZaLYGm6dqsGZkvQh3zsSjp
XN+EcdcW3+MAQ7lBQs+Xz6HHYI1teQGCEaKO5zkVDjFr2gpwBpUJbA0ySZ9ZAuyY
2+jfO06bICygpK60lL4QVMW1/nubpd5pZ3prvKDlPD58HmtUWFfCN2M524dDJioQ
uJedlwUdoq0qLm0FzD+JRpMZww4zx33NMWVIfOGQHt7CT9aZkET+/995J+XIMqtC
On9ZN9N/rCQdtHjbJN3iFijcbM1FNCT7DVe8Jre3lP/Qrj5K+Q6gGoLvqpoZ3jNE
2eoo3pDF2TqsQv/eKySsI/loE7fjU30a3JLQ8QIDAQABAoIBAQDPRndP8QLVqxcs
eYEImWzSz2GpIBwL+RH9w5Gl1/eYy7HEDCrczLwv1i15KyZfnh8CEOyen03uCqXf
dKpcNdFEM/9zvBI9b1cMgqzM3B4zZeBVeXrith3PFbdoRnRMrS7ofI8eQm++gElt
nYkLQsb/eA99mlvmxYrSpeN2+hvxfNsgUFKSYh93YMeHPEbPXA6rqv9ZiJvpz/Mj
YbyYbbm9TP80JlFKUfqjSdzHY2EGEtc4JtfUtOJdhHKAQIjgms4vlokFvEIX6Kfh
BTSsYJXBFlgmyWf1u0iinCguSWdSXOgIni3qdt4PXc8i2emFBz+bFdgTWslFrhIz
kOjrjhuRAoGBAP9y8GCUAM/OWdcJnJI4SXh8GrLom0cP3Ew3dRAuD4C9Ay4G1bhp
jYq8UKsosPcgnAfk9EGeNyDOniPWtcScR4i/xp6+cOBoIMvD3wjofpfG7iIcjpps
zM5W6x0yn3AJ8NRArVXwEpGpo4FKn2reBpSi5+DqecOXoOck3WQVEBkHAoGBAOAg
n8FtuCjU4/5BybX4uRjr5RCcnYWCrRIMqsjfWUcawm3j4oKn8eCYjxcpIaBIpmbB
Eg54YweYRCTNx/+AmaYa9b7MTvA3aC41MhRCZXLLQvHaA5oHgMSLddrDZlDLg+LR
EWDKoiEeYyIyN1UFwJsAKhndluv7DkUFl+xWbSBHAoGBAPxBttrIjRypO9K8rR8/
8l3GwF7YkS5VnUiuoy19LtYE0TUMjtTzd1D/sfGz1z3TuAGbuRFreiktoMDncMxd
P87tAukUS0dvzKMsI/4aCZk8W0DYToJ02rMQ5lEJAqWTS31u+T0aPFwX110AIflY
k8sILE/RfLkH7V8U6oPAwQrVAoGAQAQxfU84fbkpEfN6iNZtEBg4ykDhoUPM6U3i
7hMVbgDPrhGcHhOYO713iXb/GsgFd24IGUf7iSzNsfFxAaKawF4M+R1kIqrAwAoD
rtO0JFC4Y1oRE0q3Vew7kmujaspmdj+fBhV6r5j9WcQcF9XXyK4IWHD5bZe84KwT
U7bv3nsCgYEA/wHuPbTXRc3mJsZTz6ucS2o3EVy/HNjmRyLHiHckjSjUryq2t+q8
aJ6z5e5GWZWpITbSCneF1zXtlCsvNSWYi1P9itt+E4NfB8Bpik/M8WUhL/PrLCzu
Sh2O+DHWNyyNS8a5wvJDOEUj1ktKVjSwwG5fy0EQhH6rOQcZHNKj70o="))

(def rsa-private-pkcs1-pem
"
-----BEGIN RSA PRIVATE KEY-----\n
MIIEpQIBAAKCAQEA36UgG/QCHl7mwripADrCOwX4UIZaLYGm6dqsGZkvQh3zsSjp\n
XN+EcdcW3+MAQ7lBQs+Xz6HHYI1teQGCEaKO5zkVDjFr2gpwBpUJbA0ySZ9ZAuyY\n
2+jfO06bICygpK60lL4QVMW1/nubpd5pZ3prvKDlPD58HmtUWFfCN2M524dDJioQ\n
uJedlwUdoq0qLm0FzD+JRpMZww4zx33NMWVIfOGQHt7CT9aZkET+/995J+XIMqtC\n
On9ZN9N/rCQdtHjbJN3iFijcbM1FNCT7DVe8Jre3lP/Qrj5K+Q6gGoLvqpoZ3jNE\n
2eoo3pDF2TqsQv/eKySsI/loE7fjU30a3JLQ8QIDAQABAoIBAQDPRndP8QLVqxcs\n
eYEImWzSz2GpIBwL+RH9w5Gl1/eYy7HEDCrczLwv1i15KyZfnh8CEOyen03uCqXf\n
dKpcNdFEM/9zvBI9b1cMgqzM3B4zZeBVeXrith3PFbdoRnRMrS7ofI8eQm++gElt\n
nYkLQsb/eA99mlvmxYrSpeN2+hvxfNsgUFKSYh93YMeHPEbPXA6rqv9ZiJvpz/Mj\n
YbyYbbm9TP80JlFKUfqjSdzHY2EGEtc4JtfUtOJdhHKAQIjgms4vlokFvEIX6Kfh\n
BTSsYJXBFlgmyWf1u0iinCguSWdSXOgIni3qdt4PXc8i2emFBz+bFdgTWslFrhIz\n
kOjrjhuRAoGBAP9y8GCUAM/OWdcJnJI4SXh8GrLom0cP3Ew3dRAuD4C9Ay4G1bhp\n
jYq8UKsosPcgnAfk9EGeNyDOniPWtcScR4i/xp6+cOBoIMvD3wjofpfG7iIcjpps\n
zM5W6x0yn3AJ8NRArVXwEpGpo4FKn2reBpSi5+DqecOXoOck3WQVEBkHAoGBAOAg\n
n8FtuCjU4/5BybX4uRjr5RCcnYWCrRIMqsjfWUcawm3j4oKn8eCYjxcpIaBIpmbB\n
Eg54YweYRCTNx/+AmaYa9b7MTvA3aC41MhRCZXLLQvHaA5oHgMSLddrDZlDLg+LR\n
EWDKoiEeYyIyN1UFwJsAKhndluv7DkUFl+xWbSBHAoGBAPxBttrIjRypO9K8rR8/\n
8l3GwF7YkS5VnUiuoy19LtYE0TUMjtTzd1D/sfGz1z3TuAGbuRFreiktoMDncMxd\n
P87tAukUS0dvzKMsI/4aCZk8W0DYToJ02rMQ5lEJAqWTS31u+T0aPFwX110AIflY\n
k8sILE/RfLkH7V8U6oPAwQrVAoGAQAQxfU84fbkpEfN6iNZtEBg4ykDhoUPM6U3i\n
7hMVbgDPrhGcHhOYO713iXb/GsgFd24IGUf7iSzNsfFxAaKawF4M+R1kIqrAwAoD\n
rtO0JFC4Y1oRE0q3Vew7kmujaspmdj+fBhV6r5j9WcQcF9XXyK4IWHD5bZe84KwT\n
U7bv3nsCgYEA/wHuPbTXRc3mJsZTz6ucS2o3EVy/HNjmRyLHiHckjSjUryq2t+q8\n
aJ6z5e5GWZWpITbSCneF1zXtlCsvNSWYi1P9itt+E4NfB8Bpik/M8WUhL/PrLCzu\n
Sh2O+DHWNyyNS8a5wvJDOEUj1ktKVjSwwG5fy0EQhH6rOQcZHNKj70o=\n
-----END RSA PRIVATE KEY-----
")

(def rsa-priv-pkcs8 (base64/decode
"MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDfpSAb9AIeXubC
uKkAOsI7BfhQhlotgabp2qwZmS9CHfOxKOlc34Rx1xbf4wBDuUFCz5fPocdgjW15
AYIRoo7nORUOMWvaCnAGlQlsDTJJn1kC7Jjb6N87TpsgLKCkrrSUvhBUxbX+e5ul
3mlnemu8oOU8Pnwea1RYV8I3Yznbh0MmKhC4l52XBR2irSoubQXMP4lGkxnDDjPH
fc0xZUh84ZAe3sJP1pmQRP7/33kn5cgyq0I6f1k303+sJB20eNsk3eIWKNxszUU0
JPsNV7wmt7eU/9CuPkr5DqAagu+qmhneM0TZ6ijekMXZOqxC/94rJKwj+WgTt+NT
fRrcktDxAgMBAAECggEBAM9Gd0/xAtWrFyx5gQiZbNLPYakgHAv5Ef3DkaXX95jL
scQMKtzMvC/WLXkrJl+eHwIQ7J6fTe4Kpd90qlw10UQz/3O8Ej1vVwyCrMzcHjNl
4FV5euK2Hc8Vt2hGdEytLuh8jx5Cb76ASW2diQtCxv94D32aW+bFitKl43b6G/F8
2yBQUpJiH3dgx4c8Rs9cDquq/1mIm+nP8yNhvJhtub1M/zQmUUpR+qNJ3MdjYQYS
1zgm19S04l2EcoBAiOCazi+WiQW8Qhfop+EFNKxglcEWWCbJZ/W7SKKcKC5JZ1Jc
6AieLep23g9dzyLZ6YUHP5sV2BNayUWuEjOQ6OuOG5ECgYEA/3LwYJQAz85Z1wmc
kjhJeHwasuibRw/cTDd1EC4PgL0DLgbVuGmNirxQqyiw9yCcB+T0QZ43IM6eI9a1
xJxHiL/Gnr5w4Gggy8PfCOh+l8buIhyOmmzMzlbrHTKfcAnw1ECtVfASkamjgUqf
at4GlKLn4Op5w5eg5yTdZBUQGQcCgYEA4CCfwW24KNTj/kHJtfi5GOvlEJydhYKt
EgyqyN9ZRxrCbePigqfx4JiPFykhoEimZsESDnhjB5hEJM3H/4CZphr1vsxO8Ddo
LjUyFEJlcstC8doDmgeAxIt12sNmUMuD4tERYMqiIR5jIjI3VQXAmwAqGd2W6/sO
RQWX7FZtIEcCgYEA/EG22siNHKk70rytHz/yXcbAXtiRLlWdSK6jLX0u1gTRNQyO
1PN3UP+x8bPXPdO4AZu5EWt6KS2gwOdwzF0/zu0C6RRLR2/Moywj/hoJmTxbQNhO
gnTasxDmUQkCpZNLfW75PRo8XBfXXQAh+ViTywgsT9F8uQftXxTqg8DBCtUCgYBA
BDF9Tzh9uSkR83qI1m0QGDjKQOGhQ8zpTeLuExVuAM+uEZweE5g7vXeJdv8ayAV3
bggZR/uJLM2x8XEBoprAXgz5HWQiqsDACgOu07QkULhjWhETSrdV7DuSa6NqymZ2
P58GFXqvmP1ZxBwX1dfIrghYcPltl7zgrBNTtu/eewKBgQD/Ae49tNdFzeYmxlPP
q5xLajcRXL8c2OZHIseIdySNKNSvKra36rxonrPl7kZZlakhNtIKd4XXNe2UKy81
JZiLU/2K234Tg18HwGmKT8zxZSEv8+ssLO5KHY74MdY3LI1LxrnC8kM4RSPWS0pW
NLDAbl/LQRCEfqs5Bxkc0qPvSg=="))

(def rsa-private-pkcs8-pem
"
-----BEGIN PRIVATE KEY-----\n
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDfpSAb9AIeXubC\n
uKkAOsI7BfhQhlotgabp2qwZmS9CHfOxKOlc34Rx1xbf4wBDuUFCz5fPocdgjW15\n
AYIRoo7nORUOMWvaCnAGlQlsDTJJn1kC7Jjb6N87TpsgLKCkrrSUvhBUxbX+e5ul\n
3mlnemu8oOU8Pnwea1RYV8I3Yznbh0MmKhC4l52XBR2irSoubQXMP4lGkxnDDjPH\n
fc0xZUh84ZAe3sJP1pmQRP7/33kn5cgyq0I6f1k303+sJB20eNsk3eIWKNxszUU0\n
JPsNV7wmt7eU/9CuPkr5DqAagu+qmhneM0TZ6ijekMXZOqxC/94rJKwj+WgTt+NT\n
fRrcktDxAgMBAAECggEBAM9Gd0/xAtWrFyx5gQiZbNLPYakgHAv5Ef3DkaXX95jL\n
scQMKtzMvC/WLXkrJl+eHwIQ7J6fTe4Kpd90qlw10UQz/3O8Ej1vVwyCrMzcHjNl\n
4FV5euK2Hc8Vt2hGdEytLuh8jx5Cb76ASW2diQtCxv94D32aW+bFitKl43b6G/F8\n
2yBQUpJiH3dgx4c8Rs9cDquq/1mIm+nP8yNhvJhtub1M/zQmUUpR+qNJ3MdjYQYS\n
1zgm19S04l2EcoBAiOCazi+WiQW8Qhfop+EFNKxglcEWWCbJZ/W7SKKcKC5JZ1Jc\n
6AieLep23g9dzyLZ6YUHP5sV2BNayUWuEjOQ6OuOG5ECgYEA/3LwYJQAz85Z1wmc\n
kjhJeHwasuibRw/cTDd1EC4PgL0DLgbVuGmNirxQqyiw9yCcB+T0QZ43IM6eI9a1\n
xJxHiL/Gnr5w4Gggy8PfCOh+l8buIhyOmmzMzlbrHTKfcAnw1ECtVfASkamjgUqf\n
at4GlKLn4Op5w5eg5yTdZBUQGQcCgYEA4CCfwW24KNTj/kHJtfi5GOvlEJydhYKt\n
EgyqyN9ZRxrCbePigqfx4JiPFykhoEimZsESDnhjB5hEJM3H/4CZphr1vsxO8Ddo\n
LjUyFEJlcstC8doDmgeAxIt12sNmUMuD4tERYMqiIR5jIjI3VQXAmwAqGd2W6/sO\n
RQWX7FZtIEcCgYEA/EG22siNHKk70rytHz/yXcbAXtiRLlWdSK6jLX0u1gTRNQyO\n
1PN3UP+x8bPXPdO4AZu5EWt6KS2gwOdwzF0/zu0C6RRLR2/Moywj/hoJmTxbQNhO\n
gnTasxDmUQkCpZNLfW75PRo8XBfXXQAh+ViTywgsT9F8uQftXxTqg8DBCtUCgYBA\n
BDF9Tzh9uSkR83qI1m0QGDjKQOGhQ8zpTeLuExVuAM+uEZweE5g7vXeJdv8ayAV3\n
bggZR/uJLM2x8XEBoprAXgz5HWQiqsDACgOu07QkULhjWhETSrdV7DuSa6NqymZ2\n
P58GFXqvmP1ZxBwX1dfIrghYcPltl7zgrBNTtu/eewKBgQD/Ae49tNdFzeYmxlPP\n
q5xLajcRXL8c2OZHIseIdySNKNSvKra36rxonrPl7kZZlakhNtIKd4XXNe2UKy81\n
JZiLU/2K234Tg18HwGmKT8zxZSEv8+ssLO5KHY74MdY3LI1LxrnC8kM4RSPWS0pW\n
NLDAbl/LQRCEfqs5Bxkc0qPvSg==\n
-----END PRIVATE KEY-----
")

(def rsa-pub-key (base64/decode
"MIIBCgKCAQEA36UgG/QCHl7mwripADrCOwX4UIZaLYGm6dqsGZkvQh3zsSjpXN+E
cdcW3+MAQ7lBQs+Xz6HHYI1teQGCEaKO5zkVDjFr2gpwBpUJbA0ySZ9ZAuyY2+jf
O06bICygpK60lL4QVMW1/nubpd5pZ3prvKDlPD58HmtUWFfCN2M524dDJioQuJed
lwUdoq0qLm0FzD+JRpMZww4zx33NMWVIfOGQHt7CT9aZkET+/995J+XIMqtCOn9Z
N9N/rCQdtHjbJN3iFijcbM1FNCT7DVe8Jre3lP/Qrj5K+Q6gGoLvqpoZ3jNE2eoo
3pDF2TqsQv/eKySsI/loE7fjU30a3JLQ8QIDAQAB"))

(def rsa-public-pkcs1-pem
"
-----BEGIN RSA PUBLIC KEY-----\n
MIIBCgKCAQEA36UgG/QCHl7mwripADrCOwX4UIZaLYGm6dqsGZkvQh3zsSjpXN+E\n
cdcW3+MAQ7lBQs+Xz6HHYI1teQGCEaKO5zkVDjFr2gpwBpUJbA0ySZ9ZAuyY2+jf\n
O06bICygpK60lL4QVMW1/nubpd5pZ3prvKDlPD58HmtUWFfCN2M524dDJioQuJed\n
lwUdoq0qLm0FzD+JRpMZww4zx33NMWVIfOGQHt7CT9aZkET+/995J+XIMqtCOn9Z\n
N9N/rCQdtHjbJN3iFijcbM1FNCT7DVe8Jre3lP/Qrj5K+Q6gGoLvqpoZ3jNE2eoo\n
3pDF2TqsQv/eKySsI/loE7fjU30a3JLQ8QIDAQAB\n
-----END RSA PUBLIC KEY-----
")

(def rsa-pub-pkcs8 (base64/decode
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA36UgG/QCHl7mwripADrC
OwX4UIZaLYGm6dqsGZkvQh3zsSjpXN+EcdcW3+MAQ7lBQs+Xz6HHYI1teQGCEaKO
5zkVDjFr2gpwBpUJbA0ySZ9ZAuyY2+jfO06bICygpK60lL4QVMW1/nubpd5pZ3pr
vKDlPD58HmtUWFfCN2M524dDJioQuJedlwUdoq0qLm0FzD+JRpMZww4zx33NMWVI
fOGQHt7CT9aZkET+/995J+XIMqtCOn9ZN9N/rCQdtHjbJN3iFijcbM1FNCT7DVe8
Jre3lP/Qrj5K+Q6gGoLvqpoZ3jNE2eoo3pDF2TqsQv/eKySsI/loE7fjU30a3JLQ
8QIDAQAB"))

(def rsa-public-pkcs8-pem
"
-----BEGIN PUBLIC KEY-----\n
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA36UgG/QCHl7mwripADrC\n
OwX4UIZaLYGm6dqsGZkvQh3zsSjpXN+EcdcW3+MAQ7lBQs+Xz6HHYI1teQGCEaKO\n
5zkVDjFr2gpwBpUJbA0ySZ9ZAuyY2+jfO06bICygpK60lL4QVMW1/nubpd5pZ3pr\n
vKDlPD58HmtUWFfCN2M524dDJioQuJedlwUdoq0qLm0FzD+JRpMZww4zx33NMWVI\n
fOGQHt7CT9aZkET+/995J+XIMqtCOn9ZN9N/rCQdtHjbJN3iFijcbM1FNCT7DVe8\n
Jre3lP/Qrj5K+Q6gGoLvqpoZ3jNE2eoo3pDF2TqsQv/eKySsI/loE7fjU30a3JLQ\n
8QIDAQAB\n
-----END PUBLIC KEY-----
")

(def ec-private-sec1 (base64/decode
"MHcCAQEEIH4et747bbOv+eLWNSW01tr9zuYSYGSjBT6T4NTpNTLYoAoGCCqGSM4
9AwEHoUQDQgAEly/EM+lE5907zBNwYy2QQ6UVKQC0wEYF/pxNtkoMO4CzC+XtZWh
RVMsgtfPaOgcCb5EamDXYV68Ius9v7VZ9jQ=="))

(def ec-private-sec1-pem
"
-----BEGIN EC PRIVATE KEY-----\n
MHcCAQEEIH4et747bbOv+eLWNSW01tr9zuYSYGSjBT6T4NTpNTLYoAoGCCqGSM49\n
AwEHoUQDQgAEly/EM+lE5907zBNwYy2QQ6UVKQC0wEYF/pxNtkoMO4CzC+XtZWhR\n
VMsgtfPaOgcCb5EamDXYV68Ius9v7VZ9jQ==\n
-----END EC PRIVATE KEY-----
")

# There is no public sec1 key..

(def ec-private-pkcs8 (base64/decode
"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgfh63vjtts6/54tY1
JbTW2v3O5hJgZKMFPpPg1Ok1MtihRANCAASXL8Qz6UTn3TvME3BjLZBDpRUpALTA
RgX+nE22Sgw7gLML5e1laFFUyyC189o6BwJvkRqYNdhXrwi6z2/tVn2N"))

(def ec-private-pkcs8-pem
"-----BEGIN PRIVATE KEY-----\n
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgfh63vjtts6/54tY1\n
JbTW2v3O5hJgZKMFPpPg1Ok1MtihRANCAASXL8Qz6UTn3TvME3BjLZBDpRUpALTA\n
RgX+nE22Sgw7gLML5e1laFFUyyC189o6BwJvkRqYNdhXrwi6z2/tVn2N\n
-----END PRIVATE KEY-----
")

(def ec-public-pkcs8 (base64/decode
"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEly/EM+lE5907zBNwYy2QQ6UVKQC0
wEYF/pxNtkoMO4CzC+XtZWhRVMsgtfPaOgcCb5EamDXYV68Ius9v7VZ9jQ=="))

(def ec-public-pkcs8-pem
"-----BEGIN PUBLIC KEY-----\n
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEly/EM+lE5907zBNwYy2QQ6UVKQC0\n
wEYF/pxNtkoMO4CzC+XtZWhRVMsgtfPaOgcCb5EamDXYV68Ius9v7VZ9jQ==\n
-----END PUBLIC KEY-----
")


(deftest "rsa public export is identical"
  (def asn1-public-key (asn1/decode rsa-pub-key))
  (def {:value [{:value n} {:value e}]} asn1-public-key)
  (def pub (pk/import {:n n :e e :type :rsa}))
  (def exported (pk/export-public pub {:export-standard :pkcs1 :export-format :encoded :export-encoding :der}))
  (def {:der der} exported)
  (is (= der rsa-pub-key))

  (def {:der der} (pk/export-public pub {:export-standard :pkcs8 :export-format :encoded :export-encoding :der}))
  (is (= der rsa-pub-pkcs8))

  (def pub (pk/import {:der rsa-pub-key}))
  (def {:der der} (pk/export-public pub {:export-standard :pkcs8 :export-format :encoded :export-encoding :der}))
  (is (= der rsa-pub-pkcs8))

  (def pub (pk/import {:der rsa-pub-pkcs8}))
  (def {:der der} (pk/export-public pub {:export-standard :pkcs8 :export-format :encoded :export-encoding :der}))
  (is (= der rsa-pub-pkcs8))

  (def pub (pk/import {:pem rsa-public-pkcs1-pem}))
  (def {:der der} (pk/export-public pub {:export-standard :pkcs8 :export-format :encoded :export-encoding :der}))
  (is (= der rsa-pub-pkcs8))
  (def {:pem pem} (pk/export-public pub {:export-standard :pkcs1 :export-format :encoded :export-encoding :pem}))
  (is (= pem rsa-public-pkcs1-pem))
  )

(deftest "rsa private export is identical"
  (def asn1-private-key (asn1/decode rsa-priv-key))
  (def {:value [_ {:value n} {:value e} {:value d} {:value p} {:value q}]} asn1-private-key)
  (def priv (pk/import {:n n :e e :d d :p p :q q :type :rsa}))
  (def exported (pk/export-private priv {:export-standard :pkcs1 :export-format :encoded :export-encoding :der}))
  (def {:der der} exported)
  (is (= der rsa-priv-key))

  (def {:der der} (pk/export-private priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :der}))
  (is (= der rsa-priv-pkcs8))

  (def priv (pk/import {:der rsa-priv-key}))
  (def {:der der} (pk/export-private priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :der}))
  (is (= der rsa-priv-pkcs8))

  (def priv (pk/import {:der rsa-priv-pkcs8}))
  (def {:der der} (pk/export-private priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :der}))
  (is (= der rsa-priv-pkcs8))

  (def priv (pk/import {:pem rsa-private-pkcs1-pem}))
  (def {:der der} (pk/export-private priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :der}))
  (is (= der rsa-priv-pkcs8))
  (def {:pem pem} (pk/export-private priv {:export-standard :pkcs1 :export-format :encoded :export-encoding :pem}))
  (is (= pem rsa-private-pkcs1-pem))
  )

(deftest "ec private export is identical"
  (def asn1-private-key (asn1/decode ec-private-sec1))
  (def {:value [_ {:value d} {:value [{:value oid}]} ]} asn1-private-key)
  (def curve (oid/to-curve oid))
  (def priv (pk/import {:d d :curve-group curve :type :ecdsa}))
  (def exported (pk/export-private priv {:export-standard :sec1 :export-format :encoded :export-encoding :der}))
  (def {:der der} exported)
  (is (= der ec-private-sec1))

  (def {:der der} (pk/export-private priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :der}))
  (is (= der ec-private-pkcs8))

  (def priv (pk/import {:der ec-private-sec1}))
  (def {:der der} (pk/export-private priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :der}))
  (is (= der ec-private-pkcs8))

  (def priv (pk/import {:der ec-private-pkcs8}))
  (def {:der der} (pk/export-private priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :der}))
  (is (= der ec-private-pkcs8))

  (def priv (pk/import {:pem ec-private-sec1-pem}))
  (def {:der der} (pk/export-private priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :der}))
  (is (= der ec-private-pkcs8))
  (def {:pem pem} (pk/export-private priv {:export-standard :sec1 :export-format :encoded :export-encoding :pem}))
  (is (= pem ec-private-sec1-pem))
  )

(deftest "ec public export is identical"
  (def asn1-private-key (asn1/decode ec-private-sec1))
  (def {:value [_ {:value d} {:value [{:value oid}]} ]} asn1-private-key)
  (def curve (oid/to-curve oid))
  (def priv (pk/import {:d d :curve-group curve :type :ecdsa}))
  (def exported (pk/export-public priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :der}))
  (def {:der der} exported)
  (is (= der ec-public-pkcs8))

  (def priv (pk/import {:der ec-public-pkcs8}))
  (def exported (pk/export-public priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :der}))
  (def {:der der} exported)
  (is (= der ec-public-pkcs8))

  (def priv (pk/import {:pem ec-public-pkcs8-pem}))
  (def exported (pk/export-public priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :der}))
  (def {:der der} exported)
  (is (= der ec-public-pkcs8))
  )

(deftest "pem export is identical"
  # RSA
  (def asn1-private-key (asn1/decode rsa-priv-key))
  (def {:value [_ {:value n} {:value e} {:value d} {:value p} {:value q}]} asn1-private-key)
  (def priv (pk/import {:n n :e e :d d :p p :q q :type :rsa}))
  (def {:pem pem} (pk/export-private priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :pem}))
  (is (= rsa-private-pkcs8-pem pem))

  (def {:pem pem} (pk/export-private priv {:export-standard :pkcs1 :export-format :encoded :export-encoding :pem}))
  (is (= rsa-private-pkcs1-pem pem))

  (def {:pem pem} (pk/export-public priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :pem}))
  (is (= rsa-public-pkcs8-pem pem))

  (def {:pem pem} (pk/export-public priv {:export-standard :pkcs1 :export-format :encoded :export-encoding :pem}))
  (is (= rsa-public-pkcs1-pem pem))

  # EC
  (def asn1-private-key (asn1/decode ec-private-sec1))
  (def {:value [_ {:value d} {:value [{:value oid}]} ]} asn1-private-key)
  (def curve (oid/to-curve oid))
  (def priv (pk/import {:d d :curve-group curve :type :ecdsa}))

  (def {:pem pem} (pk/export-private priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :pem}))
  (is (= ec-private-pkcs8-pem pem))

  (def {:pem pem} (pk/export-private priv {:export-standard :sec1 :export-format :encoded :export-encoding :pem}))
  (is (= ec-private-sec1-pem pem))

  (def {:pem pem} (pk/export-public priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :pem}))
  (is (= ec-public-pkcs8-pem pem))
)

(deftest "pem import export is identical"
  # RSA
  (def priv (pk/import {:pem rsa-private-pkcs8-pem}))
  (def {:pem pem} (pk/export-private priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :pem}))
  (is (= rsa-private-pkcs8-pem pem))

  (def priv (pk/import {:pem rsa-private-pkcs1-pem}))
  (def {:pem pem} (pk/export-private priv {:export-standard :pkcs1 :export-format :encoded :export-encoding :pem}))
  (is (= rsa-private-pkcs1-pem pem))

  (def pub (pk/import {:pem rsa-public-pkcs8-pem}))
  (def {:pem pem} (pk/export-public pub {:export-standard :pkcs8 :export-format :encoded :export-encoding :pem}))
  (is (= rsa-public-pkcs8-pem pem))

  (def pub (pk/import {:pem rsa-public-pkcs1-pem}))
  (def {:pem pem} (pk/export-public pub {:export-standard :pkcs1 :export-format :encoded :export-encoding :pem}))
  (is (= rsa-public-pkcs1-pem pem))

  # EC

  (def priv (pk/import {:pem ec-private-pkcs8-pem}))
  (def {:pem pem} (pk/export-private priv {:export-standard :pkcs8 :export-format :encoded :export-encoding :pem}))
  (is (= ec-private-pkcs8-pem pem))

  (def priv (pk/import {:pem ec-private-pkcs8-pem}))
  (def {:pem pem} (pk/export-private priv {:export-standard :sec1 :export-format :encoded :export-encoding :pem}))
  (is (= ec-private-sec1-pem pem))

  (def pub (pk/import {:pem ec-public-pkcs8-pem}))
  (def {:pem pem} (pk/export-public pub {:export-standard :pkcs8 :export-format :encoded :export-encoding :pem}))
  (is (= ec-public-pkcs8-pem pem))
)

(defn ck [key]
  (def sig (:sign key data))
  (is sig)
  (is (:verify key data sig))
  )

(deftest "Generating is fine"
  (ck (pk/generate))
  (ck (pk/generate :rsa))
  (ck (pk/generate :rsa 1024))
  (ck (pk/generate :rsa 2048))
  (ck (pk/generate :ecdsa))
  (ck (pk/generate :ecdsa :secp192r1))
  (ck (pk/generate :ecdsa :secp256r1))
  (ck (pk/generate :ecdsa :secp384r1))
  (ck (pk/generate :ecdsa :secp521r1))
  (assert-thrown (pk/generate :rsa "hello"))
  (assert-thrown (pk/generate :rsa 1025))
  (assert-thrown (pk/generate :ecdsa :secp521k1))
  )


#
(def pubkey `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENP9hG3V3eIhxysDOmbinYfiqZwNr
Jvqi+Ue6Jvit1FEBWSScTQFkLzpTBElN5bbqmqY+HGVnAEKyqfjQDu4ITg==
-----END PUBLIC KEY-----`)
(def privkey `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIkAJAmmXzzzqgVZf1TntxEz+uSeYCKa+Hdk6Mc5D9pkoAoGCCqGSM49
AwEHoUQDQgAE2IQXKtLi5gYga/sYXEazBo4r0VRcsr37iX0gt3Ackrd3tNUotrbQ
F6oCMuD6tdAINYl/dJEHgly39U71K2poww==
-----END EC PRIVATE KEY-----`)

(def expected "4522afc823e522f6f280f1bb5d16b63995e219662345ac60e62dcb8726a2e0dc")

(deftest "Matches openssl (via python) implementation"
  (def priv (pk/import {:pem privkey :type :ecdh}))
  (def pub (pk/import {:pem pubkey :type :ecdh}))
  (is (= expected (hex/encode (pk/key-agreement priv pub))))
  )

(deftest "Same result with newly generated keys"
  (def key1 (pk/generate :ecdh :secp256r1))
  (def key2 (pk/generate :ecdh :secp256r1))
  (is (= (hex/encode (pk/key-agreement key1 key2)) (hex/encode (pk/key-agreement key2 key1))))
  )

(run-tests!)
