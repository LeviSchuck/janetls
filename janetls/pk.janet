# Copyright (c) 2020 Levi Schuck
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

(import ./native :prefix "")
(import ./pem :prefix "")

(defn- semi [v] ;(if v [v] []))

(def pk/formats [:components :encoded])
(def pk/encoding [:der :pem])
(def pk/standard [:pkcs8 :pkcs1])


(defn- pk/options [&opt options]
  (default options {})
  (def {
    :encoding encoding
    :encoding-variant variant
    :digest digest
    :export-format ex-format
    :export-encoding ex-encoding
    :export-standard ex-standard
    } options)
  (default encoding :raw)
  (default ex-format :components)
  (default ex-encoding :pem)
  (default ex-standard :pkcs8)
  { :encoding encoding
    :encoding-variant variant
    :digest digest
    :export-format ex-format
    :export-encoding ex-encoding
    :export-standard ex-standard
    })

(defn pk/sign [{:key key} data &opt options]
  (def options (pk/options options))
  (def signature (:sign key data ;(semi (options :digest))))
  (encoding/encode signature (options :encoding) ;(semi (options :encoding-variant)))
  )

(defn pk/verify [{:key key} data signature &opt options]
  (def options (pk/options options))
  (def signature (encoding/decode signature (options :encoding ;(semi (options :encoding-variant)))))
  (:verify key data signature ;(semi (options :digest)))
  )

(defn- only-type [expected actual reason]
  (if (not= expected actual) (errorf "Only %p keys can %S, this key is of type %p" expected reason actual)))


(defn pk/encrypt [{:key key :type kind} plaintext &opt options]
  (only-type :rsa kind "can encrypt and decrypt")
  (def options (pk/options options))
  (def ciphertext (:encrypt key plaintext))
  (def ciphertext (encoding/encode ciphertext (options :encoding ;(semi (options :encoding-variant)))))
  ciphertext)

(defn pk/decrypt [{:key key :type kind} ciphertext &opt options]
  (only-type :rsa kind "can encrypt and decrypt")
  (def options (pk/options options))
  (def ciphertext (encoding/decode ciphertext (options :encoding ;(semi (options :encoding-variant)))))
  (def plaintext (:decrypt key ciphertext))
  plaintext)

(defn- pk/to-pem-type [kind standard information-class] (cond
  (and (= :rsa kind) (= :public information-class) (= :pkcs1 standard)) "RSA PUBLIC KEY"
  (and (= :rsa kind) (= :private information-class) (= :pkcs1 standard)) "RSA PRIVATE KEY"
  (and (= :public information-class) (= :pkcs8 standard)) "PUBLIC KEY"
  (and (= :private information-class) (= :pkcs8 standard)) "PRIVATE KEY"
  (errorf "Unable to match PEM type from parameters %p %p %p" kind standard information-class)
  ))


(defn- pk/rsa-to-pkcs1-private [key] [
  0
  (key :n)
  (key :e)
  (key :d)
  (key :p)
  (key :q)
  (key :dp)
  (key :dq)
  (key :qp)
  ])

(defn- pk/rsa-to-pkcs1-public [key] [
  (key :n)
  (key :e)
  ])

(defn- pk/rsa-to-pkcs8-private [key] [
  0
  ["1.2.840.113549.1.1.1" nil]
  {:type :octet-string :value (pk/rsa-to-pkcs1-private key)}
  ])

(defn- pk/rsa-to-pkcs8-public [key] [
  ["1.2.840.113549.1.1.1" nil]
  {:type :bit-string :value (pk/rsa-to-pkcs1-public key)}
  ])

(defn- pk/to-asn1 [key kind standard information-class] (cond
  (and (= :rsa kind) (= :public information-class) (= :pkcs1 standard)) (pk/rsa-to-pkcs1-public key)
  (and (= :rsa kind) (= :private information-class) (= :pkcs1 standard)) (pk/rsa-to-pkcs1-private key)
  (and (= :rsa kind) (= :public information-class) (= :pkcs8 standard)) (pk/rsa-to-pkcs8-public key)
  (and (= :rsa kind) (= :private information-class) (= :pkcs8 standard)) (pk/rsa-to-pkcs8-private key)
  (errorf "Unable to match ASN.1 format from parameters %p %p %p" kind standard information-class)
  ))

(defn- pk/to-der [key kind standard information-class]
  (def data (pk/to-asn1 key kind standard information-class))
  (asn1/encode data))

(defn- pk/export-internal [{:key key :type kind} information-class &opt options]
  (def options (pk/options options))
  (def components (cond
    (= :public information-class) (:export-public key)
    (= :private information-class) (:export-private key)
    (errorf "Expected :public or :private but got %p" information-class)
    ))
  (def {:export-format format :export-encoding encoding :export-standard standard} options)
  (cond
    (= :components format) components
    (= :encoded format) (do
      (def result @{:export-standard standard :type kind :information-class information-class})
      (if (= :rsa kind) (put result :version (:version key)))
      (if (= :ecdsa kind) (put result :curve-group (:curve-group key)))
      (def der (pk/to-der components kind standard information-class))
      (cond
        (= :der encoding) (put result :der der)
        (= :pem encoding) (put result :pem (error "not implemented"))
        (errorf "expected :pem or :der but got %p" encoding)
        )
    )
    (errorf "Expected :components or :encoded for :export-format but got %p" format)))

(defn pk/export-public [key &opt options]
  (pk/export-internal key :public options))

(defn pk/export-private [key &opt options]
  (pk/export-internal key :private options))

(def- PK-Prototype @{
  :type :none
  :sign pk/sign
  :verify pk/verify
  :encrypt pk/encrypt
  :decrypt pk/decrypt
  :export-private pk/export-private
  :export-public pk/export-public
  })

(defn pk/import [key]
  (def kind (key :type))
  (def key (cond
    (= :rsa kind) (rsa/import key)
    (= :ecdsa kind) (ecdsa/import key)
    (errorf "Could not determine type, should be :rsa or :ecdsa but got %p" kind)
  ))
  (table/setproto @{:key key :type kind} PK-Prototype)
  )

