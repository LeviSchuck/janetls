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
(import ./oid :prefix "")

(defn- semi [v] ;(if v [v] []))

(def pk/formats [:components :encoded])
(def pk/encoding [:der :pem])
(def pk/standard [:pkcs8 :pkcs1 :sec1])

(defn check-public [key information-class]
  (if
    (and (= information-class :private) (= (key :information-class) :public))
    (error "The key given is a public key and cannot be written as a private key")))

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

(defn- pk/to-pem-type [kind standard information-class] (case [kind information-class standard]
  [:rsa :public :pkcs1] "RSA PUBLIC KEY"
  [:rsa :private :pkcs1] "RSA PRIVATE KEY"
  [:rsa :public :pkcs8] "PUBLIC KEY"
  [:rsa :private :pkcs8] "PRIVATE KEY"
  [:ecdsa :private :sec1] "EC PRIVATE KEY"
  [:ecdsa :public :pkcs8] "PUBLIC KEY"
  [:ecdsa :private :pkcs8] "PRIVATE KEY"
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
  {:type :octet-string :value {:type :sequence :value (pk/rsa-to-pkcs1-private key)}}
  ])

(defn- pk/rsa-to-pkcs8-public [key] [
  ["1.2.840.113549.1.1.1" nil]
  {:type :bit-string :value {:type :sequence :value (pk/rsa-to-pkcs1-public key) :bits (key :bits)}}
  ])

(defn- pk/ec-to-sec1-private [key include-identifier] [
  1
  {:type :octet-string :value (key :d)}
  ;(if include-identifier [{
    :value (oid/from-curve (key :curve-group))
    :type :context-specific
    :constructed true
    :tag 0
    }] [])
  {
    :value {:type :bit-string :value (key :p)}
    :type :context-specific
    :constructed true
    :tag 1
    }
  ])

(defn- pk/ec-to-pkcs8-private [key] [
  0
  ["1.2.840.10045.2.1" (oid/from-curve (key :curve-group))]
  {:type :octet-string :value {:type :sequence :value (pk/ec-to-sec1-private key false)}}
  ])

(defn- pk/ec-to-pkcs8-public [key] [
  ["1.2.840.10045.2.1" (oid/from-curve (key :curve-group))]
  {:type :bit-string :value (key :p) :bits (key :bits)}
  ])

# NOTE: SEC1 EC keys have EC in the PEM name,
# unlike rsa, PKCS8 is not a plain wrapper
# around SEC1
# RFC 5915
# RFC 5208

(defn- pk/to-asn1 [key kind standard information-class] (case [kind information-class standard]
  [:rsa :public :pkcs1] (pk/rsa-to-pkcs1-public key)
  [:rsa :private :pkcs1] (pk/rsa-to-pkcs1-private key)
  [:rsa :public :pkcs8] (pk/rsa-to-pkcs8-public key)
  [:rsa :private :pkcs8] (pk/rsa-to-pkcs8-private key)
  [:ecdsa :private :sec1] (pk/ec-to-sec1-private key true)
  [:ecdsa :private :pkcs8] (pk/ec-to-pkcs8-private key)
  [:ecdsa :public :pkcs8] (pk/ec-to-pkcs8-public key)
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
  (check-public components information-class)
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
        (= :pem encoding) (put result :pem (pem/encode {:name (pk/to-pem-type kind standard information-class) :body der}))
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
  :information-class :none
  :sign pk/sign
  :verify pk/verify
  :encrypt pk/encrypt
  :decrypt pk/decrypt
  :export-private pk/export-private
  :export-public pk/export-public
  })

(def- zero (bignum/parse 0))
(def- one (bignum/parse 1))
(defn- bignum? [b] (= :janetls/bignum (type b)))

(defn- pk/match-pkcs1-private [key] (match key
  ({:value [
    {:value version :type :integer}
    {:value n :type :integer}
    {:value e :type :integer}
    {:value d :type :integer}
    {:value p :type :integer}
    {:value q :type :integer}
    {:value _ :type :integer}
    {:value _ :type :integer}
    {:value _ :type :integer}
  ] :type :sequence}
    (and (= version zero) (bignum? n) (bignum? e) (bignum? d) (bignum? p) (bignum? q)))
    {:n n :e e :d d :p p :q q :type :rsa :information-class :private}
  _ nil
  ))

(defn- pk/match-pkcs1-public [key] (match key
  ({:value [
    {:value n :type :integer}
    {:value e :type :integer}
    ] :type :sequence} (and (bignum? n) (bignum? e) (= 2 (length (key :value)))))
    {:n n :e e :type :rsa :information-class :public}
  _ nil
  ))

(defn- pk/match-sec1-private [key] (match key
  ({:value [
    {:value version :type :integer}
    {:value d :type :octet-string}
    {:tag 0 :value [
      {:value curve-group :type :object-identifier}
      ] :constructed true :type :context-specific}
    {:tag 1 :value [
      {:value p :type :bit-string :bits _}
      ] :constructed true :type :context-specific}
    ] :type :sequence} (= one version))
  (let [curve-group (oid/to-curve curve-group)]
    (if curve-group
      { :d d
        :p p
        :curve-group curve-group
        :type :ecdsa
        :information-class :private}))
  # Without curve, With public key (likely pkcs8 wrapped)
  ({:value [
    {:value version :type :integer}
    {:value d :type :octet-string}
    {:tag 1 :value [
      {:value p :type :bit-string :bits _}
      ] :constructed true :type :context-specific}
    ] :type :sequence} (= one version))
  { :d d
    :p p
    :information-class :private}
  # With curve, Without public key
  ({:value [
    {:value version :type :integer}
    {:value d :type :octet-string}
    {:tag 0 :value [
      {:value curve-group :type :object-identifier}
      ] :constructed true :type :context-specific}
    ] :type :sequence} (and (= one version) (= 3 (length (key :value)))))
  (let [curve-group (oid/to-curve curve-group)]
    (if curve-group
      { :d d
        :curve-group curve-group
        :type :ecdsa
        :information-class :private}))
    # Withoutcurve, Without public key (likely pkcs8 wrapped)
  ({:value [
    {:value version :type :integer}
    {:value d :type :octet-string}
    ] :type :sequence} (and (= one version) (= 2 (length (key :value)))))
  { :d d
    :information-class :private}
  _ nil
))

(defn- pk/match-pcks8-private [key] (match key
  ({:value [
    {:value version :type :integer}
    {:value [
      {:value oid-type :type :object-identifier}
      option
      ] :type :sequence}
    {:value [inner-value] :type :octet-string}
    ] :type :sequence} (= version zero))
  (match [oid-type option]
    # RSA
    [[1 2 840 113549 1 1 1] {:type :null}]
    (pk/match-pkcs1-private inner-value)
    # ECDSA
    [[1 2 840 10045 2 1] {:value curve-group :type :object-identifier}]
    (let [
      curve-group (oid/to-curve curve-group)
      components (pk/match-sec1-private inner-value)]
      (if (and curve-group components)
        (freeze (merge components {:type :ecdsa :curve-group curve-group}))
        ))
    _ nil
  )
  _ nil
  ))

(defn- pk/match-pcks8-public [key] (match key
  {:value [
    {:value [
      {:value oid-type :type :object-identifier}
      option
      ] :type :sequence}
    {:value inner-value :type :bit-string :bits _}
    ] :type :sequence}
  (match [oid-type option]
    # RSA - should have an eager parsed element
    # Hence we unwrap it
    [[1 2 840 113549 1 1 1] {:type :null}]
    (let [[inner-value] inner-value] (pk/match-pkcs1-public inner-value))
    # ECDSA - It's an opaque binary, should be the public point.
    [[1 2 840 10045 2 1] {:value curve-group :type :object-identifier}]
    (let [curve-group (oid/to-curve curve-group)]
      (if (and curve-group (string? inner-value))
        {:type :ecdsa :curve-group curve-group :p inner-value :information-class :public}
        ))
    _ nil
  )
  _ nil
  ))


(defn pk/asn1-to-components [asn1] (or
  (pk/match-pkcs1-private asn1)
  (pk/match-pkcs1-public asn1)
  (pk/match-pcks8-private asn1)
  (pk/match-pcks8-public asn1)
  (pk/match-sec1-private asn1)
  ))

(defn pk/import [key]
  (def kind (key :type))
  # only used in der and pem
  (def body (or (key :der) (key :pem)))
  (def kind (if kind
    (case kind
      :rsa :rsa
      :ecdsa :ecdsa
      (errorf ":type %p is not supported" kind))
    (cond
      (key :der) :der
      (key :pem) :pem
      (error "No :type was found, could not find :der or :pem either.")
      )))
  (def imported (case kind
    :rsa (rsa/import key)
    :ecdsa (ecdsa/import key)
    :der (do
      (def asn1 (asn1/decode (key :der) :eager-parse))
      (def components (pk/asn1-to-components asn1))
      (if (not components) (error "Could not decode DER into a known key type"))
      ((pk/import components) :key)
      )
    :pem (do
      (def pem (pem/decode (key :pem)))
      (if (not pem) (error "PEM could not be decoded"))
      (def [pem] pem)
      (def {:name name :body body} pem)
      (def asn1 (asn1/decode body))
      (def components (case name
        "RSA PRIVATE KEY" (pk/match-pkcs1-private asn1)
        "RSA PUBLIC KEY" (pk/match-pkcs1-public asn1)
        "PRIVATE KEY" (pk/match-pcks8-private asn1)
        "PUBLIC KEY" (pk/match-pcks8-public asn1)
        "EC PRIVATE KEY" (pk/match-sec1-private asn1)
        (errorf "Pem type %p not supported" name)
        ))
      (if (not components) (errorf "PEM %p did not match expected ASN.1 structure" name))
      ((pk/import components) :key)
      )
    (errorf "Could not determine type, should be :rsa, :ecdsa, :der, or :pem but got %p" kind)
  ))
  (def kind (if (cfunction? (imported :type)) (:type imported) (imported :type)))
  (def information-class (if (cfunction?
    (imported :information-class))
    (:information-class imported)
    (imported :information-class)))
  (def result @{:key imported :type kind :information-class information-class})
  (if (= :rsa kind) (put result :version (:version imported)))
  (if (= :ecdsa kind) (put result :curve-group (:curve-group imported)))
  (table/setproto result PK-Prototype)
  )

(defn pk/wrap [key]
  (def kind (:type key))
  (case (type key)
    :janetls/rsa nil
    :janetls/ecdsa nil
    (errorf "Could not determine type, should be janetls/rsa or janetls/ecdsa but got %p" (type key)))
  (table/setproto @{:key key :type kind :information-class (:information-class key)} PK-Prototype)
  )

# An enhancement may be to provide access to the other portions of the
# generation functions.
# For example, rsa has versions, digests, mask generation function in a tables.
# ECDSA has a digest as an additional option.

(defn pk/generate [&opt kind option]
  (default kind :rsa)
  (case kind
    :rsa (do
      (default option 2048)
      (pk/wrap (rsa/generate {:bits option}))
      )
    :ecdsa (do
      (default option :secp256r1)
      (pk/wrap (ecdsa/generate option))
      )
    (errorf "Expected :rsa or :ecdsa but got %p" kind)
    ))
