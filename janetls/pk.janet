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

(def pk/formats
  "Enumerates the export formats, to export a PEM file, :encoded must be used."
  [:components :encoded])
(def pk/encoding
  "Enumerates the :encoded encoding options, be it binary DER or ascii PEM"
  [:der :pem])
(def pk/standard
  "Enumerates the ASN.1 standard that a DER or PEM can be encoded with.\n
  If you want your key PEM header to mention \"RSA\", you want :pkcs1.\n
  If you want your key PEM header to mention \"EC\", you want :sec1
  (only available for private EC keys).\n
  Otherwise, and by default, :pkcs8 is used.\n
  "
  [:pkcs8 :pkcs1 :sec1])

(defn- check-public [key information-class]
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

(defn- only-type [expected actual reason]
  (if (not= expected actual) (errorf "Only %p keys can %S, this key is of type %p" expected reason actual)))

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

(defn pk/export-public
  "Export a private or public key to a public key.\n
  Options are described in the documentation for (pk/export).\n
  \n
  The return value depends on the options format, it is either a struct of
  components or a string.
  "
  [key &opt options]
  (pk/export-internal key :public options))

(defn pk/export-private
  "Export a private key to a private key.\n
  Public keys cannot be exported as private keys.\n
  Options are described in the documentation for (pk/export).\n
  \n
  The return value depends on the options format, it is either a struct of
  components or a string.
  "
  [key &opt options]
  (pk/export-internal key :private options))

(defn pk/export
  "Export a key with the same information class.\n
  That is, if the imported key is private, the exported key is private,
  likewise if the imported key is public, the exported key is public.\n
  \n
  Options:\n
  {:export-format format :export-encoding encoding :export-standard standard}\n
  \n
  format - valid values are enumerated from (pk/formats).
  By default is :components.\n
  \n
  encoding - valid values are enumerated from (pk/encoding) and is
  only applicable if format is :encoded. By default is :pem\n
  \n
  standard - valid values are enumaretd from (pk/standard) and is only
  applicable if format is :encoded. :pkcs1 only supports RSA,
  :sec1 only supports ECDSA, :pkcs8 supports all keys. By default is :pkcs8.\n
  \n
  The return value depends on the options format, it is either a struct of
  components or a string.
  "
  [key &opt options]
  (pk/export-internal key (key :information-class) options))

(defn pk/sign
  "
  Sign a string or buffer with this private key.

  Options:\n
  {:encoding encoding :encoding-variant variant :digest digest}\n
  \n
  encoding - valid options enumerated in (encoding/types), by default :raw.\n
  \n
  encoding-variant - used for base64, valid options enumareted in
  (base64/variants), by default :standard.\n
  \n
  digest - can override the digest algorithm used for signatures,
  valid options enumerated in (md/algorithms). Default is attached to the
  wrapped key (rsa, ecdsa), usually :sha256.
  The attached digest can be determined with (:digest key).
  \n
  \n
  Examples:\n
  (pk/sign key \"data here\")\n
  (:sign key data {:encoding :hex})\n
  (:sign key data {:encoding :base64 :encoding-variant :url-unpadded})\n
  (:sign key data {:digest :sha512})\n
  \n
  The return value is a string, which may be encoded according to the options.
  \n
  \n
  Note that this does not support signing a hash directly,
  please file an issue if you need to sign a large amount of data
  without having it all in memory.
  "
  [key data &opt options]
  (def {:key key} key)
  (def options (pk/options options))
  (def signature (:sign key data ;(semi (options :digest))))
  (encoding/encode signature (options :encoding) ;(semi (options :encoding-variant)))
  )

(defn pk/verify
  "
  Verify a string or buffer of data against a string or buffer of
  signature with a private or public key.\n
  \n
  Options are described in the documentation for (pk/sign),
  settings for encoding will be reversed prior to verification.\n
  \n
  Examples:\n
  (pk/verify key data signature)\n
  (:verify key data signature {:encoding :hex})\n
  (:verify key data signature {:encoding :base64 :encoding-variant :url-unpadded})\n
  (:verify key data signature {:digest :sha512})\n
  \n
  The return value is a boolean.\n
  \n
  \n
  Note that this does not support verifying a hash directly,
  please file an issue if you need to sign a large amount of data
  without having it all in memory.\n
  \n
  Note that :rsa signatures vary by the rsa version, such as :pkcs1-v2.1.
  Verification is not compatible across versions, and must be set in the
  wrapped key.
  Please file an issue if you need to pass the version as a part of
  this function. Wrapping a key with the appropriate version beforehand is
  a workaround for this limitation.
  "
  [key data signature &opt options]
  (def {:key key} key)
  (def options (pk/options options))
  (def signature (encoding/decode signature (options :encoding ;(semi (options :encoding-variant)))))
  (:verify key data signature ;(semi (options :digest)))
  )

(defn pk/encrypt
  "Encrypt a plaintext with this key, note only :rsa keys are supported.\n
  \n
  Options:\n
  {:encoding encoding :encoding-variant variant}\n
  \n
  encoding - valid options enumerated in (encoding/types), by default :raw.\n
  \n
  encoding-variant - used for base64, valid options enumareted in
  (base64/variants), by default :standard.\n
  \n
  Examples:\n
  (pk/encrypt key \"hello world\")
  (:encrypt key data {:encoding :hex})\n
  (:encrypt key data {:encoding :base64 :encoding-variant :url-unpadded})\n
  \n
  Note that :rsa encryption varies by the rsa version, such as :pkcs1-v2.1.
  Decryption is not compatible across versions, and must be set in the wrapped
  key. Please file an issue if you need to pass the version as a part of
  this function. Wrapping a key with the appropriate version beforehand is
  a workaround for this limitation.
  "
  [key plaintext &opt options]
  (def {:key key :type kind} key)
  (only-type :rsa kind "can encrypt and decrypt")
  (def options (pk/options options))
  (def ciphertext (:encrypt key plaintext))
  (def ciphertext (encoding/encode ciphertext (options :encoding ;(semi (options :encoding-variant)))))
  ciphertext)

(defn pk/decrypt
  "Decrypt a ciphertext into a plaintext, note that only :rsa keys are
  supported.\n
  \n
  Options are documented in (pk/encrypt)
  settings for encoding will be reversed prior to decryption.
  \n
  Examples:\n
  (pk/decrypt key ciphertext)\n
  (:decrypt key ciphertext {:encoding :hex})\n
  (:decrypt key ciphertext {:encoding :base64 :encoding-variant :url-unpadded})\n
  \n
  Returns a successfully decrypted plaintext, or nil.\n
  \n
  Note that :rsa encryption varies by the rsa version, such as :pkcs1-v2.1.
  Decryption is not compatible across versions, and must be set in the wrapped
  key. Please file an issue if you need to pass the version as a part of
  this function. Wrapping a key with the appropriate version beforehand is
  a workaround for this limitation.
  "
  [key ciphertext &opt options]
  (def {:key key :type kind} key)
  (only-type :rsa kind "can encrypt and decrypt")
  (def options (pk/options options))
  (def ciphertext (encoding/decode ciphertext (options :encoding ;(semi (options :encoding-variant)))))
  (def plaintext (:decrypt key ciphertext))
  plaintext)

(defn pk/key-agreement
  "Performs key agreement, such as ECDH for EC keys\n
  \n
  Options:\n
  private - The private key\n
  public - The private or public key\n
  \n
  Examples:\n
  (def private (pk/generate :ecdh :public))\n
  (def public (pk/generate :ecdh :private))\n
  (pk/key-agreement private public)\n
  \n
  Returns a byte string\n
  \n
  Note: The return value should be used with a key derivation
  function as found in the janetls/kdf module, refer to the
  protocol specification on correct use of key agreement.\n
  \n
  Note: Although this API tolerates :ecdsa keys, keys used for sign
  and verify operations should not be reused for key agreement.
  "
  [private public]
  (only-type :ecdh (private :type) "cannot do key agreement")
  (only-type :ecdh (private :type) "cannot do key agreement")
  (def priv (private :key))
  (def pub (public :key))
  (ecdh/compute priv pub)
  )

(defn pk/digest
  "Retrieves the digest used for signatures on this private key"
  [key]
  (:digest (key :key)))

(defn pk/version
  "Retrieves the internal version attached to the key, for rsa,
  values may be :pkcs1-v1.5.
  Otherwise returns nil.
  "
  [key]
  (if (= :rsa (:type key)) (:version (key :key)))
  )

(defn pk/mask
  "Retrieves the mask generation function attached to the key,
  only applicable to :pkcs1-v2.1 rsa keys. Otherwise returns nil.
  "
  [key]
  (if (= :rsa (:type key)) (:mask (key :key)))
  )

(def- PK-Prototype @{
  :type :none
  :information-class :none
  :sign pk/sign
  :verify pk/verify
  :encrypt pk/encrypt
  :decrypt pk/decrypt
  :export-private pk/export-private
  :export-public pk/export-public
  :digest pk/digest
  :mask pk/mask
  :version pk/version
  :key-agreement pk/key-agreement
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


(defn- pk/asn1-to-components [asn1] (or
  (pk/match-pkcs1-private asn1)
  (pk/match-pkcs1-public asn1)
  (pk/match-pcks8-private asn1)
  (pk/match-pcks8-public asn1)
  (pk/match-sec1-private asn1)
  ))

(defn- pk/import-der [der] (do
  (def asn1 (asn1/decode der :eager-parse))
  (def components (pk/asn1-to-components asn1))
  (if (not components) (error "Could not decode DER into a known key type"))
  components
  ))
(defn- pk/import-pem [pem] (do
  (def pem (pem/decode pem))
  (if (not pem) (error "PEM could not be decoded"))
  (def [pem] pem)
  (def {:name name :body body} pem)
  (def asn1 (asn1/decode body :eager-parse))
  (def components (case name
    "RSA PRIVATE KEY" (pk/match-pkcs1-private asn1)
    "RSA PUBLIC KEY" (pk/match-pkcs1-public asn1)
    "PRIVATE KEY" (pk/match-pcks8-private asn1)
    "PUBLIC KEY" (pk/match-pcks8-public asn1)
    "EC PRIVATE KEY" (pk/match-sec1-private asn1)
    (errorf "Pem type %p not supported" name)
    ))
  (if (not components) (errorf "PEM %p did not match expected ASN.1 structure" name))
  components
  ))

(defn- pk/import-ecdh [components] (do
  (def {
    :curve-group curve-group
    :p public
    :d private
    :information-class information-class
    } components)
    (if (not information-class) (errorf "Expected an :information-class in components %p" components))
    (if (not curve-group) (errorf "Expected a :curve-group in components %p" components))
    (case information-class
      :public (ecp/import-point curve-group public)
      :private (ecp/import-keypair curve-group private)
      (errorf "Information class not the expected value, should be :public or :private but got %p" information-class)
      )
  ))

(defn pk/import
  "Import a private or public key.\n
  Supported types are RSA and ECDSA.\n
  This function accepts the component format, a table with
  {:type :rsa or :ecdsa} and raw components.
  To see the expected components, try (:export-private (rsa/generate)) and
  (:export-private (ecdsa/generate)), :export-public will give a reduced set
  of components used for the public key.\n
  This function also supports DER and PEM files, DER keys are binary, while
  PEM keys have a format like the example below.\n
  -----BEGIN <KEY TYPE>-----\n
  ...\n
  -----END <KEY TYPE------\n
  \n
  When importing a DER key, the type will be automatically deduced.\n
  When importing a PEM key, the type will be mapped by the <KEY TYPE> in the
  PEM header.\n
  \n
  Examples:\n
  (pk/import {:type :rsa :n ... :e  65537)}) - imports a RSA public key
  by components\n
  (pk/import (:export-private (rsa/generate))) - imports a generated RSA key,
  by components\n
  (pk/import {:type :ecdsa :curve-group :secp2561r :d \"...\"}) - imports
  an ECDSA secp2561r private key by components\n
  (pk/import {:der \"...\"}) - imports a DER key\n
  (pk/import {:pem \"...\"}) - imports a PEM key, only supports one PEM body
  within the input\n
  "
  [key]
  (def kind (key :type))
  # only used in der and pem
  (def body (or (key :der) (key :pem)))
  (if kind
    (case kind
      :rsa :rsa
      :ecdsa :ecdsa
      :ecdh :ecdh
      (errorf ":type %p is not supported" kind)))
  (def components (cond
    (key :pem) (pk/import-pem (key :pem))
    (key :der) (pk/import-der (key :der))
    key
    ))
  (def kind (if kind kind (components :type)))
  (if (not kind) (errorf "Could not determine type (%p) from components, see %p" kind components))
  # (printf "Components %p" components)
  (def imported (case kind
    :rsa (rsa/import components)
    :ecdsa (ecdsa/import components)
    :ecdh (pk/import-ecdh components)
    (errorf "Could not determine type, should be :rsa, :ecdsa, :der, or :pem but got %p" kind)
  ))
  (def information-class (if
    (cfunction? (imported :information-class))
    (:information-class imported)
    (imported :information-class)))
  (def result @{:key imported :type kind :information-class information-class})
  (if (= :rsa kind) (put result :version (:version imported)))
  (if (or
    (= :ecdsa kind)
    (= :ecdh kind))
    (put result :curve-group (:curve-group imported)))
  (table/setproto result PK-Prototype)
  )

(defn pk/wrap
  "Wrap a janetls rsa or ecdsa key. This is useful if you need to set other
  options, such as rsa version, digest type, mask generation function digest,
  etc.\n
  \n
  Examples:\n
  (pk/wrap (rsa/generate {:bits 2048 :version :pkcs1-v2.1
    :mgf1 :sha256 :digest :sha256}))
  (pk/wrap (ecp/generate :secp256r1) :ecdh)
  "
  [key &opt pk-type]
  (def key-type (type key))
  (def kind (if pk-type
    (case pk-type
      :rsa (if
        (= :janetls/rsa key-type)
        :rsa
        (errorf "Expected type should be :janetls/rsa but is %p" key-type))
      :ecdsa (if
        (= :janetls/ecdsa key-type)
        :ecdsa
        (errorf "Expected type should be :janetls/ecdsa but is %p" key-type))
      :ecdh (if
        (or (= :janetls/ecp/keypair key-type) (= :janetls/ecp/point key-type))
        :ecdh
        (errorf "Expected type should be :janetls/ecp/keypair or :janetls/ecp/point but is %p" key-type))
      (errorf "The type %p is not supported" pk-type))
    (case key-type
      :janetls/rsa :rsa
      :janetls/ecdsa :ecdsa
      (errorf "The key type could not be determined from the wrapped object %p
, consider using the optional parameter pk-type on the function pk/wrap" key-type)
    )))
  (def information-class (:information-class key))
  (def curve-group (if (= kind :ecdsa) (:curve-group key)))
  (def version (if (= kind :rsa) (:version key)))
  (def pk @{:key key :type kind :information-class information-class :curve-group curve-group :version version})
  (table/setproto pk PK-Prototype)
  )

(defn pk/unwrap
  "Unwrap the wrapped key (rsa, ecdsa) to the janetls object that backs this private key."
  [key]
  (key :key)
  )

# An enhancement may be to provide access to the other portions of the
# generation functions.
# For example, rsa has versions, digests, mask generation function in a tables.
# ECDSA has a digest as an additional option.

(defn pk/generate
  "Generate a private keypair. By default will generate an RSA 2048 key.\n
  When generating an ECDSA key, by default the curve :secp256r1 will be used.\n
  When generating an ECDH key, by default the curve :secp256r1 will be used.\n
  \n
  Examples:\n
  (pk/generate)\n
  (pk/generate :rsa)\n
  (pk/generate :rsa 4096) - note the bit size is a parameter\n
  (pk/generate :ecdsa)\n
  (pk/generate :ecdsa :secp521r1) - note the curve group is a parameter\n
  (pk/generate :ecdh)\n
  (pk/generate :ecdh :secp521r1) - note the curve group is a parameter\n
  available curve options are enumerated in (ecp/curve-groups).
  "
  [&opt kind option]
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
    :ecdh (do
      (default option :secp256r1)
      (pk/wrap (ecp/generate option) :ecdh)
      )
    (errorf "Expected :rsa or :ecdsa but got %p" kind)
    ))
