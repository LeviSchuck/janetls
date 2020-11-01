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

(def cipher/ciphers
  "Struct of available ciphers and metadata of what is accepted"
  {
  :aes-gcm {
    :aead true
    :key-sizes [128 192 256]
    :iv-minimum 1 :iv-maximum 16384
    :algorithm :aes :mode :gcm
    }
  :aes-cbc {
    :aead false
    :key-sizes [128 192 256]
    :iv-minimum 16 :iv-maximum 16
    :algorithm :aes
    :mode :cbc
    }
  :aes-ebc {
    :aead false
    :key-sizes [128 192 256]
    :iv-minimum 0 :iv-maximum 0
    :algorithm :aes
    :mode :ebc
    }
  :aes-ctr {
    :aead false
    :key-sizes [128 192 256]
    :iv-minimum 16 :iv-maximum 16
    :algorithm :aes :mode :ctr
    }
  :chacha20 {
    :aead false
    :key-sizes [256]
    :iv-minimum 12
    :iv-maximum 12
    :algorithm :chacha20 :mode :stream
    }
  :chacha20-poly1305 {
    :aead true
    :key-sizes [256]
    :iv-minimum 12 :iv-maximum 12
    :algorithm :chacha20 :mode :chacha20-poly1305
    }
  })
(defn- dummy-none [&opt _] :none)
(defn- dummy-nil [&opt _ _] nil)
#
(defn cipher/start
  "
  TODO
  "
  [cipher operation &opt key iv ad] (do
  (default cipher :chacha20-poly1305)
  (def cipher-data (get cipher/ciphers cipher))

  (if (not cipher-data) (errorf "The cipher %p is unknown, review janetls/cipher/ciphers" cipher))
  (case operation
    :encrypt nil
    :decrypt nil
    (errorf "The operation %p was not expected, only :encrypt and :decrypt are supported" cipher))
  (def {
    :iv-minimum iv-minimum
    :iv-maximum iv-maximum
    :aead aead
    :key-sizes key-sizes
    :algorithm algorithm
    :mode mode
    } cipher-data)
  # Check that additional data is only supplied on AEAD supported ciphers
  (if (and ad (not aead)) (errorf "The cipher %p does not support additional data"))
  # Check that during decryption required (but seemingly optional) parameters are included
  (if (= :decryption operation) (do
    (if (not key) (error "A key is required when using the :decryption operation"))
    (if (and (not iv) (not= 0 iv-minimum)) (error "An iv or nonce is required when using the :decryption operation"))
    ))
  # Check that the IV is of proper length
  (if iv (do
    (def iv-len (length iv))
    (if (and (= 0 iv-minimum) (= 0 iv-maximum) (not= 0 iv-len))
      (errorf "The cipher %p does not support an iv or nonce" cipher))
    (if (or (< iv-len iv-minimum) (> iv-len iv-maximum))
      (if (= iv-minimum iv-maximum)
        (errorf "The cipher %p requires an iv or nonce with the length of %p bytes" cipher iv-minimum)
        (errorf "The cipher %p requires an iv or nonce with the length between (inclusive) of %p to %p bytes" cipher iv-minimum iv-maximum)
      ))
    ))
  # Check that the key is present and has a length that matches the expected key size
  (if key (do
    (def key-bits (* 8 (length key)))
    (if (not (reduce (fn [a b] (or a (= key-bits b))) nil key-sizes))
      (errorf "The key has a size of %p bits, however the cipher %p only supports the following key sizes: %p" key-bits cipher key-sizes))
    ))
  # Finally start the respective cipher
  (def cipher-object (match [algorithm mode]
    [:aes :gcm] (gcm/start operation key iv ad)
    [:aes :cbc] (aes/start operation :cbc :pkcs7 key iv)
    [:aes mode] (aes/start operation mode key iv)
    [:chacha20 :stream] (chacha/start operation key iv)
    [:chacha20 :chacha20-poly1305] (chachapoly/start operation key iv ad)
    _ (errorf "An internal error has occurred, unsupported cipher %p" cipher)
    ))
  (def [update-fn finish-fn key-fn iv-fn tag-fn ad-fn padding-fn] (match [algorithm mode]
    [:aes :gcm] [gcm/update gcm/finish gcm/key gcm/iv gcm/tag gcm/ad dummy-none]
    [:aes mode] [aes/update aes/finish aes/key aes/iv dummy-nil dummy-nil aes/padding]
    [:chacha20 :stream] [chacha/update chacha/finish chacha/key chacha/nonce dummy-nil dummy-nil dummy-none]
    [:chacha20 :chacha20-poly1305] [chachapoly/update chachapoly/finish chachapoly/key chachapoly/nonce chachapoly/tag chachapoly/ad dummy-nil]
    _ (errorf "An internal error has occurred, unsupported cipher %p" cipher)
    ))
  @{
    :update (fn [_ data &opt buf] (update-fn cipher-object data buf))
    :finish (fn [_ &opt buf] (finish-fn cipher-object buf))
    :key (fn [_] (key-fn cipher-object))
    :iv (fn [_] (iv-fn cipher-object))
    :nonce (fn [_] (iv-fn cipher-object))
    :tag (fn [_ &opt tag] (tag-fn cipher-object ;(if tag [tag] [])))
    :ad (fn [_] (ad-fn cipher-object))
    :padding (padding-fn cipher-object)
    :operation operation
    :algorithm algorithm
    :mode mode
    :aead aead
    :cipher cipher
    :key-bits (* 8 (if
      (and key (> 0 (length key)))
      (length key)
      (length (key-fn cipher-object))
      ))
    }
  ))
#
(defn cipher/update [object data &opt buf] (:update object data ;(if buf [buf] [])))
(defn cipher/finish [object &opt buf] (:finish object ;(if buf [buf] [])))
(defn cipher/key [object] (:key object))
(defn cipher/iv [object] (:iv object))
(defn cipher/nonce [object] (:nonce object))
(defn cipher/ad [object] (:ad object))
(defn cipher/tag [object &opt tag] (:tag object ;(if tag [tag] [])))
(defn cipher/padding [object] (get object :padding))
(defn cipher/operation [object] (get object :operation))
(defn cipher/algorithm [object] (get object :algorithm))
(defn cipher/mode [object] (get object :mode))
(defn cipher/key-bits [object] (get object :key-bits))
(defn cipher/aead [object] (get object :aead))

(defn cipher/encrypt [cipher key iv ad plaintext] (do
  (def result (buffer))
  (def object (cipher/start cipher :encrypt key iv ad))
  (:update object plaintext result)
  (:finish object result)
  [result (:tag object)]
  ))

(defn cipher/new-encrypt [cipher ad plaintext] (do
  (def object (cipher/start cipher :encrypt nil nil ad))
  (def result (buffer))
  (:update object plaintext result)
  (:finish object result)
  [(object :cipher) (:key object) (:iv object) result (:tag object)]
  ))

(defn cipher/decrypt [cipher key iv ad ciphertext tag] (do
  (def result (buffer))
  (def object (cipher/start cipher :decrypt key iv ad))
  (if (and (object :aead) (or (not tag) (and tag (= 0 (length tag)))))
    (error "A tag must be provided to decrypt an AEAD cipher"))
  (:update object ciphertext result)
  (:finish object result)
  # Return result if the tag matches
  (if (object :aead)
    (if (:tag object tag) result)
    result)
  ))

