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
  Create a new cipher object, this wraps the underlying algorithm
  and provides a unified interface to authenticated and unauthenticated
  ciphers.\n
  \n
  For authenticated ciphers, a restriction is that the associated additional
  data must be known anead of time.
  Further, to correctly use a cipher object, during encryption the tag must
  be retrieved after finishing, during decryption, the tag must be compared
  to the tag emitted during encryption. Consequently, when the tag comparison
  fails, the plaintext decrypted should not be used.\n
  \n
  This function takes an operation parameter, which is to encrypt or decrypt.
  \n
  For encryption and decryption, a series of :update calls are made, followed
  by a :finish call. Each call should supply a buffer. Only after the :finish
  call is performed is the ciphertext complete. Note that input to :update
  calls be buffered, ideally the same buffer is reused across calls to produce
  a coherent ciphertext.\n
  \n
  The cipher should be a keyword as seen in the struct provided by
  janetls/cipher/ciphers. If nil, the cipher :chacha20-poly1305 will be used.\n
  \n
  The key should have a bit length suitable for the cipher, when nil and the
  operation is :encrypt, then a new key will be generated automatically.
  This key should then be retrieved by the :key function.\n
  \n
  The iv (or nonce) may be provided for encryption, but unless verifying a
  known vector or implementing a higher level protocol, the iv (or nonce)
  should be nil for encryption.
  An iv (or nonce) will be generated automatically.
  An iv (or nonce) must be provided for decryption when the cipher
  uses an iv or nonce.\n
  \n
  The parameter ad may be may be nil, or \"\", or a populated string or buffer.
  When the cipher is not authenticated, ad must be nil and the tag value
  returned is nil.
  \n
  Examples:\n
  (def key (hex/decode \"00000000000000000000000000000000\"))\n
  (def cipher (cipher/start :aes-cbc :encrypt key nil nil))\n
  (def ciphertext (buffer))\n
  > @{:cipher :aes-cbc ... }\n
  (:update cipher \"hello\" ciphertext)\n
  > @\"\"\n
  (:update cipher \" \" ciphertext)\n
  > @\"\"\n
  (:update cipher \"world\" ciphertext)\n
  > @\"\"\n
  (:update cipher \"1234567890\" ciphertext)\n
  > @\"...\"\n
  (:finish cipher ciphertext)\n
  > @\"......\"\n
  \n
  (def key (hex/decode \"00000000000000000000000000000000\"))\n
  (def cipher (cipher/start :aes-ctr :encrypt key nil nil))\n
  (def ciphertext (buffer))\n
  > @{:cipher :aes-ctr ... }\n
  (:update cipher \"hello\" ciphertext)\n
  > @\".....\"\n
  (:update cipher \" \" ciphertext)\n
  > @\"......\"\n
  (:update cipher \"world\" ciphertext)\n
  > @\"...........\"\n
  (:finish cipher ciphertext)\n
  > @\"...........\"\n
  (def decipher (cipher/start :aes-ctr :decrypt key (:iv cipher) nil))\n
  (def plaintext (buffer))\n
  (:update decipher (buffer/slice ciphertext 0 3) plaintext)\n
  > @\"hel\"\n
  (:update decipher (buffer/slice ciphertext 3 8) plaintext)\n
  > @\"hello wo\"\n
  (:update decipher (buffer/slice ciphertext 8) plaintext)\n
  > @\"hello world\"\n
  (:finish decipher plaintext)\n
  > @\"hello world\"\n
  \n
  (def key (hex/decode \"00000000000000000000000000000000\"))\n
  (def ad \"data\")\n
  (def cipher (cipher/start :aes-gcm :encrypt key nil ad))\n
  (def ciphertext (buffer))\n
  (:update cipher \"hello world\" ciphertext)\n
  > @\"\"\n
  (:finish cipher ciphertext)\n
  > @\"...\"\n
  (def tag (:tag cipher))\n
  > @\"...\"\n
  (def decipher (cipher/start :aes-ctr :decrypt key (:iv cipher) ad))\n
  (def plaintext (buffer))\n
  (:update decipher ciphertext plaintext)\n
  > @\"\"\n
  (:finish decipher plaintext)\n
  > @\"hello world\"\n
  (:tag decipher tag)\n
  > true\n
  \n
  Returns a cipher object ready to process plaintext or ciphertext.
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
  (if (and ad (not aead)) (errorf "The cipher %p does not support additional data" cipher))
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
(defn cipher/update
  "Update the cipher with additional plaintext or ciphertext
  (depending on the operation). This may be called multiple times.
  It is not guaranteed that the output will be equal in length as the input
  due to internal buffering on some ciphers.\n
  \n
  It is recommended to use a single buffer for encrypting or decrypting,
  if a buffer is not supplied, a new buffer will be allocated and returned.\n
  \n
  Note that cipher/finish must be called to get the last block of plaintext or
  ciphertext, and to calculate the tag (if AEAD).\n
  \n
  Additional Associated Data (AAD or AD) must be passed during cipher/start
  and cannot be fed iteratively through update.
  \n
  Examples:\n
  (def key (hex/decode \"00000000000000000000000000000000\"))\n
  (def cipher (cipher/start :aes-cbc :encrypt key nil nil))\n
  (def ciphertext (buffer))\n
  > @{:cipher :aes-cbc ... }\n
  (:update cipher \"hello\" ciphertext)\n
  > @\"\"\n
  (:update cipher \" \" ciphertext)\n
  > @\"\"\n
  (:update cipher \"world\" ciphertext)\n
  > @\"\"\n
  (:finish cipher ciphertext)\n
  > @\"...\"\n
  \n
  Returns the input buffer or a new buffer with the processed data
  "
  [object data &opt buf] (:update object data ;(if buf [buf] [])))
(defn cipher/finish
  "Finish the cipher's process and return the final block of ciphertext or
  plaintext, also calculate the tag if aead.\n
  This must be called to properly process an encryption or decryption
  operation.\n
  \n
  Examples:\n
  (def key (hex/decode \"00000000000000000000000000000000\"))\n
  (def cipher (cipher/start :aes-cbc :encrypt key nil nil))\n
  (def ciphertext (buffer))\n
  > @{:cipher :aes-cbc ... }\n
  (:update cipher \"hello world\" ciphertext)\n
  > @\"\"\n
  (:finish cipher ciphertext)\n
  > @\"...\"\n
  \n
  Returns the input buffer or a new buffer with the processed data
  "
  [object &opt buf] (:finish object ;(if buf [buf] [])))
(defn cipher/key
  "Returns the key material used on this cipher, treat this carefully."
  [object] (:key object))
(defn cipher/iv
  "Returns the IV used on this cipher, this must be provided with the
  ciphertext for decryption to be possible. This is the same as cipher/nonce."
  [object] (:iv object))
(defn cipher/nonce
  "Returns the nonce used on this cipher, this must be provided with the
  ciphertext for decryption to be possible. This is the same as cipher/iv."
  [object] (:nonce object))
(defn cipher/ad
  "Returns the additional associated data used on this cipher, 
  please review AEAD encryption on how to properly communicate this data
  or derive this data."
  [object] (:ad object))
(defn cipher/tag
  "Either fetches the authentication tag from a finished cipher
  context or compares the input tag with the authentication tag calculated
  from a decrypted ciphertext.\n
  Note that a tag only applies if the cipher is an AEAD cipher, this may be
  determined by (cipher/aead cipher-object-here).\n
  This functionality must be used to correctly use AEAD ciphers.
  The plaintext should not be processed until the authentication tag is
  verified.\n
  Inputs:\n
  object - cipher object\n
  tag - optional, an authentication tag to verify\n
  When a tag is not provided, the tag is returned if the cipher
  context is not finished.
  Otherwise it will return nil when there is no
  authentication tag.\n
  When a tag is provided, true is returned when the input tag matches
  the calculated authentication tag in constant time. Otherwise false is
  returned.\n
  For GCM, the tag length may vary between 4 to 16 bytes,
  but for chacha20-poly1305 the tag length must be 16 bytes.
  "
  [object &opt tag] (:tag object ;(if tag [tag] [])))
(defn cipher/padding
  "Returns the padding, for unpadded ciphers, :none will be returned.
  CBC will likely return :pkcs7."
  [object] (get object :padding))
(defn cipher/operation
  "Returns which operation this cipher is operating, be it :encrypt or 
  :decrypt"
  [object] (get object :operation))
(defn cipher/algorithm
  "Returns the algorithm this cipher is operating, values may be
  :aes or :chacha20"
  [object] (get object :algorithm))
(defn cipher/mode
  "Returns the mode this cipher is operating, values are specific to the
  algorithm. AES may be :cbc, :ctr, :gcm; while Chacha20 may be :stream
  or :chacha20-poly1305."
  [object] (get object :mode))
(defn cipher/key-bits
  "Returns the key bit count for this cipher, for example, an AES key with 32
  bytes of key material would be AES 256, thus the return value is 256.
  "
  [object] (get object :key-bits))
(defn cipher/aead
  "Returns true if the cipher is an AEAD cipher, such as :aes-gcm 
  or :chacha20-poly1305."
  [object] (get object :aead))
(defn cipher/cipher
  "Returns the cipher keyword associated with this cipher object.
  Available ciphers (by key) and their meta data (values) can be observed in
  janetls/cipher/ciphers
  "
  [object] (get object :cipher))

(defn cipher/encrypt
  "
  Encrypt a plaintext with a known key, an iv or nonce is supplied
  automatically when nil (recommended).
  Supports both authenticated ciphers and unauthenticated ciphers.\n
  \n
  Note that for authenticated ciphers, ad may be may be nil, or \"\", or
  a populated string or buffer.
  When the cipher is not authenticated, ad must be nil and the tag value
  returned is nil.
  \n
  For proper usage, it is recommended to supply nil for the iv or nonce.\n
  Only provide an iv or nonce if testing a known vector or implementing a
  higher level protocol which involves a predetermined iv or nonce.\n
  \n
  Examples:\n
  (def key (hex/decode \"00000000000000000000000000000000\"))\n
  (def [iv ciphertext tag] (cipher/encrypt :aes-gcm key nil nil \"hello world\"))\n
  > [\"...\" @\"...\" \"...\"]\n
  (cipher/decrypt :aes-gcm key iv nil ciphertext tag)
  > @\"hello world\"\n
  \n
  Returns a tuple of the [iv ciphertext tag]
  "
  [cipher key iv ad plaintext] (do
  (if (not cipher) (error "A cipher is required"))
  (if (or (not key) (= 0 (length key))) (error "A key is required"))
  (def result (buffer))
  (def object (cipher/start cipher :encrypt key iv ad))
  (:update object plaintext result)
  (:finish object result)
  [(:iv object) result (:tag object)]
  ))

(defn cipher/new-encrypt
  "
  Quickly encrypt a ciphertext, supports both authenticated ciphers
  and unauthenticated ciphers.\n
  \n
  Note that for authenticated ciphers, ad may be nil, or \"\", or a populated
  string or buffer.
  When the cipher is not authenticated, ad must be nil and the tag value
  returned is nil.
  \n
  Examples:\n
  (def [cipher key nonce ciphertext tag] (cipher/new-encrypt nil nil \"hello world\"))\n
  > [:chacha20-poly1305 \"...\" \"...\" @\"...\" \"...\"]\n
  (def [cipher key nonce ciphertext tag] (cipher/new-encrypt :aes-ctr nil \"hello world\"))\n
  > [:aes-ctr \"...\" \"...\" @\"...\" nil]\n
  \n
  Returns a tuple of [cipher key nonce ciphertext tag]
  "
  [cipher ad plaintext] (do
  (def object (cipher/start cipher :encrypt nil nil ad))
  (def result (buffer))
  (:update object plaintext result)
  (:finish object result)
  [(object :cipher) (:key object) (:iv object) result (:tag object)]
  ))

(defn cipher/decrypt
  "
  Decrypt a ciphertext, supports both authenticated ciphers
  and unauthenticated ciphers.\n
  \n
  Note that for authenticated ciphers, ad may be nil, or \"\", or a populated
  string or buffer; but there will always be a tag.
  The tag will be checked automatically prior to returning the plaintext.\n
  \n
  Examples:\n
  (def [cipher key nonce ciphertext tag] (cipher/new-encrypt nil nil \"hello world\"))\n
  (cipher/decrypt cipher key nonce nil ciphertext tag)\n
  > @\"hello world\"
  \n
  (def additional-data \"associated additional data\")\n
  (def [cipher key nonce ciphertext tag] (cipher/new-encrypt :aes-gcm additional-data \"hello world\"))\n
  (cipher/decrypt cipher key nonce additional-data ciphertext tag)
  > @\"hello world\"\n
  \n
  Returns a buffer of the output plaintext or nil upon authentication failure
  "
  [cipher key iv ad ciphertext &opt tag]
  (do
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

