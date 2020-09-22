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

(defn- pk/options [&opt options]
  (default options {})
  (def {:encoding encoding :encoding-variant variant :digest digest} options)
  (default encoding :raw)
  {:encoding encoding :encoding-variant variant :digest digest}
  )

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
  ciphertext
  )
(defn pk/decrypt [{:key key :type kind} ciphertext &opt options]
  (only-type :rsa kind "can encrypt and decrypt")
  (def options (pk/options options))
  (def ciphertext (encoding/decode ciphertext (options :encoding ;(semi (options :encoding-variant)))))
  (def plaintext (:decrypt key ciphertext))
  plaintext
  )
(defn pk/export-public [] nil)
(defn pk/export-private [] nil)


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
