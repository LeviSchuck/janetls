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

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# U T I L I T Y
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


(defn- normalize-oid [oid] (if (indexed? oid) (string/join (map string oid) ".") oid))

(defn- flip-map [m] (freeze (invert m)))

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# M A P S
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


(def- to-digest {
  "1.2.840.113549.2.5" :md5
  "1.2.840.113549.2.5" :sha1
  "2.16.840.1.101.3.4.2.4" :sha224
  "2.16.840.1.101.3.4.2.1" :sha256
  "2.16.840.1.101.3.4.2.2" :sha384
  "2.16.840.1.101.3.4.2.3" :sha512
  # sha3 is in the same collection as sha256 2.16.840.1.101.3.4.2.x
})

(def- from-digest (flip-map to-digest))

(def- to-curve {
  "1.2.840.10045.3.1.1" :secp192r1
  "1.3.132.0.33" :secp224r1
  "1.2.840.10045.3.1.7" :secp256r1
  "1.3.132.0.34" :secp384r1
  "1.3.132.0.35" :secp521r1
  "1.3.36.3.3.2.8.1.1.7" :bp256r1
  "1.3.36.3.3.2.8.1.1.11" :bp384r1
  "1.3.36.3.3.2.8.1.1.13" :bp512r1
  "1.3.101.110" :x25519
  "1.3.101.111" :x448
  "1.3.101.112" :ed25519
  "1.3.101.113" :ed448
  "1.3.132.0.31" :secp192k1
  "1.3.132.0.32" :secp224k1
  "1.3.132.0.10" :secp256k1
})

(def- from-curve (flip-map to-curve))


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# P U B L I C
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

(defn oid/to-curve [oid] (to-curve (normalize-oid oid)))
(defn oid/from-curve [curve] (from-curve curve))

(defn oid/to-digest [oid] (to-digest (normalize-oid oid)))
(defn oid/from-digest [digest] (from-digest digest))
