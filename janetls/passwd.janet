# Copyright (c) 2021 Levi Schuck
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

(defn passwd/scrypt
  "The scrypt key derivation function is designed to be far more
  secure against hardware brute-force attacks than alternative
  functions such as PBKDF2 or bcrypt.\n
  This function is meant for use with storing and later validating
  passwords for authentication.\n
  \nExamples:\n
  (def pass (passwd/scrypt \"Password Here\"))\n
  (passwd/verify-scrypt pass \"Password Here\")\n
  \nTo set custom parameters such as general work factor :n,
  rounds :r usually 8, 
  or parallelism :p usually 1 (and won't actually be parallel),
  set them in a table or struct after the password.\n
  Additionally, a :salt can be provided or will be generated automatically
  based on the :salt-size usually 12.\n
  (passwd/scrypt \"Password Here\" {:n 65536 :r 16 :p 8 :salt-size 32})\n
  (passwd/scrypt \"Password Here\" {:n 1024 :r 8 :p 1 :salt \"salty\"})\n
  \n
  The output will look something like $scrypt$$...$<base64>$<base64>
  using the modular crypt format as specified by the
  Password Hashing Competition String format.
  "
  [password &opt options]
  (default options {})
  (def {:n n :r r :p p :length length :salt-size salt-size :salt salt} options)
  (default n 16384)
  (default r 8)
  (default p 1)
  (default length 64)
  (default salt-size 12)
  (def salt (if salt salt (util/random salt-size)))
  (def hash (kdf/scrypt password salt length n r p))
  
  # https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
  (string
    "$scrypt$$n=" n ",r=" r ",p=" p
    "$" (base64/encode salt :standard-unpadded)
    "$" (base64/encode hash :standard-unpadded)
    ))

(defn passwd/verify-scrypt
  "Verify scrypt password hashes.\n
  The parameters will be extracted from the input modular crypt format string (mcf)
  and verified against input password.\n
  \nExamples:\n
  (def pass (passwd/scrypt \"Password Here\"))\n
  (passwd/verify-scrypt pass \"Password Here\")\n
  \n
  Will return true on success, otherwise false
  "
  [mcf password]
  (var n 16384)
  (var r 8)
  (var p 1)
  (var salt-size 12)

  (def [_ alg _ options salt hash] (string/split "$" mcf))
  (unless (= "scrypt" alg) (errorf "This function can only verify scrypt passwords"))
  (each opt (string/split "," options)
    (match (string/split "=" opt)
      ["n" optN] (set n (scan-number optN))
      ["r" optR] (set r (scan-number optR))
      ["p" optP] (set p (scan-number optP))
    ))
  (def salt (base64/decode salt))
  (def hash (base64/decode hash))
  (def length (length hash))
  (def expected (kdf/scrypt password salt length n r p))
  (constant= hash expected))
