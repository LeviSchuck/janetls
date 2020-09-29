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
(import ./util :prefix "")

(def- pem-grammar (peg/compile ~{
  :header-name (some (choice (range "AZ" "az" "09") (set " #")))
  :base64 (choice (range "AZ" "az" "09") (set "+/"))
  :pem-header (* "-----BEGIN " (constant :name) (capture :header-name :block-name)  "-----")
  :pem-footer (drop (* "-----END " (cmt (* (-> :block-name) ':header-name) ,=) "-----"))
  :base64 (choice (range "AZ" "az" "09") (set "+/"))
  :base64-padding (any "=")
  :base64-line (* (some :base64))
  :base64-body (* (constant :body) (capture (* (some (* :s* :base64-line)) :base64-padding)))
  :checksum-content (capture (* (some "=") :base64-line))
  :checksum (? (* (constant :checksum) :checksum-content))
  :pem-header-label (capture (some (if-not (set "\n\r:") 1)))
  :pem-header-value (capture (some (if-not (set "\n\r") 1)))
  :pem-header-pair (* :pem-header-label ":" :s* :pem-header-value)
  :pem-headers (? (* (constant :headers) (cmt (some (* :pem-header-pair "\n")) ,table) "\n"))
  :pem-body (* :pem-headers :base64-body :s* :checksum)
  :single-pem (cmt (* :pem-header :s* :pem-body :s* :pem-footer) ,table)
  :comment (* (some (if-not "\n" 1)) (? "\n"))
  :single-pem-or-comment (choice :single-pem :comment)
  :main (any :single-pem-or-comment)
  }))

(defn- pem/base64-parse [pem] (merge pem {:body (base64/decode (get pem :body))}))

(defn pem/decode
  ``Decode a PEM body into an array of PEM tables, with the following content:
  :name - the PEM block's name, such as "EC PUBLIC KEY"
  :body - binary value of the PEM block, what is inside is not guaranteed to be valid binary, asn.1, etc.
  :headers - optional table of headers found in the PEM body
  :checksum - included checksum if present in PGP ascii-armor blocks, which are near identical to PEM.``
  [str]
  (def result (peg/match pem-grammar str))
  (def pems (if (= nil result) @[] [;result]))
  (freeze (map pem/base64-parse pems))
  )

(defn- pem/encode-header [[k v]] (buffer k ": " v))

(defn pem/encode
``Encode a PEM to a string, the input is a struct or table with the following fields
  :name - the PEM block's name, such as "EC PUBLIC KEY", required
  :body - binary value of the PEM block, it will be base64 encoded in the output
  :headers - optional table (string to string) of informational headers in a PEM block
  :checksum - optional string (a base64 like string starting with a =) for PGP

  The output is a buffer.
  ``
  [{:name name :body body :headers headers :checksum checksum}]
  (if (= nil name) (error ":name cannot be nil"))
  (if (= nil body) (error ":body cannot be nil"))
  (def pem-header (if headers (buffer (string/join (map pem/encode-header (pairs headers)) "\n") "\n\n")))
  (def ascii-armor-checksum (if checksum (buffer "\n" checksum)))
  (def pem-body (string/join (util/chunk (base64/encode body) 64) "\n"))
  (freeze (buffer "-----BEGIN " name "-----\n" pem-header pem-body ascii-armor-checksum "\n-----END " name "-----"))
  )
