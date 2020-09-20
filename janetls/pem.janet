(import ../build/janetls_native :prefix "")

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

(defn pem/parse
  ``Decode a PEM body into an array of pem tables, with the following content:
  :name - the pem block's name, such as 'EC PUBLIC KEY'
  :body - binary value of the pem block, what is inside is not guaranteed to be valid binary, asn.1, etc.
  :headers - optional table of headers found in the PEM body
  :checksum - included checksum if present in PGP ascii-armor blocks, which are near identical to PEM.``
  [str] (do
  (def result (peg/match pem-grammar str))
  (def pems (if (= nil result) @[] [;result]))
  (map pem/base64-parse pems)
  ))
