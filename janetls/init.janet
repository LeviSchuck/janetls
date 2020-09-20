(import ../build/janetls_native :prefix "" :export true)

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
  :pem-headers (? (* (constant :headers) (cmt (some (* :pem-header-pair "\n")) ,struct) "\n"))
  :pem-body (* :pem-headers :base64-body :s* :checksum)
  :main (cmt (* :pem-header :s* :pem-body :s* :pem-footer) ,struct)
  }))

(defn pem-parse [str] (do
  (def [result] (peg/match pem-grammar str))
  result
  ))
