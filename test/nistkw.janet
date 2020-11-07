
# https://tools.ietf.org/html/rfc3394
# https://tools.ietf.org/html/rfc5649
(import testament :prefix "" :exit true)
(import ../janetls :exit true :prefix "")

(setdyn :pretty-format "%.99N")

(run-tests!)
