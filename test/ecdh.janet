(import testament :prefix "" :exit true)
(import ../janetls :exit true :prefix "")

(setdyn :pretty-format "%.99N")

(run-tests!)
