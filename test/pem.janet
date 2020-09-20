(import testament :prefix "" :exit true)
# Testament framework documentation
# https://github.com/pyrmont/testament/blob/master/api.md
(import ../janetls :exit true :prefix "")

(def ec-key "
-----BEGIN PUBLIC KEY-----\n
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEly/EM+lE5907zBNwYy2QQ6UVKQC0\n
wEYF/pxNtkoMO4CzC+XtZWhRVMsgtfPaOgcCb5EamDXYV68Ius9v7VZ9jQ==\n
-----END PUBLIC KEY-----
")

(def pgp-example "
-----BEGIN PGP SIGNATURE-----\n
Version: GnuPG v0.9.7 (GNU/Linux)\n
Comment: For info see http://www.gnupg.org\n
\n
iEYEARECAAYFAjdYCQoACgkQJ9S6ULt1dqz6IwCfQ7wP6i/i8HhbcOSKF4ELyQB1\n
oCoAoOuqpRqEzr4kOkQqHRLE/b8/Rw2k\n
=y6kj\n
-----END PGP SIGNATURE-----
")

(def combined (string
  "Comments outside\n"
  ec-key
  "Comments in between\nMore comments\n"
  pgp-example
  "\nComments after\n\n\n"
  ))

(def expected-ec-key {
  :name "PUBLIC KEY"
  :body "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEly/EM+lE5907zBNwYy2QQ6UVKQC0\nwEYF/pxNtkoMO4CzC+XtZWhRVMsgtfPaOgcCb5EamDXYV68Ius9v7VZ9jQ=="
  })


(def expected-pgp-example {
  :name "PGP SIGNATURE"
  :headers {
    "Version" "GnuPG v0.9.7 (GNU/Linux)"
    "Comment" "For info see http://www.gnupg.org"
    }
  :body "iEYEARECAAYFAjdYCQoACgkQJ9S6ULt1dqz6IwCfQ7wP6i/i8HhbcOSKF4ELyQB1\noCoAoOuqpRqEzr4kOkQqHRLE/b8/Rw2k"
  :checksum "=y6kj"
  })

(deftest "Examples parse as expected" (do
  (is (= [expected-ec-key] (pem/parse ec-key)))
  (is (= [expected-pgp-example] (pem/parse pgp-example)))
  (is (= [expected-ec-key expected-pgp-example] (pem/parse combined)))
  ))

(run-tests!)
