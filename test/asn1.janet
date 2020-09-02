(import testament :prefix "" :exit true)
# Testament framework documentation
# https://github.com/pyrmont/testament/blob/master/api.md
(import ../build/janetls :exit true :prefix "")


(def five (bignum/parse 5))

(def silly-large-number (bignum/parse "10000000000000000000000000000055"))
(deftest "Decode Encode 127" (is (= silly-large-number (asn1/decode-127 (asn1/encode-127 silly-large-number)))))
(deftest "Encode 127 small is small" (is (= "\x05" (asn1/encode-127 5))))
(deftest "Encode 127 small is small" (is (= "\x05" (asn1/encode-127 (bignum/parse 5)))))
(deftest "Decode 127 small is small" (is (= five (asn1/decode-127 "\x05"))))
(deftest "Decode 127 small is small" (is (= 5 (asn1/decode-127 "\x05" :number))))

(deftest "Encode 127 medium is medium" (is (= "\x81\x01" (asn1/encode-127 129))))
(deftest "Decode 127 medium is medium" (is (= (bignum/parse 129) (asn1/decode-127 "\x81\x01"))))
(deftest "Decode 127 medium is medium" (is (= 129 (asn1/decode-127 "\x81\x01" :number))))
(deftest "Decode 127 medium is medium" (is (= (int/u64 129) (asn1/decode-127 "\x81\x01" :u64))))

(deftest "Fails on overflow number" (assert-thrown (asn1/decode-127 "100000000000000000000" :number)))
(deftest "Fails on overflow u64" (assert-thrown (asn1/decode-127 "100000000000000000000" :u64)))

# EC keys are soooo much smaller.. for the same level of protection.
(def ec-key (base64/decode
"MHcCAQEEIH4et747bbOv+eLWNSW01tr9zuYSYGSjBT6T4NTpNTLYoAoGCCqGSM4
9AwEHoUQDQgAEly/EM+lE5907zBNwYy2QQ6UVKQC0wEYF/pxNtkoMO4CzC+XtZWh
RVMsgtfPaOgcCb5EamDXYV68Ius9v7VZ9jQ=="))
(def rsa-key (base64/decode
"MIICXAIBAAKBgQDkCGRwBG1j/WPjDO+nkQfKxhQDckktMjq9QBS7RUQ+Y5fFidp
rkztiC8Y/JWGEKC6Z5Au/9chZrx0DeSoleiKtdVFQUvjvrgrVsamztTbnH5fkFZo
X4lc/S0FgT3q9tys2k/nwY0jYvUO2EaBY2CnR/drdFS+iw+l0aIy9yxEQmQIDAQA
BAoGAfJpFX5xbte6I/VFdRyANtPSljPiPGd4/kJgKfAYuczTyguN/8ZZjNYEfk/O
2JIPcawTckskX8EGqxfIYYKArf7rzvlEQvXiFbN/znIOfgAL8JtB5bi5bO5PXUaq
piaAb5NQoZ+3O+T3etnxHORrpC7socZRtZIb9tQT2aLbHoDECQQDzgh3yBX0o998
Dl1aWi28kgZOhpSAqw6ZyWvwgC+qz69w9QXkT/E1Gxmfy9uex9z2DDR/nMTc1nt9
QkNtzrm4lAkEA77sK+DkUE8an+lZNFW8D5c/HsemVExOCF7VrZf1otTAP+Je9LAH
BXV6VvCQyGrkR6IbkAxLWRJvOIL6+fyhsZQJBANEIBzC06YX7kaOBjEDbHONXoCW
InB5ZqU5NMFVKJYWhmIO06nzvfl6c/qqgrLAmrtUKtTI/G0eaQ9TjJJ8fQ0kCQBr
BEx5UsGrslr6Xdw7XTuYM5Ep0uRBh8vjWZGADgfYGoSGrPY91urDC548Rsw3MbbU
3qKa3KXaKtNxurS/fwQkCQHeoIAy2aRltkFsaOfeghvX4kTQFAh7uLm+JV4xGrUU
sjtJfseYG44ETk8+m3AjwNq5jmkhif8YGeFBC8w0KdeQ="))

(def rsa-key-json [
  "0"
  "160130065517131389311344861145589848370959233533492526527506806257632158161956866978965544486311181725659944465317576320271788371253085185156632919863850842571131863281257875796540238614704909618203514071942012433027603660426789715885659507750104298441589289165587947230177847758528357237225001175279364804761"
  "65537"
  "87498936115995425219777695385579414071630088531179347047874425727330595174296006277121856563457126947794501903466556687142423567800543716765249881643107887406569600747691147845476270908413946726375439518363471726365722196132099739915474559437465871720080038409538888126644124566387840706409281081239119831089"
  "12753562913580676002895259500271898402544206790667077393749423242101594856648247715054754403773897078848798557211533428185806832271184534593610270414630437"
  "12555712203890595143785953649835791209355238040885108486586460178610354944973062521923553540271133019963216268396997582478915551886885508674180820622666853"
  "10947860634332082191294711521221546001958160819527113539184812438075461547603904969003011630796525655154732582077398226999666154537319369930990533484692297"
  "1401231045962674716292330515508780946720542762577378938170703110401088485398064898993680983162840333063932798069115771522205599073816021643391649328382217"
  "6266931931866644824710628140478842048413702666464486531757332339811743806283458293992494572738709008699929512988707435077157636665116508077025012168160740"
])
(def rsa-key-full {
  :value [
    {:value (bignum/parse "0") :type :integer}
    {:value (bignum/parse "160130065517131389311344861145589848370959233533492526527506806257632158161956866978965544486311181725659944465317576320271788371253085185156632919863850842571131863281257875796540238614704909618203514071942012433027603660426789715885659507750104298441589289165587947230177847758528357237225001175279364804761") :type :integer}
    {:value (bignum/parse "65537") :type :integer}
    {:value (bignum/parse "87498936115995425219777695385579414071630088531179347047874425727330595174296006277121856563457126947794501903466556687142423567800543716765249881643107887406569600747691147845476270908413946726375439518363471726365722196132099739915474559437465871720080038409538888126644124566387840706409281081239119831089") :type :integer}
    {:value (bignum/parse "12753562913580676002895259500271898402544206790667077393749423242101594856648247715054754403773897078848798557211533428185806832271184534593610270414630437") :type :integer}
    {:value (bignum/parse "12555712203890595143785953649835791209355238040885108486586460178610354944973062521923553540271133019963216268396997582478915551886885508674180820622666853") :type :integer}
    {:value (bignum/parse "10947860634332082191294711521221546001958160819527113539184812438075461547603904969003011630796525655154732582077398226999666154537319369930990533484692297") :type :integer}
    {:value (bignum/parse "1401231045962674716292330515508780946720542762577378938170703110401088485398064898993680983162840333063932798069115771522205599073816021643391649328382217") :type :integer}
    {:value (bignum/parse "6266931931866644824710628140478842048413702666464486531757332339811743806283458293992494572738709008699929512988707435077157636665116508077025012168160740") :type :integer}
  ]
  :type :sequence
})

(def ec-key-json [
  "1"
  {:value "fh63vjtts6_54tY1JbTW2v3O5hJgZKMFPpPg1Ok1Mtg=" :encoding :base64-url :type :octet-string}
  {:tag 0
    :value "1.2.840.10045.3.1.7"
    :type :context-specific
    :constructed true
    }
  {:tag 1
    :value {:value "BJcvxDPpROfdO8wTcGMtkEOlFSkAtMBGBf6cTbZKDDuAswvl7WVoUVTLILXz2joHAm-RGpg12FevCLrPb-1WfY0=" :type :bit-string :bits 520 :encoding :base64-url}
    :type :context-specific
    :constructed true
    }
])

(def ec-key-full {
  :value [
    {:value (bignum/parse "1") :type :integer}
    {:value "~\x1E\xB7\xBE;m\xB3\xAF\xF9\xE2\xD65%\xB4\xD6\xDA\xFD\xCE\xE6\x12`d\xA3\x05>\x93\xE0\xD4\xE952\xD8" :type :octet-string}
    {:tag 0
      :value [
        {:value [1 2 840 10045 3 1 7] :type :object-identifier}
      ]
      :type :context-specific
      :constructed true
    }
    {:tag 1 :value [
      {:bits 520 :value "\x04\x97/\xC43\xE9D\xE7\xDD;\xCC\x13pc-\x90C\xA5\x15)\0\xB4\xC0F\x05\xFE\x9CM\xB6J\f;\x80\xB3\v\xE5\xEDehQT\xCB \xB5\xF3\xDA:\x07\x02o\x91\x1A\x985\xD8W\xAF\x08\xBA\xCFo\xEDV}\x8D" :type :bit-string}
      ]
      :type :context-specific
      :constructed true
    }
  ]
  :type :sequence
})

# Test ASN1 Decode
(deftest "RSA key decode meets expectations" (is (= rsa-key-json (asn1/decode rsa-key :json))))
(deftest "EC key decode meets expectations" (is (= ec-key-json (asn1/decode ec-key :json))))
(deftest "RSA key decode meets expectations" (is (= rsa-key-full (asn1/decode rsa-key))))
(deftest "EC key decode meets expectations" (is (= ec-key-full (asn1/decode ec-key))))

(deftest "Encode EC key (json) gives same binary" (is (= ec-key (asn1/encode ec-key-json))))
(deftest "Encode RSA key (json) gives same binary" (is (= rsa-key (asn1/encode rsa-key-json))))
(deftest "Encode EC key gives same binary" (is (= ec-key (asn1/encode ec-key-full))))
(deftest "Encode RSA key gives same binary" (is (= rsa-key (asn1/encode rsa-key-full))))


(defn contains? [x s] (not (empty? (filter |(= x $0) s))))

(deftest "Types contains integer" (is (contains? :integer (asn1/types))))
(deftest "Types contains sequence" (is (contains? :sequence (asn1/types))))
(deftest "Types contains octet-string" (is (contains? :octet-string (asn1/types))))

(deftest "Classes contains universal" (is (contains? :universal (asn1/classes))))
(deftest "Classes contains context-specific" (is (contains? :context-specific (asn1/classes))))

(run-tests!)
