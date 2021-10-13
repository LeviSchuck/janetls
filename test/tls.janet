(import testament :prefix "" :exit true)
# Testament framework documentation
# https://github.com/pyrmont/testament/blob/master/api.md
(import ../janetls :prefix "" :exit true)

(def cert-pem "-----BEGIN CERTIFICATE-----\n
MIICbjCCAfOgAwIBAgIQYvYybOXE42hcG2LdnC6dlTAKBggqhkjOPQQDAzB4MQswCQYDVQQGEwJF\n
UzERMA8GA1UECgwIRk5NVC1SQ00xDjAMBgNVBAsMBUNlcmVzMRgwFgYDVQRhDA9WQVRFUy1RMjgy\n
NjAwNEoxLDAqBgNVBAMMI0FDIFJBSVogRk5NVC1SQ00gU0VSVklET1JFUyBTRUdVUk9TMB4XDTE4\n
MTIyMDA5MzczM1oXDTQzMTIyMDA5MzczM1oweDELMAkGA1UEBhMCRVMxETAPBgNVBAoMCEZOTVQt\n
UkNNMQ4wDAYDVQQLDAVDZXJlczEYMBYGA1UEYQwPVkFURVMtUTI4MjYwMDRKMSwwKgYDVQQDDCNB\n
QyBSQUlaIEZOTVQtUkNNIFNFUlZJRE9SRVMgU0VHVVJPUzB2MBAGByqGSM49AgEGBSuBBAAiA2IA\n
BPa6V1PIyqvfNkpSIeSX0oNnnvBlUdBeh8dHsVnyV0ebAAKTRBdp20LHsbI6GA60XYyzZl2hNPk2\n
LEnb80b8s0RpRBNm/dfF/a82Tc4DTQdxz69qBdKiQ1oKUm8BA06Oi6NCMEAwDwYDVR0TAQH/BAUw\n
AwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFAG5L++/EYZg8k/QQW6rcx/n0m5JMAoGCCqG\n
SM49BAMDA2kAMGYCMQCuSuMrQMN0EfKVrRYj3k4MGuZdpSRea0R7/DjiT8ucRRcRTBQnJlU5dUoD\n
zBOQn5ICMQD6SmxgiHPz7riYYqnOK8LZiqZwMR2vsJRM60/G49HzYqc8/5MuB1xJAWdpEgJyv+c=\n
-----END CERTIFICATE-----")

(deftest "Simple Client Conf checks"
  (def cert-der (get-in (pem/decode cert-pem) [0 :body]))
  (def cert (x509/from cert-der))
  (def conf (tls/new-client-config :verify-optional cert :datagram))
  (is (not= nil conf))
  (is (= cert (:get-cert-chain conf)))
  (is (= cert (tls/get-cert-chain conf)))
  (is (= :verify-optional (:get-verify conf)))
  (is (= :verify-optional (tls/get-verify conf)))
  (is (= :datagram (:get-transport conf)))
  (is (= :datagram (tls/get-transport conf)))
  (is (= :client (:get-endpoint conf)))
  (is (= :client (tls/get-endpoint conf)))
  )

(run-tests!)
