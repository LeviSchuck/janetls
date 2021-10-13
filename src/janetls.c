/*
 * Copyright (c) 2021 Levi Schuck
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "janetls.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/cipher.h"
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include "mbedtls/chacha20.h"
#include "mbedtls/nist_kw.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/ssl.h"

JANET_MODULE_ENTRY(JanetTable *env)
{
  submod_md(env);
  submod_util(env);
  submod_encoding(env);
  submod_bignum(env);
  submod_random(env);
  submod_byteslice(env);
  submod_asn1(env);
  submod_asn1(env);
  submod_rsa(env);
  submod_ecp(env);
  submod_ecdsa(env);
  submod_cipher(env);
  submod_aes(env);
  submod_chacha(env);
  submod_chachapoly(env);
  submod_gcm(env);
  submod_ecdh(env);
  submod_nistkw(env);
  submod_kdf(env);
  submod_x509(env);
  submod_tls(env);
}

const char * result_error_message(int result, uint8_t * unhandled)
{
  switch (result)
  {
    case 0:
      return "There is no error.";
    case MBEDTLS_ERR_MPI_NOT_ACCEPTABLE:
      return "MPI: The input value was not acceptable";
    case MBEDTLS_ERR_MPI_NEGATIVE_VALUE:
      return "MPI: An input value was negative when it cannot be";
    case MBEDTLS_ERR_MPI_INVALID_CHARACTER:
      return "MPI: Cannot parse, an invalid character was found";
    case MBEDTLS_ERR_MPI_DIVISION_BY_ZERO:
      return "MPI: Division by zero";
    case MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL:
      return "MPI: Allocated buffer is too small, this is an internal error";
    case MBEDTLS_ERR_MD_ALLOC_FAILED:
    case MBEDTLS_ERR_MPI_ALLOC_FAILED:
    case JANETLS_ERR_ALLOCATION_FAILED:
    case MBEDTLS_ERR_ECP_ALLOC_FAILED:
    case MBEDTLS_ERR_CIPHER_ALLOC_FAILED:
      return "Ran out of memory";
    case MBEDTLS_ERR_MD_BAD_INPUT_DATA:
    case MBEDTLS_ERR_MPI_BAD_INPUT_DATA:
      return "One of the inputs is bad";
    case MBEDTLS_ERR_MPI_FILE_IO_ERROR:
      return "File IO error with bignum";
    case MBEDTLS_ERR_MD_HW_ACCEL_FAILED:
      return "Unable to use hardware acceleration";
    case MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR:
    case MBEDTLS_ERR_MD_FILE_IO_ERROR:
      return "IO Error with file system";
    case MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE:
      return "Message Digest feature unavailable";
    case MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED:
      return "AES CTR: Unable to gather entropy for random number generation";
    case MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG:
      return "AES CTR: The input was too big";
    case MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG:
      return "AES CTR: Too many bytes were requested at once";
    case MBEDTLS_ERR_RSA_BAD_INPUT_DATA:
      return "RSA: bad input parameters";
    case MBEDTLS_ERR_RSA_INVALID_PADDING:
      return "RSA: Bad padding on the input data, don't let the client know";
    case MBEDTLS_ERR_RSA_KEY_GEN_FAILED:
      return "RSA: Could not generate key, something failed";
    case MBEDTLS_ERR_RSA_KEY_CHECK_FAILED:
      return "RSA: the key did not validate";
    case MBEDTLS_ERR_RSA_PUBLIC_FAILED:
      return "RSA: A public key operation failed";
    case MBEDTLS_ERR_RSA_PRIVATE_FAILED:
      return "RSA: A private key operation failed";
    case MBEDTLS_ERR_RSA_VERIFY_FAILED:
      return "RSA: PKCS#1 signature verification failed";
    case MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE:
      return "RSA: The output buffer for decryption is not large enough";
    case MBEDTLS_ERR_RSA_RNG_FAILED:
      return "RSA: The random generator used failed to generate non zero values";
    case MBEDTLS_ERR_ECP_BAD_INPUT_DATA:
      return "ECP: Input invalid";
    case MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL:
      return "ECP: Internal error, buffer too small";
    case MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE:
      return "ECP: Feature unavailable, maybe that function doesn't work for this curve group";
    case MBEDTLS_ERR_ECP_VERIFY_FAILED:
      return "ECP: Verification failed, the signature is not valid";
    case MBEDTLS_ERR_ECP_RANDOM_FAILED:
      return "ECP: Random number generator appears to be failing";
    case MBEDTLS_ERR_ECP_INVALID_KEY:
      return "ECP: Invalid public or private key";
    case MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH:
      return "ECP: The signature is the wrong length";
    case MBEDTLS_ERR_CIPHER_AUTH_FAILED:
      return "CIPHER: Auth tag failed";
    case MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA:
      return "CIPHER: Bad input data";
    case MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED:
      return "CIPHER: Full block expected";
    case MBEDTLS_ERR_CIPHER_INVALID_CONTEXT:
      return "CIPHER: Invalid context";
    case MBEDTLS_ERR_CIPHER_INVALID_PADDING:
      return "CIPHER: Invalid padding";
    case MBEDTLS_ERR_AES_BAD_INPUT_DATA:
      return "AES Bad input data";
    case MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH:
      return "AES: Invalid input length";
    case MBEDTLS_ERR_AES_INVALID_KEY_LENGTH:
      return "AES: Invalid key length";
    case MBEDTLS_ERR_GCM_AUTH_FAILED:
      return "GCM: Auth tag failed";
    case MBEDTLS_ERR_GCM_BAD_INPUT:
      return "GCM: Bad input data";
    case MBEDTLS_ERR_CHACHA20_BAD_INPUT_DATA:
      return "Chacha20: Bad input data";
    case MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE:
    case MBEDTLS_ERR_AES_FEATURE_UNAVAILABLE:
    case MBEDTLS_ERR_CHACHA20_FEATURE_UNAVAILABLE:
      return "CIPHER: Feature Unavailable";
    case MBEDTLS_ERR_CIPHER_HW_ACCEL_FAILED:
    case MBEDTLS_ERR_GCM_HW_ACCEL_FAILED:
    case MBEDTLS_ERR_AES_HW_ACCEL_FAILED:
    case MBEDTLS_ERR_CHACHA20_HW_ACCEL_FAILED:
      return "CIPHER: Hardware accelleration failure";
    case MBEDTLS_ERR_HKDF_BAD_INPUT_DATA:
      return "HKDF: Bad Input data";
    case MBEDTLS_ERR_PKCS5_BAD_INPUT_DATA:
      return "PKCS5: Bad Input data";
    case MBEDTLS_ERR_PKCS5_INVALID_FORMAT:
      return "PKCS5: Invalid ASN.1 header";
    case MBEDTLS_ERR_PKCS5_FEATURE_UNAVAILABLE:
      return "PKCS5: Feature unavailable";
    case MBEDTLS_ERR_PKCS5_PASSWORD_MISMATCH:
      return "PKCS5: Password mismatch";
    case MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE:
      return "X509: Feature Unavailable";
    case MBEDTLS_ERR_X509_UNKNOWN_OID:
      return "X509: Unknown OID";
    case MBEDTLS_ERR_X509_INVALID_FORMAT:
      return "X509: Invalid Format";
    case MBEDTLS_ERR_X509_INVALID_VERSION:
      return "X509: Invalid Version";
    case MBEDTLS_ERR_X509_INVALID_SERIAL:
      return "X509: Invalid Serial";
    case MBEDTLS_ERR_X509_INVALID_ALG:
      return "X509: Invalid Algorithm";
    case MBEDTLS_ERR_X509_INVALID_NAME:
      return "X509: Invalid Name";
    case MBEDTLS_ERR_X509_INVALID_DATE:
      return "X509: Invalid Date";
    case MBEDTLS_ERR_X509_INVALID_SIGNATURE:
      return "X509: Invalid signature";
    case MBEDTLS_ERR_X509_INVALID_EXTENSIONS:
      return "X509: Invalid Extensions";
    case MBEDTLS_ERR_X509_SIG_MISMATCH:
      return "X509: Signature mismatch";
    case MBEDTLS_ERR_X509_CERT_VERIFY_FAILED:
      return "X509: Certificate verify failed";
    case MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT:
      return "X509: Certificate unknown format";
    case MBEDTLS_ERR_X509_BAD_INPUT_DATA:
      return "X509: Bad Input data";
    case MBEDTLS_ERR_X509_ALLOC_FAILED:
      return "X509: Allocation Failed";
    case MBEDTLS_ERR_X509_FILE_IO_ERROR:
      return "X509: File IO Error";
    case MBEDTLS_ERR_X509_BUFFER_TOO_SMALL:
      return "X509: Buffer Too Small";
    case MBEDTLS_ERR_X509_FATAL_ERROR:
      return "X509: Fatal Error";
    case MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE:
      return "TLS: Feature Unavailable";
    case MBEDTLS_ERR_SSL_BAD_INPUT_DATA:
      return "TLS: Bad Input Data";
    case MBEDTLS_ERR_SSL_INVALID_MAC:
      return "TLS: Invalid MAC (Message Authentication Code)";
    case MBEDTLS_ERR_SSL_INVALID_RECORD:
      return "TLS: Invalid Record";
    case MBEDTLS_ERR_SSL_CONN_EOF:
      return "TLS: Connection End Of File";
    case MBEDTLS_ERR_SSL_UNKNOWN_CIPHER:
      return "TLS: Unknown Cipher";
    case MBEDTLS_ERR_SSL_NO_CIPHER_CHOSEN:
      return "TLS: No Cipher Chosen";
    case MBEDTLS_ERR_SSL_NO_RNG:
      return "TLS: No Random Found";
    case MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE:
      return "TLS: No Client Certificate";
    case MBEDTLS_ERR_SSL_CERTIFICATE_TOO_LARGE:
      return "TLS: Certificate too large";
    case MBEDTLS_ERR_SSL_CERTIFICATE_REQUIRED:
      return "TLS: Certificate Required";
    case MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED:
      return "TLS: Private Key Required";
    case MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED:
      return "TLS: Certificate Authority chain required";
    case MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE:
      return "TLS: Unexpected Message";
    case MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE:
      return "TLS: Fatal Alert Message";
    case MBEDTLS_ERR_SSL_PEER_VERIFY_FAILED:
      return "TLS: Peer Verify Failed";
    case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
      return "TLS: Peer Closing connection notification";
    case MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO:
      return "TLS: Bad Handshake Client Hello";
    case MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO:
      return "TLS: Bad Handshake Server Hello";
    case MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE:
      return "TLS: Bad Handshake certificate";
    case MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST:
      return "TLS: Bad Handshake Certificate request";
    case MBEDTLS_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE:
      return "TLS: Bad Handshake Server Key Exchange";
    case MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO_DONE:
      return "TLS: Bad Handshake Server Hello Done";
    case MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE:
      return "TLS: Bad Handshake Client Key Exchange";
    case MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_RP:
      return "TLS: Bad Handshake Client key exchange Read Public";
    case MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_CS:
      return "TLS: Bad Handshake Client key exchange Calculate Secret";
    case MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY:
      return "TLS: Bad Handshake Certificate verify failed";
    case MBEDTLS_ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC:
      return "TLS: Bad Handshake change cipher specification";
    case MBEDTLS_ERR_SSL_BAD_HS_FINISHED:
      return "TLS: Bad Handshake finished";
    case MBEDTLS_ERR_SSL_ALLOC_FAILED:
      return "TLS: Allocation failure";
    case MBEDTLS_ERR_SSL_HW_ACCEL_FAILED:
      return "TLS: Hardware accelleration failed";
    case MBEDTLS_ERR_SSL_HW_ACCEL_FALLTHROUGH:
      return "TLS: Hardware Accelleration Fallthrough";
    case MBEDTLS_ERR_SSL_COMPRESSION_FAILED:
      return "TLS: Compression Failed";
    case MBEDTLS_ERR_SSL_BAD_HS_PROTOCOL_VERSION:
      return "TLS: Bad Handshake protocol version";
    case MBEDTLS_ERR_SSL_BAD_HS_NEW_SESSION_TICKET:
      return "TLS: Bad Handshake new session ticket";
    case MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED:
      return "TLS: Session ticket expired";
    case MBEDTLS_ERR_SSL_PK_TYPE_MISMATCH:
      return "TLS: Public Key type mismatch";
    case MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY:
      return "TLS: Unknown Identity";
    case MBEDTLS_ERR_SSL_INTERNAL_ERROR:
      return "TLS: Internal Error";
    case MBEDTLS_ERR_SSL_COUNTER_WRAPPING:
      return "TLS: Counter Wrapped, too much data needs a new connection";
    case MBEDTLS_ERR_SSL_WAITING_SERVER_HELLO_RENEGO:
      return "TLS: Waiting Server Hello renegotiation";
    case MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED:
      return "TLS: Hello verify required";
    case MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL:
      return "TLS: Buffer too small";
    case MBEDTLS_ERR_SSL_NO_USABLE_CIPHERSUITE:
      return "TLS: No usable ciphersuite";
    case MBEDTLS_ERR_SSL_WANT_READ:
      return "TLS: Needs more data";
    case MBEDTLS_ERR_SSL_WANT_WRITE:
      return "TLS: Needs to write more data";
    case MBEDTLS_ERR_SSL_TIMEOUT:
      return "TLS: Timeout";
    case MBEDTLS_ERR_SSL_CLIENT_RECONNECT:
      return "TLS: Client Reconnect";
    case MBEDTLS_ERR_SSL_UNEXPECTED_RECORD:
      return "TLS: Unexpected Record";
    case MBEDTLS_ERR_SSL_NON_FATAL:
      return "TLS: Non Fatal error";
    case MBEDTLS_ERR_SSL_INVALID_VERIFY_HASH:
      return "TLS: Invalid verify hash";
    case MBEDTLS_ERR_SSL_CONTINUE_PROCESSING:
      return "TLS: Continue processing";
    case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
      return "TLS: Async In Progress";
    case MBEDTLS_ERR_SSL_EARLY_MESSAGE:
      return "TLS: Early Message";
    case MBEDTLS_ERR_SSL_UNEXPECTED_CID:
      return "TLS: An encrypted DTLS-frame with an unexpected CID was received";
    case MBEDTLS_ERR_SSL_VERSION_MISMATCH:
      return "TLS: Version mismatch";
    case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:
      return "TLS: Cryptography in progress";
    case MBEDTLS_ERR_SSL_BAD_CONFIG:
      return "TLS: Bad Configuration";
    // -------------- JANETLS ERRORS ------------------
    case JANETLS_ERR_ENCODING_INVALID_CHARACTER:
      return "Invalid character found during decoding";
    case JANETLS_ERR_ENCODING_INVALID_LENGTH:
      return "There are extra or missing characters in the encoded value";
    case JANETLS_ERR_ENCODING_INVALID_TYPE:
      return "Invalid encoding type";
    case JANETLS_ERR_MD_INVALID_INPUT_TYPE:
      return "Invalid input type, should be string or buffer";
    case JANETLS_ERR_MD_INVALID_ALGORITHM:
      return "Invalid algorithm";
    case JANETLS_ERR_CIPHER_INVALID_CIPHER:
      return "Invalid cipher";
    case JANETLS_ERR_CIPHER_INVALID_MODE:
      return "Invalid cipher mode";
    case JANETLS_ERR_CIPHER_INVALID_ALGORITHM:
      return "Invalid cipher algorithm";
    case JANETLS_ERR_CIPHER_INVALID_KEY_SIZE:
      return "Invalid cipher key size";
    case JANETLS_ERR_CIPHER_INVALID_IV_SIZE:
      return "Invalid IV / nonce size";
    case JANETLS_ERR_CIPHER_INVALID_STATE:
      return "Cipher is in a state where this operation cannot be performed";
    case JANETLS_ERR_CIPHER_INVALID_PADDING:
      return "Cipher padding is invalid";
    case JANETLS_ERR_CIPHER_INVALID_TAG_SIZE:
      return "Cipher tag size is different from what is requested, cannot get tag of this size";
    case JANETLS_ERR_CIPHER_INVALID_OPERATION:
      return "Cipher invalid operation, encrypt or decrypt is expected";
    case JANETLS_ERR_CIPHER_INVALID_DATA_SIZE:
      return "Cipher can only operate on a fixed size of data or the data is too large or too small.";
    case JANETLS_ERR_PADDING_INVALID_BLOCK:
      return "Invalid block while unpadding";
    case JANETLS_ERR_PADDING_BLOCK_FULL:
      return "The block is full and cannot be padded";
    case JANETLS_ERR_PADDING_INVALID_LENGTH:
      return "Invalid length during padding, can only pad lengths under the block size";
    case JANETLS_ERR_ASN1_INVALID_BIT_STRING_LENGTH:
      return "A bitstring had an invalid length while parsing";
    case JANETLS_ERR_ASN1_EMPTY_INPUT:
      return "Cannot operate on an empty ASN.1 document";
    case JANETLS_ERR_ASN1_OTHER:
      return "An internal error has occurred within ASN.1 parsing";
    case JANETLS_ERR_ASN1_INCOMPLETE:
      return "Expected more bytes while parsing ASN.1 document, but reached end of content";
    case JANETLS_ERR_ASN1_TEXT_PARSE_ERR:
      return "While decoding text, an invalid character was encountered";
    case JANETLS_ERR_ASN1_INVALID_ASN1_CLASS:
      return "Could not determine the ASN.1 class from tag byte, appears invalid";
    case JANETLS_ERR_ASN1_DATE_PARSE_ERROR:
      return "A date field could not be parsed correctly";
    case JANETLS_ERR_ASN1_LENGTH_TOO_LARGE:
      return "The length parsed on a tag is too large and is larger than the document";
    case JANETLS_ERR_ASN1_U64_OVERFLOW:
      return "The number could not fit in a u64, try a bignum instead";
    case JANETLS_ERR_ASN1_NUMBER_OVERFLOW:
      return "The number could not fit into a janet number, try a bignum instead";
    case JANETLS_ERR_ASN1_BOOLEAN_INVALID_LENGTH:
      return "Invalid boolean length, should be 1 byte";
    case JANETLS_ERR_ASN1_OBJECT_IDENTIFIER_INVALID_LENGTH:
      return "Invalid object identifier length, either too short, or overflowed";
    case JANETLS_ERR_ASN1_INVALID_OBJECT_IDENTIFIER:
      return "Invalid ASN.1 Object Identifier";
    case JANETLS_ERR_ASN1_NUMBER_WAS_FRACTIONAL:
      return "A number provided as an ASN.1 integer had a fractional value";
    case JANETLS_ERR_ASN1_MISSING_VALUE:
      return "Expected to find a value for :value in one of the structs or tables provided for ASN.1 encoding";
    case JANETLS_ERR_ASN1_INVALID_TAG:
      return "Invalid ASN.1 tag value";
    case JANETLS_ERR_ASN1_UNSUPPORTED_ENCODING:
      return "Unsupported encoding for a value provided for ASN.1 encoding";
    case JANETLS_ERR_ASN1_LENGTH_OVERFLOW:
      return "Length overflow occurred during ASN.1 encoding";
    case JANETLS_ERR_ASN1_UNSUPPORTED_TYPE:
      return "A value found during ASN.1 encoding could not be encoded, the type is not supported";
    case JANETLS_ERR_ASN1_INPUT_CANNOT_BE_DECODED:
      return "An ASN.1 input could not be decoded";
    case JANETLS_ERR_ASN1_INVALID_CONSTRUCTED_PARAMETER:
      return "The :constructed field had a non boolean value";
    case JANETLS_ERR_ASN1_INPUT_TYPE_MISSING:
      return "An input :type is necessary but was not provided during ASN.1 encoding";
    case JANETLS_ERR_ASN1_INVALID_INPUT_TYPE:
      return "An input type provided was not valid during ASN.1 encoding";
    case JANETLS_ERR_ASN1_INPUT_TYPE_NOT_IMPLEMENTED:
      return "The input type for an ASN.1 value is not implemented";
    case JANETLS_ERR_ASN1_INVALID_BITS:
      return "The input :bits is not numeric or contains a fraction";
    case JANETLS_ERR_INVALID_BOOLEAN_VALUE:
      return "The :type was :boolean, but the value was neither true nor false";
    case JANETLS_ERR_ASN1_INVALID_INTEGER:
      return "The :type was :integer, but the value was not a number or a bignum";
    case JANETLS_ERR_ASN1_INVALID_VALUE_TYPE:
      return "The input value type could not be used during ASN.1 encoding";
    case JANETLS_ERR_BIGNUM_COULD_NOT_CONVERT:
      return "Could not convert value to a bignum when an integer or bignum was expected";
    case JANETLS_ERR_SEARCH_OPTION_NOT_FOUND:
      return "The option input could not be matched";
    case JANETLS_ERR_SEARCH_OPTION_INPUT_INVALID_TYPE:
      return "Invalid input type for search option";
    case JANETLS_ERR_NOT_IMPLEMENTED:
      return "Not implemented";
  }
  *unhandled = 1;
  return "An internal error occurred";
}

void check_result(int result)
{
  if (result == 0)
  {
    return;
  }
  uint8_t unhandled = 0;
  const char * message = result_error_message(result, &unhandled);
  if (unhandled)
  {
    if (result < 0)
    {
      janet_panicf("%s: -%x", message, -result);
    }
    else
    {
      janet_panicf("%s: %x", message, result);
    }
  }
  else
  {
    janet_panic(message);
  }
}
