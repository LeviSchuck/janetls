/*
 * Copyright (c) 2020 Levi Schuck
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
#include "janetls-options.h"

#define JANETLS_SEARCH_OPTION_LIST(NAME, TYPE) \
  int janetls_search_ ## NAME ## _count() \
  {\
    return (sizeof(NAME) / sizeof(option_list_entry)); \
  }\
  \
  int janetls_search_ ## NAME(Janet value, TYPE * output) \
  { \
    if (janet_is_byte_typed(value)) \
    { \
      int type; \
      if (search_option_list(NAME, janetls_search_ ## NAME ## _count(), janet_to_bytes(value), &type)) \
      { \
        *output = type; \
        return 0; \
      } \
      return JANETLS_ERR_SEARCH_OPTION_NOT_FOUND; \
    } \
    return JANETLS_ERR_SEARCH_OPTION_INPUT_INVALID_TYPE; \
  } \
  Janet janetls_search_ ## NAME ## _set(int32_t argc, Janet * argv) \
  { \
    janet_fixarity(argc, 0); \
    return enumerate_option_list(NAME, janetls_search_ ## NAME ## _count()); \
  } \
  Janet janetls_search_ ## NAME ## _to_janet(TYPE type) \
  { \
    return value_to_option(NAME, janetls_search_ ## NAME ## _count(), type);\
  } \
  const char * janetls_search_ ## NAME ## _text(TYPE type) \
  { \
    return value_to_option_text(NAME, janetls_search_ ## NAME ## _count(), type); \
  }

option_list_entry md_supported_algorithms[] = {
  {janetls_md_algorithm_none, "none", OPTION_LIST_HIDDEN},
  {janetls_md_algorithm_md5, "md5", 0},
  {janetls_md_algorithm_sha1, "sha1", 0},
  {janetls_md_algorithm_sha1, "sha-1", OPTION_LIST_HIDDEN},
  {janetls_md_algorithm_sha224, "sha224", 0},
  {janetls_md_algorithm_sha256, "sha256", 0},
  {janetls_md_algorithm_sha384, "sha384", 0},
  {janetls_md_algorithm_sha512, "sha512", 0},
  {janetls_md_algorithm_sha224, "sha-224", OPTION_LIST_HIDDEN},
  {janetls_md_algorithm_sha256, "sha-256", OPTION_LIST_HIDDEN},
  {janetls_md_algorithm_sha384, "sha-384", OPTION_LIST_HIDDEN},
  {janetls_md_algorithm_sha512, "sha-512", OPTION_LIST_HIDDEN},
};

JANETLS_SEARCH_OPTION_LIST(md_supported_algorithms, janetls_md_algorithm)

option_list_entry encoding_base64_variant[] = {
  {janetls_encoding_base64_variant_standard, "standard", 0},
  {janetls_encoding_base64_variant_standard_unpadded, "standard-unpadded", 0},
  {janetls_encoding_base64_variant_url, "url", 0},
  {janetls_encoding_base64_variant_url_unpadded, "url-unpadded", 0},
  {janetls_encoding_base64_variant_pem, "pem", OPTION_LIST_HIDDEN},
  {janetls_encoding_base64_variant_mime, "mime", OPTION_LIST_HIDDEN},
  {janetls_encoding_base64_variant_imap, "imap", OPTION_LIST_HIDDEN},
  {janetls_encoding_base64_variant_pgp, "pgp", OPTION_LIST_HIDDEN},
};

JANETLS_SEARCH_OPTION_LIST(encoding_base64_variant, janetls_encoding_base64_variant)

option_list_entry encoding_base32_variant[] = {
  {janetls_encoding_base32_variant_standard, "standard", 0},
  {janetls_encoding_base32_variant_standard_unpadded, "standard-unpadded", 0},
  {janetls_encoding_base32_variant_z_base, "z-base", 0},
  {janetls_encoding_base32_variant_hex, "hex", 0},
  {janetls_encoding_base32_variant_hex_unpadded, "hex-unpadded", 0},
};

JANETLS_SEARCH_OPTION_LIST(encoding_base32_variant, janetls_encoding_base32_variant)

option_list_entry encoding_type[] = {
  {janetls_encoding_type_raw, "raw", 0},
  {janetls_encoding_type_hex, "hex", 0},
  {janetls_encoding_type_base64, "base64", 0},
  {janetls_encoding_type_base32, "base32", 0},
};

JANETLS_SEARCH_OPTION_LIST(encoding_type, janetls_encoding_type)

option_list_entry rsa_pkcs1_version[] = {
  {janetls_rsa_pkcs1_version_v15, "pkcs1-v1.5", 0},
  {janetls_rsa_pkcs1_version_v21, "pkcs1-v2.1", 0},
  {janetls_rsa_pkcs1_version_v15, "pkcs1-v1_5", OPTION_LIST_HIDDEN},
  {janetls_rsa_pkcs1_version_v21, "pkcs1-v2_1", OPTION_LIST_HIDDEN},
  {janetls_rsa_pkcs1_version_v15, "v1.5", OPTION_LIST_HIDDEN},
  {janetls_rsa_pkcs1_version_v21, "v2.1", OPTION_LIST_HIDDEN},
  {janetls_rsa_pkcs1_version_v15, "v1_5", OPTION_LIST_HIDDEN},
  {janetls_rsa_pkcs1_version_v21, "v2_1", OPTION_LIST_HIDDEN},
  {janetls_rsa_pkcs1_version_v15, "ssa", OPTION_LIST_HIDDEN},
  {janetls_rsa_pkcs1_version_v21, "rsaes", OPTION_LIST_HIDDEN},
  {janetls_rsa_pkcs1_version_v21, "oeap", OPTION_LIST_HIDDEN},
  {janetls_rsa_pkcs1_version_v21, "pss", OPTION_LIST_HIDDEN},
};

JANETLS_SEARCH_OPTION_LIST(rsa_pkcs1_version, janetls_rsa_pkcs1_version)

option_list_entry asn1_universal_type[] = {
  {janetls_asn1_universal_type_end_of_content, "not-universal", OPTION_LIST_HIDDEN},
  {janetls_asn1_universal_type_end_of_content, "end-of-content", OPTION_LIST_HIDDEN},
  {janetls_asn1_universal_type_boolean, "boolean", 0},
  {janetls_asn1_universal_type_integer, "integer", 0},
  {janetls_asn1_universal_type_bit_string, "bit-string", 0},
  {janetls_asn1_universal_type_octet_string, "octet-string", 0},
  {janetls_asn1_universal_type_null, "null", 0},
  {janetls_asn1_universal_type_object_identifier, "object-identifier", 0},
  {janetls_asn1_universal_type_object_identifier, "oid", OPTION_LIST_HIDDEN},
  {janetls_asn1_universal_type_object_descriptor, "object-descriptor", OPTION_LIST_HIDDEN},
  {janetls_asn1_universal_type_external, "external", OPTION_LIST_HIDDEN},
  {janetls_asn1_universal_type_real_float, "real-float", OPTION_LIST_HIDDEN},
  {janetls_asn1_universal_type_enumerated, "enumerated", OPTION_LIST_HIDDEN},
  {janetls_asn1_universal_type_embedded_pdv, "embedded-pdv", OPTION_LIST_HIDDEN},
  {janetls_asn1_universal_type_utf8_string, "utf8-string", 0},
  {janetls_asn1_universal_type_utf8_string, "utf8", OPTION_LIST_HIDDEN},
  {janetls_asn1_universal_type_relative_oid, "relative-oid", OPTION_LIST_HIDDEN},
  {janetls_asn1_universal_type_time, "time", OPTION_LIST_HIDDEN},
  {janetls_asn1_universal_type_sequence, "sequence", 0},
  {janetls_asn1_universal_type_set, "set", 0},
  {janetls_asn1_universal_type_numeric_string, "numeric-string", OPTION_LIST_HIDDEN},
  {janetls_asn1_universal_type_printable_string, "printable-string", 0},
  {janetls_asn1_universal_type_teletext_string, "teletex-string", OPTION_LIST_HIDDEN},
  {janetls_asn1_universal_type_videotex_string, "videotex-string", OPTION_LIST_HIDDEN},
  {janetls_asn1_universal_type_ia5_string, "ia5-string", 0},
  {janetls_asn1_universal_type_ia5_string, "ascii", OPTION_LIST_HIDDEN},
  {janetls_asn1_universal_type_utc_time, "utc-time", 0},
  {janetls_asn1_universal_type_generalized_time, "generalized-time", 0},
  {janetls_asn1_universal_type_graphic_string, "graphic-string", OPTION_LIST_HIDDEN},
  {janetls_asn1_universal_type_visible_string, "visible-string", OPTION_LIST_HIDDEN},
  {janetls_asn1_universal_type_general_string, "generalized-string", OPTION_LIST_HIDDEN},
  {janetls_asn1_universal_type_universal_string, "universal-string", OPTION_LIST_HIDDEN},
  {janetls_asn1_universal_type_character_string, "character-string", OPTION_LIST_HIDDEN},
  {janetls_asn1_universal_type_bitmap_string, "bitmap-string", 0},
  {janetls_asn1_universal_type_date, "date", OPTION_LIST_HIDDEN},
  {janetls_asn1_universal_type_time_of_day, "time-of-day", OPTION_LIST_HIDDEN},
  {janetls_asn1_universal_type_date_time, "date-time", OPTION_LIST_HIDDEN},
  {janetls_asn1_universal_type_duration, "duration", OPTION_LIST_HIDDEN},
  {janetls_asn1_universal_type_oid_iri, "oid-iri", OPTION_LIST_HIDDEN},
  {janetls_asn1_universal_type_relative_oid_iri, "relative-oid-iri", OPTION_LIST_HIDDEN},
};

JANETLS_SEARCH_OPTION_LIST(asn1_universal_type, janetls_asn1_universal_type)

option_list_entry asn1_class[] = {
  {janetls_asn1_class_universal, "universal", 0},
  {janetls_asn1_class_application, "application", 0},
  {janetls_asn1_class_context_specific, "context-specific", 0},
  {janetls_asn1_class_private, "private", 0},
};
JANETLS_SEARCH_OPTION_LIST(asn1_class, janetls_asn1_class)

option_list_entry pk_information_class[] = {
  {janetls_pk_information_class_private, "private", 0},
  {janetls_pk_information_class_public, "public", 0},
};
JANETLS_SEARCH_OPTION_LIST(pk_information_class, janetls_pk_information_class)

option_list_entry pk_key_type[] = {
  {janetls_pk_key_type_rsa, "rsa", 0},
  {janetls_pk_key_type_ecdsa, "ecdsa", 0},
};
JANETLS_SEARCH_OPTION_LIST(pk_key_type, janetls_pk_key_type)

option_list_entry ecp_curve_type[] = {
  {janetls_ecp_curve_type_none, "none", OPTION_LIST_HIDDEN},
  {janetls_ecp_curve_type_short_weierstrass, "short-weierstrass", 0},
  {janetls_ecp_curve_type_montgomery, "montgomery", 0},
};
JANETLS_SEARCH_OPTION_LIST(ecp_curve_type, janetls_ecp_curve_type)

option_list_entry ecp_compression[] = {
  {janetls_ecp_compression_uncompressed, "uncompressed", 0},
  {janetls_ecp_compression_compressed, "compressed", 0},
};
JANETLS_SEARCH_OPTION_LIST(ecp_compression, janetls_ecp_compression)

option_list_entry ecp_curve_group[] = {
  {janetls_ecp_curve_group_none, "none", OPTION_LIST_HIDDEN},
  {janetls_ecp_curve_group_secp192r1, "secp192r1", 0},
  {janetls_ecp_curve_group_secp192r1, "p192", OPTION_LIST_HIDDEN},
  {janetls_ecp_curve_group_secp224r1, "secp224r1", 0},
  {janetls_ecp_curve_group_secp224r1, "p224", OPTION_LIST_HIDDEN},
  {janetls_ecp_curve_group_secp256r1, "secp256r1", 0},
  {janetls_ecp_curve_group_secp256r1, "p256", OPTION_LIST_HIDDEN},
  {janetls_ecp_curve_group_secp384r1, "secp384r1", 0},
  {janetls_ecp_curve_group_secp384r1, "p384", OPTION_LIST_HIDDEN},
  {janetls_ecp_curve_group_secp521r1, "secp521r1", 0},
  {janetls_ecp_curve_group_secp521r1, "p521", OPTION_LIST_HIDDEN},
  {janetls_ecp_curve_group_secp192k1, "secp192k1", 0},
  {janetls_ecp_curve_group_secp224k1, "secp224k1", 0},
  {janetls_ecp_curve_group_secp256k1, "secp256k1", 0},
  {janetls_ecp_curve_group_bp256r1, "bp256r1", 0},
  {janetls_ecp_curve_group_bp384r1, "bp384r1", 0},
  {janetls_ecp_curve_group_bp512r1, "bp512r1", 0},
  {janetls_ecp_curve_group_x25519, "x25519", OPTION_LIST_HIDDEN},
  {janetls_ecp_curve_group_x448, "x448", OPTION_LIST_HIDDEN},
  {janetls_ecp_curve_group_ed25519, "ed25519", OPTION_LIST_HIDDEN},
  {janetls_ecp_curve_group_ed448, "ed448", OPTION_LIST_HIDDEN},
};
JANETLS_SEARCH_OPTION_LIST(ecp_curve_group, janetls_ecp_curve_group)

option_list_entry cipher_algorithm[] = {
  {janetls_cipher_algorithm_none, "none", OPTION_LIST_HIDDEN},
  {janetls_cipher_algorithm_aes, "aes", 0},
  // {janetls_cipher_algorithm_des, "des", 0},
  // {janetls_cipher_algorithm_camellia, "camellia", 0},
  // {janetls_cipher_algorithm_blowfish, "blowfish", 0},
  {janetls_cipher_algorithm_chacha20, "chacha20", 0},
  {janetls_cipher_algorithm_chacha20, "chacha", OPTION_LIST_HIDDEN},
};
JANETLS_SEARCH_OPTION_LIST(cipher_algorithm, janetls_cipher_algorithm)

option_list_entry cipher_padding[] = {
  {janetls_cipher_padding_none, "none", 0},
  {janetls_cipher_padding_pkcs7, "pkcs7", 0},
  // {janetls_cipher_padding_one_and_zeros, "one-and-zeros", 0},
  // {janetls_cipher_padding_zeros_and_len, "zeros-and-len", 0},
  // {janetls_cipher_padding_zeros, "zeros", 0},
};
JANETLS_SEARCH_OPTION_LIST(cipher_padding, janetls_cipher_padding)

option_list_entry cipher_operation[] = {
  {janetls_cipher_operation_none, "none", OPTION_LIST_HIDDEN},
  {janetls_cipher_operation_encrypt, "encrypt", 0},
  {janetls_cipher_operation_decrypt, "decrypt", 0},
};
JANETLS_SEARCH_OPTION_LIST(cipher_operation, janetls_cipher_operation)

option_list_entry aes_mode[] = {
  {janetls_aes_mode_none, "none", OPTION_LIST_HIDDEN},
  {janetls_aes_mode_ecb, "ecb", 0},
  {janetls_aes_mode_cbc, "cbc", 0},
  {janetls_aes_mode_ctr, "ctr", 0},
  {janetls_aes_mode_cfb8, "cfb8", 0},
  {janetls_aes_mode_cfb128, "cfb128", 0},
  {janetls_aes_mode_ofb, "ofb", 0},
};
JANETLS_SEARCH_OPTION_LIST(aes_mode, janetls_aes_mode)

