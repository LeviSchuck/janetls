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
    return (sizeof(supported_algorithms) / sizeof(option_list_entry)); \
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
      return JANETLS_ERR_SEARH_OPTION_INPUT_INVALID_TYPE; \
    } \
    return JANETLS_ERR_SEARH_OPTION_NOT_FOUND; \
  } \
  static Janet janetls_search_ ## NAME ## _set(int32_t argc, Janet * argv) \
  { \
    janet_fixarity(argc, 0); \
    return enumerate_option_list(NAME, janetls_search_ ## NAME ## _count()); \
  } \
  Janet janetls_search_ ## NAME ## _to_janet(TYPE type) \
  { \
    return value_to_option(NAME, janetls_search_ ## NAME ## _count(), type);\
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

option_list_entry encoding_type[] = {
  {janetls_encoding_type_raw, "raw", 0},
  {janetls_encoding_type_hex, "hex", 0},
  {janetls_encoding_type_base64, "base64", 0},
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

option_list_entry asn1_class_type[] = {
  {janetls_asn1_class_universal, "universal", 0},
  {janetls_asn1_class_application, "application", 0},
  {janetls_asn1_class_context_specific, "context-specific", 0},
  {janetls_asn1_class_private, "private", 0},
};
JANETLS_SEARCH_OPTION_LIST(asn1_class_type, janetls_asn1_class)