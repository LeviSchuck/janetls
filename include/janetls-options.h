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

#ifndef JANETLS_OPTIONS_H
#define JANETLS_OPTIONS_H
#include <janet.h>
#include "janetls.h"

#define JANETLS_SEARCH_OPTION_FORWARD_DECLARE(NAME, TYPE) \
  int janetls_search_ ## NAME ## _count(); \
  int janetls_search_ ## NAME(Janet value, TYPE * output); \
  Janet janetls_search_ ## NAME ## _set(int32_t argc, Janet * argv); \
  Janet janetls_search_ ## NAME ## _to_janet(TYPE type); \
  const char * janetls_search_ ## NAME ## _text(TYPE type);

typedef enum janetls_rsa_pkcs1_version
{
  janetls_rsa_pkcs1_version_v15 = 0,
  janetls_rsa_pkcs1_version_v21 = 1,
} janetls_rsa_pkcs1_version;

JANETLS_SEARCH_OPTION_FORWARD_DECLARE(rsa_pkcs1_version, janetls_rsa_pkcs1_version)

typedef enum janetls_pk_information_class
{
  janetls_pk_information_class_public = 0,
  janetls_pk_information_class_private
} janetls_pk_information_class;

JANETLS_SEARCH_OPTION_FORWARD_DECLARE(pk_information_class, janetls_pk_information_class)

typedef enum janetls_pk_key_type
{
  janetls_pk_key_type_rsa,
  janetls_pk_key_type_ecdsa,
} janetls_pk_key_type;

JANETLS_SEARCH_OPTION_FORWARD_DECLARE(pk_key_type, janetls_pk_key_type)

typedef enum janetls_md_algorithm
{
  // These numbers are in sync with mbedtls_md_type_t
  janetls_md_algorithm_none = 0,
  janetls_md_algorithm_md5 = 3,
  janetls_md_algorithm_sha1 = 4,
  janetls_md_algorithm_sha224 = 5,
  janetls_md_algorithm_sha256 = 6,
  janetls_md_algorithm_sha384 = 7,
  janetls_md_algorithm_sha512 = 8,
} janetls_md_algorithm;

JANETLS_SEARCH_OPTION_FORWARD_DECLARE(md_supported_algorithms, janetls_md_algorithm)

typedef enum janetls_encoding_type
{
  janetls_encoding_type_raw = 0,
  janetls_encoding_type_hex,
  janetls_encoding_type_base64,
} janetls_encoding_type;

JANETLS_SEARCH_OPTION_FORWARD_DECLARE(encoding_type, janetls_encoding_type)

typedef enum janetls_encoding_base64_variant
{
  janetls_encoding_base64_variant_standard = 0,
  janetls_encoding_base64_variant_standard_unpadded,
  janetls_encoding_base64_variant_pem,
  janetls_encoding_base64_variant_mime,
  janetls_encoding_base64_variant_imap,
  janetls_encoding_base64_variant_url,
  janetls_encoding_base64_variant_url_unpadded,
  janetls_encoding_base64_variant_pgp,
} janetls_encoding_base64_variant;

JANETLS_SEARCH_OPTION_FORWARD_DECLARE(encoding_base64_variant, janetls_encoding_base64_variant)

typedef enum janetls_asn1_number_type
{
  janetls_asn1_number_type_bignum = 0,
  janetls_asn1_number_type_number,
  janetls_asn1_number_type_u64
} janetls_asn1_number_type;

JANETLS_SEARCH_OPTION_FORWARD_DECLARE(asn1_number_type, janetls_encoding_base64_variant)

typedef enum janetls_asn1_class
{
  janetls_asn1_class_universal = 0,
  janetls_asn1_class_application = 1,
  janetls_asn1_class_context_specific = 2,
  janetls_asn1_class_private = 3,
} janetls_asn1_class;

JANETLS_SEARCH_OPTION_FORWARD_DECLARE(asn1_class, janetls_asn1_class)

// https://en.wikipedia.org/wiki/Distinguished_Encoding_Rules#Types
typedef enum janetls_asn1_universal_type
{
  janetls_asn1_universal_type_end_of_content = 0,
  janetls_asn1_universal_type_boolean = 1,
  janetls_asn1_universal_type_integer = 2,
  janetls_asn1_universal_type_bit_string = 3,
  janetls_asn1_universal_type_octet_string = 4,
  janetls_asn1_universal_type_null = 5,
  janetls_asn1_universal_type_object_identifier = 6,
  janetls_asn1_universal_type_object_descriptor = 7,
  janetls_asn1_universal_type_external = 8,
  janetls_asn1_universal_type_real_float = 9,
  janetls_asn1_universal_type_enumerated = 0x0A,
  janetls_asn1_universal_type_embedded_pdv = 0x0B,
  janetls_asn1_universal_type_utf8_string = 0x0C,
  janetls_asn1_universal_type_relative_oid = 0x0D,
  janetls_asn1_universal_type_time = 0x0E,
  // 0x0F is reverved
  janetls_asn1_universal_type_sequence = 0x10,
  janetls_asn1_universal_type_set = 0x11,
  janetls_asn1_universal_type_numeric_string = 0x12,
  janetls_asn1_universal_type_printable_string = 0x13,
  janetls_asn1_universal_type_teletext_string = 0x14,
  janetls_asn1_universal_type_videotex_string = 0x15,
  janetls_asn1_universal_type_ia5_string = 0x16,
  janetls_asn1_universal_type_utc_time = 0x17,
  janetls_asn1_universal_type_generalized_time = 0x18,
  janetls_asn1_universal_type_graphic_string = 0x19,
  janetls_asn1_universal_type_visible_string = 0x1A,
  janetls_asn1_universal_type_general_string = 0x1B,
  janetls_asn1_universal_type_universal_string = 0x1C,
  janetls_asn1_universal_type_character_string = 0x1D,
  janetls_asn1_universal_type_bitmap_string = 0x1E,
  janetls_asn1_universal_type_date = 0x1F,
  janetls_asn1_universal_type_time_of_day = 0x20,
  janetls_asn1_universal_type_date_time = 0x21,
  janetls_asn1_universal_type_duration = 0x22,
  janetls_asn1_universal_type_oid_iri = 0x23,
  janetls_asn1_universal_type_relative_oid_iri = 0x24,
} janetls_asn1_universal_type;

JANETLS_SEARCH_OPTION_FORWARD_DECLARE(asn1_universal_type, janetls_asn1_universal_type)

typedef enum janetls_asn1_flags
{
  janetls_asn1_flags_bignum_as_string = 0,
  janetls_asn1_flags_eager_parse,
  janetls_asn1_flags_base64_non_ascii,
  janetls_asn1_flags_base64_use_url,
  janetls_asn1_flags_collapse_single_constructions,
  janetls_asn1_flags_collapse_guessable_values,
  janetls_asn1_flags_string_oid,
  janetls_asn1_flags_json,
} janetls_asn1_flags;

JANETLS_SEARCH_OPTION_FORWARD_DECLARE(asn1_flags, janetls_asn1_flags)

#define ASN1_FLAG_BIGNUM_AS_STRING (1 << janetls_asn1_flags_bignum_as_string)
#define ASN1_FLAG_EAGER_PARSE (1 << janetls_asn1_flags_eager_parse)
#define ASN1_FLAG_BASE64_NON_ASCII (1 << janetls_asn1_flags_base64_non_ascii)
#define ASN1_FLAG_BASE64_USE_URL (1 << janetls_asn1_flags_base64_use_url)
#define ASN1_FLAG_COLLAPSE_SINGLE_CONSTRUCTIONS (1 << janetls_asn1_flags_collapse_single_constructions)
#define ASN1_FLAG_COLLAPSE_GUESSABLE_VALUES (1 << janetls_asn1_flags_collapse_guessable_values)
#define ASN1_FLAG_STRING_OID (1 << janetls_asn1_flags_string_oid)

// Full list of possible curves..
// For now it's only what mbedtls supports
// https://www.hyperelliptic.org/EFD/
typedef enum janetls_ecp_curve_type
{
  janetls_ecp_curve_type_none = 0, // not one of these
  janetls_ecp_curve_type_short_weierstrass, // y^2 = x^3 + a x + b
  janetls_ecp_curve_type_montgomery, // y^2 = x^3 + a x^2 + x
} janetls_ecp_curve_type;

JANETLS_SEARCH_OPTION_FORWARD_DECLARE(ecp_curve_type, janetls_ecp_curve_type)

typedef enum janetls_ecp_compression
{
  janetls_ecp_compression_uncompressed = 0,
  janetls_ecp_compression_compressed, // The y coordinate is just a sign-bit
} janetls_ecp_compression;

JANETLS_SEARCH_OPTION_FORWARD_DECLARE(ecp_compression, janetls_ecp_compression)

// This is in the same order as mbedtls
typedef enum janetls_ecp_curve_group
{
  janetls_ecp_curve_group_none = 0, // not one of these
  janetls_ecp_curve_group_secp192r1, // NIST 192
  janetls_ecp_curve_group_secp224r1, // NIST 224
  janetls_ecp_curve_group_secp256r1, // NIST 256
  janetls_ecp_curve_group_secp384r1, // NIST 384
  janetls_ecp_curve_group_secp521r1, // NIST 521 bit (not a typo)
  janetls_ecp_curve_group_bp256r1, // Brainpool 256bit
  janetls_ecp_curve_group_bp384r1, // Brainpool 384bit
  janetls_ecp_curve_group_bp512r1, // Brainpool 512bit
  janetls_ecp_curve_group_secp192k1, // Koblitz
  janetls_ecp_curve_group_secp224k1, // Koblitz
  janetls_ecp_curve_group_secp256k1, // Koblitz
  janetls_ecp_curve_group_x25519, // Curve25519
  janetls_ecp_curve_group_x448, // Curve448
  janetls_ecp_curve_group_ed25519, // Curve25519
  janetls_ecp_curve_group_ed448, // Curve448
} janetls_ecp_curve_group;

JANETLS_SEARCH_OPTION_FORWARD_DECLARE(ecp_curve_group, janetls_ecp_curve_group)

typedef enum janetls_cipher_class
{
  janetls_cipher_class_none = 0,
  janetls_cipher_class_aes,
  janetls_cipher_class_chacha20,
} janetls_cipher_class;

JANETLS_SEARCH_OPTION_FORWARD_DECLARE(cipher_class, janetls_cipher_class)

typedef enum janetls_cipher_padding
{
  janetls_cipher_padding_none = 0,
  janetls_cipher_padding_pkcs7,
  janetls_cipher_padding_one_and_zeros,
  janetls_cipher_padding_zeros_and_len,
  janetls_cipher_padding_zeros,
} janetls_cipher_padding;

JANETLS_SEARCH_OPTION_FORWARD_DECLARE(cipher_padding, janetls_cipher_padding)

typedef enum janetls_cipher_mode
{
  janetls_cipher_mode_none = 0,
  janetls_cipher_mode_ecb,
  janetls_cipher_mode_cbc,
  janetls_cipher_mode_ctr,
  janetls_cipher_mode_gcm,
  janetls_cipher_mode_stream, // used for chacha20
  janetls_cipher_mode_chachapoly, // used for AEAD chacha20+poly1305
} janetls_cipher_mode;

JANETLS_SEARCH_OPTION_FORWARD_DECLARE(cipher_mode, janetls_cipher_mode)

#endif
