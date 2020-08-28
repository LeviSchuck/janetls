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

#ifndef JANETLS_ASN1_H
#define JANETLS_ASN1_H
#include <janet.h>
#include "janetls-encoding.h"


typedef enum number_type {
  BIGNUM = 0,
  NUMBER,
  U64
} number_type;

typedef enum asn1_class {
  UNIVERSAL = 1,
  APPLICATION,
  CONTEXT_SPECIFIC,
  PRIVATE
} asn1_class;

typedef enum asn1_universal_type {
  NOT_UNIVERSAL = 0,
  BOOLEAN = 1,
  INTEGER = 2,
  BIT_STRING = 3,
  OCTET_STRING = 4,
  NULL_TYPE = 5,
  OBJECT_IDENTIFIER = 6,
  UTF8_STRING = 0x0c,
  SEQUENCE = 0x10,
  SET = 0x11,
  PRINTABLE_STRING = 0x13,
  TELETEX_STRING = 0x14,
  IA5_ASCII_STRING = 0x16,
  UTC_TIME = 0x17,
  GENERALIZED_TIME = 0x18,
  UNIVERSAL_STRINGS = 0x1C,
  BITMAP_STRING = 0x1E,
} asn1_universal_type;

typedef struct asn1_parser {
  Janet source;
  const uint8_t * buffer;
  size_t position;
  size_t length;
  uint64_t flags;
  base64_variant base64_variant;
} asn1_parser;

typedef struct asn1_parsed_tag {
  uint64_t tag;
  asn1_class asn1_class;
  asn1_universal_type asn1_universal_type;
  uint8_t base_tag_byte;
  uint8_t constructed;
  const uint8_t * tag_start;
  const uint8_t * value_start;
  const uint8_t * value_end;
  size_t tag_position;
  size_t value_position;
  size_t header_length;
  size_t value_length;
} asn1_parsed_tag;

typedef enum asn1_flags {
  ASN1_BIGNUM_AS_STRING = 0,
  ASN1_EAGER_PARSE,
  ASN1_BASE64_NON_ASCII,
  ASN1_BASE64_USE_URL,
  ASN1_COLLAPSE_SINGLE_CONSTRUCTIONS,
  ASN1_STRING_OID,
} asn1_flags;

#define ASN1_FLAG_BIGNUM_AS_STRING (1 << ASN1_BIGNUM_AS_STRING)
#define ASN1_FLAG_EAGER_PARSE (1 << ASN1_EAGER_PARSE)
#define ASN1_FLAG_BASE64_NON_ASCII (1 << ASN1_BASE64_NON_ASCII)
#define ASN1_FLAG_BASE64_USE_URL (1 << ASN1_BASE64_USE_URL)
#define ASN1_FLAG_COLLAPSE_SINGLE_CONSTRUCTIONS (1 << ASN1_COLLAPSE_SINGLE_CONSTRUCTIONS)
#define ASN1_FLAG_STRING_OID (1 << ASN1_STRING_OID)

#endif
