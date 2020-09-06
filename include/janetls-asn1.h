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
#include "janetls-options.h"

typedef struct asn1_parser {
  Janet source;
  const uint8_t * buffer;
  size_t position;
  size_t length;
  uint64_t flags;
  janetls_encoding_base64_variant base64_variant;
} asn1_parser;

typedef struct asn1_parsed_tag {
  uint64_t tag;
  janetls_asn1_class asn1_class;
  janetls_asn1_universal_type asn1_universal_type;
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

#endif
