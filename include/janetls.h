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

#ifndef JANETLS_H
#define JANETLS_H
#include <janet.h>

typedef enum content_encoding
{
  RAW_BYTE = 0,
  HEX,
  BASE_64,
} content_encoding;

typedef enum base64_variant
{
  STANDARD = 0,
  STANDARD_UNPADDED,
  PEM,
  MIME,
  IMAP,
  URL,
  URL_UNPADDED,
  PGP,
} base64_variant;

typedef struct option_list_entry {
  int value;
  char option[32];
  uint8_t flags;
} option_list_entry;

#define OPTION_LIST_HIDDEN 1
#define OPTION_LIST_CASE_SENSITIVE 2

Janet hex_encode(const uint8_t * str, unsigned int length);
Janet hex_decode(const uint8_t * str, unsigned int length);
Janet base64_encode(const uint8_t * data, unsigned int length, base64_variant variant);
Janet base64_decode(const uint8_t * data, unsigned int length, base64_variant variant);
int get_base64_variant(int argc, Janet * argv, int index, uint8_t panic, base64_variant * variant);
int get_content_encoding(int argc, Janet * argv, int index, uint8_t panic, content_encoding * encoding);
Janet content_to_encoding(const uint8_t * str, unsigned int length, content_encoding encoding, int encoding_variant);
Janet content_from_encoding(const uint8_t * str, unsigned int length, content_encoding encoding, int encoding_variant);
// Tries to consume arguments pertaining to encoding
int extract_encoding(int argc, Janet * argv, int offset, content_encoding * encoding, int * variant);
// Option list helpers
int search_option_list(option_list_entry * list, int list_size, JanetByteView str, int * destination);
Janet enumerate_option_list(option_list_entry * list, int size);
Janet value_to_option(option_list_entry * list, int size, int value);
// Byte view helpers
JanetByteView janet_to_bytes(Janet x);
int janet_is_byte_typed(Janet x);


void submod_md(JanetTable * env);
void submod_util(JanetTable * env);
void submod_bignum(JanetTable * env);
void submod_random(JanetTable * env);

#ifndef NULL
#define NULL 0
#endif

#endif
