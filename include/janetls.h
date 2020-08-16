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

Janet hex_encode(const uint8_t * str, unsigned int length);
Janet hex_decode(const uint8_t * str, unsigned int length);
Janet base64_encode(const uint8_t * data, unsigned int length, base64_variant variant);
Janet base64_decode(const uint8_t * data, unsigned int length, base64_variant variant);
base64_variant get_base64_variant(int argc, Janet * argv, int index);
content_encoding get_content_encoding(int argc, Janet * argv, int index);
Janet content_to_encoding(const uint8_t * str, unsigned int length, content_encoding encoding, int encoding_variant);
Janet content_from_encoding(const uint8_t * str, unsigned int length, content_encoding encoding, int encoding_variant);


void submod_md(JanetTable * env);
void submod_util(JanetTable * env);

#ifndef NULL
#define NULL 0
#endif

#endif
