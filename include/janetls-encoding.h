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

#ifndef JANETLS_ENCODING_H
#define JANETLS_ENCODING_H
#include <janet.h>
#include "janetls-options.h"

Janet hex_encode(const uint8_t * str, unsigned int length);
Janet hex_decode(const uint8_t * str, unsigned int length);
int janetls_hex_decode(Janet * result, const uint8_t * str, unsigned int length);
int janetls_hex_encode(Janet * result, const uint8_t * str, unsigned int length);
Janet base64_encode(const uint8_t * data, unsigned int length, janetls_encoding_base64_variant variant);
Janet base64_decode(const uint8_t * data, unsigned int length, janetls_encoding_base64_variant variant);
int janetls_base64_encode(Janet * result, const uint8_t * data, unsigned int length, janetls_encoding_base64_variant variant);
int janetls_base64_decode(Janet * result, const uint8_t * data, unsigned int length, janetls_encoding_base64_variant variant);
int get_base64_variant(int argc, Janet * argv, int index, uint8_t panic, janetls_encoding_base64_variant * variant);
Janet base32_encode(const uint8_t * data, unsigned int length, janetls_encoding_base32_variant variant);
Janet base32_decode(const uint8_t * data, unsigned int length, janetls_encoding_base32_variant variant);
int janetls_base32_encode(Janet * result, const uint8_t * data, unsigned int length, janetls_encoding_base32_variant variant);
int janetls_base32_decode(Janet * result, const uint8_t * data, unsigned int length, janetls_encoding_base32_variant variant);
int get_base32_variant(int argc, Janet * argv, int index, uint8_t panic, janetls_encoding_base32_variant * variant);
int get_content_encoding(int argc, Janet * argv, int index, uint8_t panic, janetls_encoding_type* encoding);
Janet content_to_encoding(const uint8_t * str, unsigned int length, janetls_encoding_type encoding, int encoding_variant);
Janet content_from_encoding(const uint8_t * str, unsigned int length, janetls_encoding_type encoding, int encoding_variant);
int janetls_content_to_encoding(Janet * result, const uint8_t * str, unsigned int length, janetls_encoding_type encoding, int encoding_variant);
int janetls_content_from_encoding(Janet * result, const uint8_t * str, unsigned int length, janetls_encoding_type encoding, int encoding_variant);
// Tries to consume arguments pertaining to encoding
int extract_encoding(int argc, Janet * argv, int offset, janetls_encoding_type* encoding, int * variant);

#endif
