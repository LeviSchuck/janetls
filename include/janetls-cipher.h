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

#ifndef JANETLS_CIPHER_H
#define JANETLS_CIPHER_H
#include <janet.h>
#include "mbedtls/cipher.h"
#include "janetls-options.h"

#define JANETLS_MAX_CIPHER_KEY_SIZE 64
// GCM tags 4 - 16 bytes
// Cachapoly is exactly 16 bytes
#define JANETLS_MAX_CIPHER_TAG_SIZE 16

typedef struct janetls_cipher_type
{
  janetls_cipher_cipher cipher;
  janetls_cipher_algorithm algorithm;
  janetls_cipher_mode mode;
  uint16_t key_size;
  mbedtls_cipher_type_t mbedtls_type;
  uint32_t default_flags;
} janetls_cipher_type;

typedef struct janetls_cipher_object {
  mbedtls_cipher_context_t ctx;
  const janetls_cipher_type * type;
  janetls_cipher_padding padding;
  janetls_cipher_operation operation;
  uint32_t buffer_length;
  uint32_t key_size;
  uint32_t iv_size;
  uint32_t tag_size;
  uint32_t flags;
  uint8_t key[JANETLS_MAX_CIPHER_KEY_SIZE];
  uint8_t buffer[MBEDTLS_MAX_BLOCK_LENGTH];
  uint8_t iv[MBEDTLS_MAX_IV_LENGTH];
  uint8_t tag[JANETLS_MAX_CIPHER_TAG_SIZE];
} janetls_cipher_object;

janetls_cipher_object * janetls_new_cipher();
JanetAbstractType * janetls_cipher_object_type();
int janetls_setup_cipher(
  janetls_cipher_object * cipher_object,
  janetls_cipher_cipher cipher);
int janetls_cipher_set_key(
  janetls_cipher_object * cipher_object,
  const uint8_t * key,
  size_t length,
  janetls_cipher_operation operation);
int janetls_cipher_set_iv(
  janetls_cipher_object * cipher_object,
  const uint8_t * iv,
  size_t length);
int janetls_cipher_set_padding(
  janetls_cipher_object * cipher_object,
  janetls_cipher_padding padding);
int janetls_cipher_update(
  janetls_cipher_object * cipher_object,
  const uint8_t * data,
  size_t length,
  Janet * output);
int janetls_cipher_update_ad(
  janetls_cipher_object * cipher_object,
  const uint8_t * data,
  size_t length,
  Janet * output);
int janetls_cipher_finish(
  janetls_cipher_object * cipher_object,
  Janet * output);
int janetls_cipher_get_tag(
  janetls_cipher_object * cipher_object,
  Janet * output,
  size_t tag_size);
int janetls_cipher_get_iv(
  janetls_cipher_object * cipher_object,
  Janet * output);
int janetls_cipher_get_key(
  janetls_cipher_object * cipher_object,
  Janet * output);
int janetls_cipher_check_tag(
  janetls_cipher_object * cipher_object,
  const uint8_t * data,
  size_t length,
  Janet * output);

#endif