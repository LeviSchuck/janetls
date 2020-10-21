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

#ifndef JANETLS_AES_H
#define JANETLS_AES_H
#include <janet.h>
#include "mbedtls/aes.h"
#include "janetls-options.h"

typedef struct janetls_aes_object {
  mbedtls_aes_context ctx;
  janetls_cipher_mode mode;
  janetls_cipher_padding padding;
  janetls_cipher_operation operation;
  uint32_t buffer_length;
  uint32_t key_size;
  uint32_t flags;
  uint8_t key[32];
  uint8_t buffer[16];
  union {
    uint8_t iv[16];
    uint8_t nonce[16];
  };
  union {
    uint8_t working_iv[16];
    uint8_t working_nonce[16];
  };
  union {
    size_t iv_offset;
    size_t nonce_offset;
  };
  uint8_t stream_block[16];
} janetls_aes_object;


janetls_aes_object * janetls_new_aes();
JanetAbstractType * janetls_aes_object_type();
int janetls_setup_aes(
  janetls_aes_object * aes_object,
  janetls_aes_mode mode,
  const uint8_t * key,
  size_t key_length,
  const uint8_t * iv,
  size_t iv_length,
  janetls_cipher_operation operation,
  janetls_cipher_padding padding
  );
int janetls_aes_update(
  janetls_aes_object * aes_object,
  const uint8_t * data,
  size_t length,
  Janet * output);
int janetls_aes_finish(
  janetls_aes_object * aes_object,
  Janet * output);

#endif