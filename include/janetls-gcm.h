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

#ifndef JANETLS_GCM_H
#define JANETLS_GCM_H
#include <janet.h>
#include "mbedtls/gcm.h"
#include "janetls-options.h"

typedef struct janetls_gcm_object {
  mbedtls_gcm_context ctx;
  janetls_cipher_operation operation;
  uint8_t tag[16];
  Janet iv;
  Janet ad;
  uint32_t flags;
} janetls_gcm_object;


janetls_gcm_object * janetls_new_gcm();
JanetAbstractType * janetls_gcm_object_type();

int janetls_setup_gcm(
  janetls_gcm_object * gcm_object,
  const uint8_t * key,
  size_t key_length,
  const uint8_t * iv,
  size_t iv_length,
  janetls_cipher_operation operation,
  const uint8_t * ad,
  size_t ad_length
  );
int janetls_gcm_update(
  janetls_gcm_object * gcm_object,
  const uint8_t * data,
  size_t length,
  Janet * output);
int janetls_gcm_finish(
  janetls_gcm_object * gcm_object,
  Janet * output);


#endif