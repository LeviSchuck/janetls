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

#ifndef JANETLS_RSA_H
#define JANETLS_RSA_H
#include <janet.h>
#include "mbedtls/rsa.h"
#include "mbedtls/md.h"
#include "janetls-random.h"

typedef enum rsa_pkcs1_version {
  rsa_pkcs1_version_v15 = 0,
  rsa_pkcs1_version_v21 = 1,
} rsa_pkcs1_version;

typedef enum rsa_key_type {
  rsa_key_type_public,
  rsa_key_type_private
} rsa_key_type;

typedef struct rsa_object {
  mbedtls_rsa_context ctx;
  random_object * random;
  rsa_pkcs1_version version;
  rsa_key_type type;
  mbedtls_md_type_t digest;
} rsa_object;
extern JanetAbstractType rsa_object_type;

rsa_object * new_rsa();

#endif
