/*
 * Copyright (c) 2021 Levi Schuck
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

#ifndef JANETLS_TLS_H
#define JANETLS_TLS_H
#include <janet.h>
#include "mbedtls/ssl.h"
#include "janetls-x509.h"
#include "janetls-random.h"
#include "janetls-options.h"

typedef struct janetls_tls_config_object {
  mbedtls_ssl_config config;
  janetls_x509_crt_object * cert_chain;
  // janetls_x509_crt_object * own_cert;
  janetls_random_object * random;
  janetls_tls_verify verify; // Optional, required, none
  janetls_tls_endpoint endpoint;
  janetls_tls_transport transport;
} janetls_tls_config_object;

janetls_tls_config_object * janetls_new_tls_config();
JanetAbstractType * janetls_tls_config_object_type();

#endif
