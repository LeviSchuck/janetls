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

#include "janetls.h"
#include "janetls-cipher.h"

static int cipher_gc_fn(void * data, size_t len);
static int cipher_gcmark(void * data, size_t len);
static int cipher_get_fn(void * data, Janet key, Janet * out);

JanetAbstractType cipher_object_type = {
  "janetls/cipher",
  cipher_gc_fn,
  cipher_gcmark,
  cipher_get_fn,
  JANET_ATEND_GET
};

static JanetMethod cipher_methods[] = {
  {NULL, NULL}
};

static const JanetReg cfuns[] =
{
  {"cipher/modes", janetls_search_cipher_mode_set, "(janetls/cipher/modes)\n\n"
    "Provides an tuple of keywords for available cipher modes"},
  {"cipher/paddings", janetls_search_cipher_padding_set, "(janetls/cipher/paddings)\n\n"
    "Provides an tuple of keywords for available cipher paddings"},
  {"cipher/classes", janetls_search_cipher_class_set, "(janetls/cipher/classes)\n\n"
    "Provides an tuple of keywords for available cipher classes (like aes)"},
  {NULL, NULL, NULL}
};

void submod_cipher(JanetTable * env)
{
  janet_cfuns(env, "janetls", cfuns);
  janet_register_abstract_type(janetls_cipher_object_type());
}

janetls_cipher_object * janetls_new_cipher()
{
  janetls_cipher_object * cipher = janet_abstract(&cipher_object_type, sizeof(janetls_cipher_object));
  memset(cipher, 0, sizeof(janetls_cipher_object));
  mbedtls_cipher_init(&cipher->ctx);
  return cipher;
}

JanetAbstractType * janetls_cipher_object_type()
{
  return &cipher_object_type;
}

static int cipher_gc_fn(void * data, size_t len)
{
  janetls_cipher_object * cipher = (janetls_cipher_object *)data;
  mbedtls_cipher_free(&cipher->ctx);
  return 0;
}

static int cipher_gcmark(void * data, size_t len)
{
  (void)data;
  (void)len;
  return 0;
}

static int cipher_get_fn(void * data, Janet key, Janet * out)
{
  (void)data;

  if (!janet_checktype(key, JANET_KEYWORD))
  {
    janet_panicf("expected keyword, got %p", key);
  }

  return janet_getmethod(janet_unwrap_keyword(key), cipher_methods, out);
}
