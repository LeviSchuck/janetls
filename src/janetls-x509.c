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

#include <ctype.h>
#include "janetls.h"
#include "janetls-x509.h"

static int x509_crt_gc_fn(void * data, size_t len);
static int x509_crt_gcmark(void * data, size_t len);
static int x509_crt_get_fn(void * data, Janet key, Janet * out);
static Janet x509_crt_from(int32_t argc, Janet * argv);
static Janet x509_crt_der(int32_t argc, Janet * argv);
static Janet x509_crt_next(int32_t argc, Janet * argv);

static JanetAbstractType x509_crt_object_type = {
  "janetls/x509_crt",
  x509_crt_gc_fn,
  x509_crt_gcmark,
  x509_crt_get_fn,
  JANET_ATEND_GET
  // TODO marshalling so it can cross thread boundaries
};

static JanetMethod x509_crt_methods[] = {
  {"der", x509_crt_der},
  {"next", x509_crt_next},
  {NULL, NULL}
};

static int x509_crt_get_fn(void * data, Janet key, Janet * out)
{
  (void)data;

  if (!janet_checktype(key, JANET_KEYWORD))
  {
    // Unexpected type, not found.
    return 0;
  }

  return janet_getmethod(janet_unwrap_keyword(key), x509_crt_methods, out);
}

static int x509_crt_gc_fn(void * data, size_t len)
{
  janetls_x509_crt_object * x509_crt = (janetls_x509_crt_object *)data;

  if (x509_crt->crt.next && x509_crt->next_object != NULL && &(x509_crt->next_object->crt) == x509_crt->crt.next) {
    // Unlink the next one prior to GC, as it is managed by the next object
    x509_crt->crt.next = NULL;
  }

  mbedtls_x509_crt_free(&x509_crt->crt);
  return 0;
}

static int x509_crt_gcmark(void *data, size_t len)
{
  (void)len;
  janetls_x509_crt_object * x509_crt = (janetls_x509_crt_object *)data;

  if (x509_crt->next_object != NULL)
  {
    janet_mark(janet_wrap_abstract(x509_crt->next_object));
  }

  janet_mark(x509_crt->der_source);

  return 0;
}

janetls_x509_crt_object * new_x509_crt()
{
  janetls_x509_crt_object * x509_crt = janet_abstract(&x509_crt_object_type, sizeof(janetls_x509_crt_object));
  memset(x509_crt, 0, sizeof(janetls_x509_crt_object));
  mbedtls_x509_crt_init(&x509_crt->crt);
  x509_crt->der_source = janet_wrap_nil();
  x509_crt->next_object = NULL;
  return x509_crt;
}

JanetAbstractType * janetls_x509_crt_object_type()
{
  return &x509_crt_object_type;
}

static const JanetReg cfuns[] =
{
  {"x509/from", x509_crt_from, "(janetls/x509/from cert1 cert2 ...)\n\n"
    "Receives an array or tuple of DER encoded strings"
    },
  {"x509/next", x509_crt_next, "(janetls/x509/next x509-crt)\n\n"
    "Finds the next certificate in the chain"
    },
  {"x509/der", x509_crt_der, "(janetls/x509/der 509-cert)\n\n"
    "Returns the der content used on this chain link"
    },
  {NULL, NULL, NULL}
};

void submod_x509(JanetTable * env)
{
  janet_cfuns(env, "janetls", cfuns);
  janet_register_abstract_type(&x509_crt_object_type);
}

static Janet x509_crt_from(int32_t argc, Janet * argv)
{
  Janet value = janet_wrap_nil();
  if (argc > 0)
  {
    janetls_x509_crt_object * last = NULL;
    for (int i = argc - 1; i >= 0; i--)
    {
      Janet der = argv[i];
      JanetByteView bytes = janet_to_bytes(der);

      if (!janet_checktype(der, JANET_STRING))
      {
        // Force it into a string type so that it does not change.
        der = janet_wrap_string(janet_string(bytes.bytes, bytes.len));
        bytes = janet_to_bytes(der);
      }

      janetls_x509_crt_object * crt = new_x509_crt();
      int result = mbedtls_x509_crt_parse_der_nocopy(&crt->crt, bytes.bytes, bytes.len);

      if (result < 0)
      {
        // Panic
        check_result(result);
      }

      crt->der_source = der;
      crt->next_object = last;
      // Link the next one so mbedtls can iterate
      crt->crt.next = &(last->crt);

      // Prepare this one to be linked to by the next one
      last = crt;

      if (i == 0)
      {
        // This is the last one, set the return value.
        value = janet_wrap_abstract(crt);
      }
    }
  }
  return value;
}

static Janet x509_crt_der(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_x509_crt_object * crt = janet_getabstract(argv, 0, &x509_crt_object_type);
  return crt->der_source;
}

static Janet x509_crt_next(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_x509_crt_object * crt = janet_getabstract(argv, 0, &x509_crt_object_type);
  if (crt->next_object == NULL)
  {
    return janet_wrap_nil();
  }
  return janet_wrap_abstract(crt->next_object);
}
