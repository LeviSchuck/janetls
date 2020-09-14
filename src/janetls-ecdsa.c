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
#include "janetls-ecdsa.h"


static int ecdsa_gc_fn(void * data, size_t len);
static int ecdsa_gcmark(void * data, size_t len);
static int ecdsa_get_fn(void * data, Janet key, Janet * out);

static Janet ecdsa_is_private(int32_t argc, Janet * argv);
static Janet ecdsa_is_public(int32_t argc, Janet * argv);
static Janet ecdsa_sign(int32_t argc, Janet * argv);
static Janet ecdsa_verify(int32_t argc, Janet * argv);
static Janet ecdsa_export_public(int32_t argc, Janet * argv);
static Janet ecdsa_export_private(int32_t argc, Janet * argv);
static Janet ecdsa_get_digest(int32_t argc, Janet * argv);
static Janet ecdsa_get_sizebits(int32_t argc, Janet * argv);
static Janet ecdsa_get_sizebytes(int32_t argc, Janet * argv);
static Janet ecdsa_get_group(int32_t argc, Janet * argv);
static Janet ecdsa_import(int32_t argc, Janet * argv);
static Janet ecdsa_generate(int32_t argc, Janet * argv);

JanetAbstractType ecdsa_object_type = {
  "janetls/ecdsa",
  ecdsa_gc_fn,
  ecdsa_gcmark,
  ecdsa_get_fn,
  JANET_ATEND_GET
};

static JanetMethod ecdsa_methods[] = {
  {"private?", ecdsa_is_private},
  {"public?", ecdsa_is_public},
  {"group", ecdsa_get_group},
  {"digest", ecdsa_get_digest},
  {"verify", ecdsa_verify},
  {"sign", ecdsa_sign},
  {"bits", ecdsa_get_sizebits},
  {"bytes", ecdsa_get_sizebytes},
  {"export-public", ecdsa_export_public},
  {"export-private", ecdsa_export_private},
  {NULL, NULL}
};

static const JanetReg cfuns[] =
{
  {"ecdsa/sign", ecdsa_sign, "(janetls/ecdsa/sign ecdsa data &opt alg)\n\n"
    "A Private key operation, sign the input data with the given key.\n"
    "When an algorithm is provided, it overrides the default algorithm on "
    "this key for signatures. It's probably best to set the algorithm "
    "on key import or generation instead.\n"
    "A binary string is returned, this is the signature to provide to "
    "a verifier. In the case of ECDSA, it comes in two parts, R,S which are "
    "two X coordinates in the curve group's prime field."
    },
  {"ecdsa/verify", ecdsa_verify, "(janetls/ecdsa/verify ecdsa alg data &opt sig)\n\n"
    "A Public key operation, verify the input data with the given public point "
    "with the binary signature.\n"
    "The algorithm must be a value in janetls/md/algorithms.\n"
    "Usually a false return when the data has been modified, or the signature "
    "was made with another key (or is just noise).\n"
    "A true or false is returned."
    },
  {"ecdsa/generate", ecdsa_generate, ""},
  {"ecdsa/import", ecdsa_import, ""},
  {"ecdsa/private?", ecdsa_is_private, ""},
  {"ecdsa/public?", ecdsa_is_public, ""},
  {"ecdsa/group", ecdsa_get_group, ""},
  {"ecdsa/digest", ecdsa_get_digest, ""},
  {"ecdsa/verify", ecdsa_verify, ""},
  {"ecdsa/sign", ecdsa_sign, ""},
  {"ecdsa/bits", ecdsa_get_sizebits, ""},
  {"ecdsa/bytes", ecdsa_get_sizebytes, ""},
  {"ecdsa/export-public", ecdsa_export_public, ""},
  {"ecdsa/export-private", ecdsa_export_private, ""},
  {NULL, NULL, NULL}
};

void submod_ecdsa(JanetTable * env)
{
  janet_cfuns(env, "janetls", cfuns);
}

janetls_ecdsa_object * janetls_new_ecdsa()
{
  janetls_ecdsa_object * ecdsa = janet_abstract(&ecdsa_object_type, sizeof(janetls_ecdsa_object));
  memset(ecdsa, 0, sizeof(janetls_ecdsa_object));
  return ecdsa;
}

JanetAbstractType * janetls_ecdsa_object_type()
{
  return &ecdsa_object_type;
}

static int ecdsa_get_fn(void * data, Janet key, Janet * out)
{
  (void)data;

  if (!janet_checktype(key, JANET_KEYWORD))
  {
    janet_panicf("expected keyword, got %p", key);
  }

  return janet_getmethod(janet_unwrap_keyword(key), ecdsa_methods, out);
}

static int ecdsa_gc_fn(void * data, size_t len)
{
  (void)len;
  (void)data;
  return 0;
}

static int ecdsa_gcmark(void *data, size_t len)
{
  (void)len;
  janetls_ecdsa_object * ecdsa = (janetls_ecdsa_object *)data;

  if (ecdsa->group != NULL)
  {
    janet_mark(janet_wrap_abstract(ecdsa->group));
  }
  if (ecdsa->point != NULL)
  {
    janet_mark(janet_wrap_abstract(ecdsa->point));
  }
  if (ecdsa->keypair != NULL)
  {
    janet_mark(janet_wrap_abstract(ecdsa->keypair));
  }
  if (ecdsa->random != NULL)
  {
    janet_mark(janet_wrap_abstract(ecdsa->random));
  }

  return 0;
}

static Janet ecdsa_is_private(int32_t argc, Janet * argv)
{
  return janet_wrap_nil();
}

static Janet ecdsa_is_public(int32_t argc, Janet * argv)
{
  return janet_wrap_nil();
}

static Janet ecdsa_sign(int32_t argc, Janet * argv)
{
  return janet_wrap_nil();
}

static Janet ecdsa_verify(int32_t argc, Janet * argv)
{
  return janet_wrap_nil();
}

static Janet ecdsa_export_public(int32_t argc, Janet * argv)
{
  return janet_wrap_nil();
}

static Janet ecdsa_export_private(int32_t argc, Janet * argv)
{
  return janet_wrap_nil();
}

static Janet ecdsa_get_digest(int32_t argc, Janet * argv)
{
  return janet_wrap_nil();
}

static Janet ecdsa_get_sizebits(int32_t argc, Janet * argv)
{
  return janet_wrap_nil();
}

static Janet ecdsa_get_sizebytes(int32_t argc, Janet * argv)
{
  return janet_wrap_nil();
}

static Janet ecdsa_get_group(int32_t argc, Janet * argv)
{
  return janet_wrap_nil();
}

static Janet ecdsa_import(int32_t argc, Janet * argv)
{
  return janet_wrap_nil();
}

static Janet ecdsa_generate(int32_t argc, Janet * argv)
{
  return janet_wrap_nil();
}

