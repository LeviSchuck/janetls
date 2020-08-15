/*
Copyright (c) 2020 Levi Schuck

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "janetls.h"


typedef struct janetls_base64_variant_option {
  base64_variant variant;
  char option[20];
} janetls_base64_variant_option;

janetls_base64_variant_option base64_variants[] = {
  {PEM,"pem"},
  {MIME,"mime"},
  {IMAP,"imap"},
  {STANDARD,"standard"},
  {STANDARD_UNPADDED,"standard-unpadded"},
  {URL,"url"},
  {URL_UNPADDED,"url-unpadded"},
  {PGP,"pgp"},
};

#define BASE64_VARIANT_COUNT (sizeof(base64_variants) / sizeof(janetls_base64_variant_option))

Janet hex_encoder(int argc, Janet * argv)
{
  janet_fixarity(argc, 1);

  JanetByteView data = janet_getbytes(argv, 0);
  return hex_string(data.bytes, data.len);
}

base64_variant get_base64_variant(int argc, Janet * argv, int index)
{
  base64_variant variant = STANDARD;

  if (index < argc)
  {
    // Parse option
    JanetKeyword keyword = janet_getkeyword(argv, index);
    int32_t size = BASE64_VARIANT_COUNT;
    uint8_t found = 0;
    for (int i = 0; i < size; i++)
    {
      if (!janet_cstrcmp(keyword, base64_variants[i].option))
      {
        variant = base64_variants[i].variant;
        found = 1;
        break;
      }
    }
    if (!found)
    {
      janet_panicf("Given option %S is not expected, please review util/encode/base64 for supported options", keyword);
    }
  }

  return variant;
}

static Janet base64_variants_set(int32_t argc, Janet *argv)
{
  janet_fixarity(argc, 0);
  int32_t size = BASE64_VARIANT_COUNT;
  // Construct result
  Janet values[size];
  for (int i = 0; i < size; i++)
  {
    values[i] = janet_ckeywordv(base64_variants[i].option);
  }

  return janet_wrap_tuple(janet_tuple_n(values, size));
}

Janet base64_encoder(int argc, Janet * argv)
{
  janet_arity(argc, 1, 2);
  JanetByteView data = janet_getbytes(argv, 0);
  base64_variant variant = get_base64_variant(argc, argv, 1);
  return base64_encode(data.bytes, data.len, variant);
}

Janet base64_decoder(int argc, Janet * argv)
{
  janet_arity(argc, 1, 2);
  JanetByteView data = janet_getbytes(argv, 0);
  base64_variant variant = get_base64_variant(argc, argv, 1);
  return base64_decode(data.bytes, data.len, variant);
}

static const JanetReg cfuns[] =
{
  {"hex/encode", hex_encoder,
    "(janetls/encode/hex str)\n\n"
    "Encodes an arbitrary string as hex."
    },
  {"base64/encode", base64_encoder,
    "(janetls/base64/encode str optional-variant)\n\n"
    "Permitted variants are described in (janetls/base64/variants). "
    "It will by by default :standard"
    },
  {"base64/decode", base64_decoder,
    "(janetls/base64/decode str optional-variant)\n\n"
    "Permitted variants are described in (janetls/base64/variants). "
    "It will by by default :standard"
    },
  {"base64/variants", base64_variants_set,
    "(janetls/base64/variants)\n\n"
    "Enumerates acceptable variants for other base64 functions"
    },
  {NULL, NULL, NULL}
};

void submod_util(JanetTable *env)
{
  janet_cfuns(env, "janetls", cfuns);
}
