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
#include "janetls-md.h"

struct janetls_supported_algorithm {
  mbedtls_md_type_t type;
  char * algorithm;
};
typedef struct janetls_supported_algorithm janetls_supported_algorithm;

janetls_supported_algorithm supported_algorithms[] = {
  {MBEDTLS_MD_MD5, "md5"},
  {MBEDTLS_MD_SHA1, "sha1"},
  {MBEDTLS_MD_SHA224, "sha224"},
  {MBEDTLS_MD_SHA256, "sha256"},
  {MBEDTLS_MD_SHA384, "sha384"},
  {MBEDTLS_MD_SHA512, "sha512"},
  {MBEDTLS_MD_NONE, NULL}
};

mbedtls_md_type_t symbol_to_alg(JanetKeyword keyword) {
  int i = 0;
  for (;;i++) {
    if (supported_algorithms[i].algorithm == NULL)
    {
      break;
    }
    if (!janet_cstrcmp(keyword, supported_algorithms[i].algorithm))
    {
      return supported_algorithms[i].type;
    }
  }

  return MBEDTLS_MD_NONE;
}

// TODO add encoding parameter (hex, base64, binary)
static Janet md(int32_t argc, Janet *argv) 
{
  janet_fixarity(argc, 2);

  const uint8_t * sym = janet_getkeyword(argv, 0);
  const uint8_t * str = janet_getstring(argv, 1);
  int length = janet_string_length(str);

  mbedtls_md_type_t algorithm = symbol_to_alg(sym);
  if (algorithm == MBEDTLS_MD_NONE) {
    janet_panicf("Given algorithm %s is not expected", sym);
  }

  const mbedtls_md_info_t *md_info;
  md_info = mbedtls_md_info_from_type(algorithm);
  unsigned char digest[MBEDTLS_MD_MAX_SIZE];

  if (mbedtls_md(md_info, str, length, digest)) 
  {
    janet_panicf("Unable to execute message digest for algorithm %s on input %s", sym, str);
  }

  return hex_string(digest, mbedtls_md_get_size(md_info));
}

static Janet algorithms(int32_t argc, Janet *argv)
{
  janet_fixarity(argc, 0);
  // Get size of algorithm list
  int size = 0;
  for (;;size++) {
    if (supported_algorithms[size].algorithm == NULL)
    {
      break;
    }
  }

  // Construct result 
  Janet values[size];
  for (int i = 0; i < size; i++) {
    values[i] = janet_ckeywordv(supported_algorithms[i].algorithm);
  }

  return janet_wrap_tuple(janet_tuple_n(values, size));
}

static const JanetReg cfuns[] = 
{
  {"md/digest", md, "(janetls/md/digest alg str)\n\n"
    "Applies A message digest to the function, alg must be one of keywords "
    ":md5, :sha1, :sha224, :sha256, :sha334, :sha512. "
    "The string may have any content as binary."
    },
  {"md/algorithms", algorithms, "(janetls/md/algorithms)\n\n"
    "Provides an array of keywords for available algorithms"},
  {NULL, NULL, NULL}
};

void submod_md(JanetTable *env) 
{
  janet_cfuns(env, "janetls", cfuns);
}
