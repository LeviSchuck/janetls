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

typedef struct janetls_digest_algorithms {
  mbedtls_md_type_t type;
  char algorithm[20];
} janetls_digest_algorithms;

janetls_digest_algorithms supported_algorithms[] = {
  {MBEDTLS_MD_MD5, "md5"},
  {MBEDTLS_MD_SHA1, "sha1"},
  {MBEDTLS_MD_SHA224, "sha224"},
  {MBEDTLS_MD_SHA256, "sha256"},
  {MBEDTLS_MD_SHA384, "sha384"},
  {MBEDTLS_MD_SHA512, "sha512"},
};

// If you use fixed sizes for things like strings
// Then you can determine the size this way
// Rather than looping over it until you find null.
#define SUPPORTED_ALG_COUNT (sizeof(supported_algorithms) / sizeof(janetls_digest_algorithms))

mbedtls_md_type_t symbol_to_alg(JanetKeyword keyword) {
  int32_t size = SUPPORTED_ALG_COUNT;
  for (int i = 0; i < size; i++)
  {
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
  const uint8_t * data = NULL;
  Janet data_value = argv[1];
  int length = 0;
  JanetBuffer * buffer;
  JanetType data_type = janet_type(data_value);

  mbedtls_md_type_t algorithm = symbol_to_alg(sym);
  if (algorithm == MBEDTLS_MD_NONE)
  {
    janet_panicf("Given algorithm %S is not expected, please review md/algorithms for supported values", sym);
  }

  switch (data_type)
  {
    case JANET_STRING:
    data = janet_unwrap_string(data_value);
    length = janet_string_length(data);
    break;

    case JANET_BUFFER:
    buffer = janet_unwrap_buffer(data_value);
    data = buffer->data;
    length = buffer->count;
    break;

    default:
    janet_panicf("bad slot #%d, expected string or buffer, got %v", 1, data_value);
    // unreachable, but for consistency.
    break;
  }

  const mbedtls_md_info_t *md_info;
  md_info = mbedtls_md_info_from_type(algorithm);
  unsigned char digest[MBEDTLS_MD_MAX_SIZE];

  if (mbedtls_md(md_info, data, length, digest)) 
  {
    janet_panicf("Unable to execute message digest for algorithm %S on input %s", sym, data);
  }

  return hex_string(digest, mbedtls_md_get_size(md_info));
}

static Janet algorithms(int32_t argc, Janet *argv)
{
  janet_fixarity(argc, 0);
  int32_t size = SUPPORTED_ALG_COUNT;
  // Construct result 
  Janet values[size];
  for (int i = 0; i < size; i++) 
  {
    values[i] = janet_ckeywordv(supported_algorithms[i].algorithm);
  }

  return janet_wrap_tuple(janet_tuple_n(values, size));
}

static const JanetReg cfuns[] = 
{
  {"md/digest", md, "(janetls/md/digest alg str)\n\n"
    "Applies A message digest to the function, alg must be one of keywords "
    " seen in md/algorithms."
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
