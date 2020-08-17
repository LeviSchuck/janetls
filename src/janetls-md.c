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
#include "janetls-md.h"

typedef struct janetls_digest_algorithms {
  mbedtls_md_type_t type;
  char algorithm[20];
} janetls_digest_algorithms;

option_list_entry supported_algorithms[] = {
  {MBEDTLS_MD_MD5, "md5", 0},
  {MBEDTLS_MD_SHA1, "sha1", 0},
  {MBEDTLS_MD_SHA1, "sha-1", OPTION_LIST_HIDDEN},
  {MBEDTLS_MD_SHA224, "sha224", 0},
  {MBEDTLS_MD_SHA256, "sha256", 0},
  {MBEDTLS_MD_SHA384, "sha384", 0},
  {MBEDTLS_MD_SHA512, "sha512", 0},
  {MBEDTLS_MD_SHA224, "sha-224", OPTION_LIST_HIDDEN},
  {MBEDTLS_MD_SHA256, "sha-256", OPTION_LIST_HIDDEN},
  {MBEDTLS_MD_SHA384, "sha-384", OPTION_LIST_HIDDEN},
  {MBEDTLS_MD_SHA512, "sha-512", OPTION_LIST_HIDDEN},
};

// If you use fixed sizes for things like strings
// Then you can determine the size this way
// Rather than looping over it until you find null.
#define SUPPORTED_ALG_COUNT (sizeof(supported_algorithms) / sizeof(option_list_entry))

mbedtls_md_type_t symbol_to_alg(Janet value) {
  if (janet_is_byte_typed(value))
  {
    int type = MBEDTLS_MD_NONE;
    if (search_option_list(supported_algorithms, SUPPORTED_ALG_COUNT, janet_to_bytes(value), &type))
    {
      return (mbedtls_md_type_t) type;
    }
  }

  janet_panicf("Given algorithm %p is not expected, please review "
    "janetls/md/algorithms for supported values", value);
  // unreachable
  return MBEDTLS_MD_NONE;
}

// TODO add encoding parameter (hex, base64, binary)
static Janet md(int32_t argc, Janet *argv)
{
  janet_fixarity(argc, 2);

  mbedtls_md_type_t algorithm = symbol_to_alg(argv[0]);
  JanetByteView data = janet_getbytes(argv, 1);

  const mbedtls_md_info_t *md_info;
  md_info = mbedtls_md_info_from_type(algorithm);
  unsigned char digest[MBEDTLS_MD_MAX_SIZE];

  if (mbedtls_md(md_info, data.bytes, data.len, digest))
  {
    janet_panicf("Unable to execute message digest for algorithm %p on "
      "input %p", argv[0], argv[1]);
  }

  // TODO make encoding configurable
  return hex_encode(digest, mbedtls_md_get_size(md_info));
}

static Janet md_algorithms_set(int32_t argc, Janet *argv)
{
  janet_fixarity(argc, 0);
  return enumerate_option_list(supported_algorithms, SUPPORTED_ALG_COUNT);
}

static const JanetReg cfuns[] =
{
  {"md/digest", md, "(janetls/md/digest alg str &opt encodng-type)\n\n"
    "Applies A message digest to the function, alg must be one of keywords "
    "seen in md/algorithms.\n"
    "The string may have any content as binary."
    },
  {"md/algorithms", md_algorithms_set, "(janetls/md/algorithms)\n\n"
    "Provides an array of keywords for available algorithms"},
  {NULL, NULL, NULL}
};

void submod_md(JanetTable *env)
{
  janet_cfuns(env, "janetls", cfuns);
}
