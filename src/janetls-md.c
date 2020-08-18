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

void assert_commands_consumed(int32_t argc, Janet *argv, int required, int optional)
{
  // Two parameters are required, hence the hard coded 2.
  // Namely: the algorithm and data
  if (required + optional < argc)
  {
    // Some arguments were not able to be used, yet were provided.
    if (required + 1 == 3)
    {
      janet_panicf("Some encoding parameters could not be used, please review "
        "janetls/encoding/types. %p was provided.", argv[required]);
    }
    else if (required + 2 == 4)
    {
      janet_panicf("Some encoding parameters could not be used, please review "
        "janetls/encoding/types and relevant variants. %p %p was provided.",
        argv[required], argv[required + 1]);
    }
  }
}

static Janet md(int32_t argc, Janet * argv)
{
  janet_arity(argc, 2, 4);

  mbedtls_md_type_t algorithm = symbol_to_alg(argv[0]);
  JanetByteView data = janet_getbytes(argv, 1);
  content_encoding encoding = HEX;
  int variant = 0;
  int consumed = extract_encoding(argc, argv, 2, &encoding, &variant);

  assert_commands_consumed(argc, argv, 2, consumed);

  const mbedtls_md_info_t *md_info;
  md_info = mbedtls_md_info_from_type(algorithm);
  unsigned char digest[MBEDTLS_MD_MAX_SIZE];

  if (mbedtls_md(md_info, data.bytes, data.len, digest))
  {
    janet_panicf("Unable to execute message digest for algorithm %p on "
      "input %p", argv[0], argv[1]);
  }

  return content_to_encoding(digest, mbedtls_md_get_size(md_info), encoding, variant);
}

typedef struct digest_object {
  mbedtls_md_type_t algorithm;
  const mbedtls_md_info_t * info;
  mbedtls_md_context_t context;
  uint8_t output[MBEDTLS_MD_MAX_SIZE];
  uint8_t flags;
} digest_object;

#define DIGEST_POISONED 1
#define DIGEST_FINISHED 2

static int md_gc_fn(void *data, size_t len);
static int md_get_fn(void *data, Janet key, Janet * out);
static Janet md_clone(int32_t argc, Janet *argv);
static Janet md_update(int32_t argc, Janet *argv);
static Janet md_finish(int32_t argc, Janet *argv);
static Janet md_size(int32_t argc, Janet *argv);
static Janet md_algorithm(int32_t argc, Janet *argv);

JanetAbstractType digest_object_type = {
  "digest",
  md_gc_fn,
  NULL,
  md_get_fn,
  JANET_ATEND_GET
};

static JanetMethod md_methods[] = {
  {"clone", md_clone},
  {"update", md_update},
  {"finish", md_finish},
  {"size", md_size},
  {"algorithm", md_algorithm},
  {NULL, NULL}
};

static int md_gc_fn(void * data, size_t len)
{
  (void) len;
  digest_object * digest = (digest_object *)data;
  mbedtls_md_free(&digest->context);
  return 0;
}

static int md_get_fn(void *data, Janet key, Janet * out)
{
  (void) data;

  if (!janet_checktype(key, JANET_KEYWORD))
  {
    janet_panicf("expected keyword, got %p", key);
  }

  return janet_getmethod(janet_unwrap_keyword(key), md_methods, out);
}

static Janet md_start(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  mbedtls_md_type_t algorithm = symbol_to_alg(argv[0]);
  digest_object * digest = janet_abstract(&digest_object_type, sizeof(digest_object));
  mbedtls_md_init(&digest->context);
  digest->algorithm = algorithm;
  digest->info = mbedtls_md_info_from_type(algorithm);
  digest->flags = 0;

  if (digest->info == NULL)
  {
    digest->flags |= DIGEST_POISONED;
    janet_panicf("An internal error occurred, unable to get the algorithm %p", argv[0]);
  }

  // Note that 0 here is a boolean on whether it is hmac
  if (mbedtls_md_setup(&digest->context, digest->info, 0))
  {
    digest->flags |= DIGEST_POISONED;
    janet_panicf("An internal error occurred, unable to get the algorithm %p", argv[0]);
  }

  if (mbedtls_md_starts(&digest->context))
  {
    digest->flags |= DIGEST_POISONED;
    janet_panicf("An internal error occurred, unable to prepare the algorithm %p", argv[0]);
  }

  return janet_wrap_abstract(digest);
}

static Janet md_clone(int32_t argc, Janet *argv)
{
  janet_fixarity(argc, 1);
  digest_object * digest = janet_getabstract(argv, 0, &digest_object_type);
  digest_object * clone;

  if (digest->flags & DIGEST_POISONED)
  {
    janet_panic("An internal error has occurred, Was unable to clone "
      "message digestion, the message digest is poisoned.");
  }

  if (digest->flags & DIGEST_FINISHED)
  {
    // Once finished, the digest becomes immutable.
    return janet_wrap_abstract(digest);
  }

  clone = janet_abstract(&digest_object_type, sizeof(digest_object));

  memcpy(clone, digest, sizeof(digest_object));
  mbedtls_md_init(&clone->context);

  if (mbedtls_md_setup(&clone->context, clone->info, 0))
  {
    clone->flags |= DIGEST_POISONED;
    janet_panicf("An internal error occurred, unable clone the digest object");
  }

  if (mbedtls_md_clone(&clone->context, &digest->context))
  {
    clone->flags |= DIGEST_POISONED;
    janet_panicf("An internal error occurred, unable to clone the digest object");
  }

  return janet_wrap_abstract(clone);
}

static Janet md_update(int32_t argc, Janet *argv)
{
  janet_fixarity(argc, 2);

  digest_object * digest = janet_getabstract(argv, 0, &digest_object_type);

  if (digest->flags & DIGEST_POISONED)
  {
    janet_panic("An internal error has occurred, Was unable to update "
      "message digestion, the message digest is poisoned.");
  }

  if (digest->flags & DIGEST_FINISHED)
  {
    janet_panic("This digest has already finished, therefore it cannot be "
      "updated with any further content. You may want to clone the digest "
      "before finishing it, so that more content can be digested.");
  }

  if (!janet_is_byte_typed(argv[1]))
  {
    janet_panicf("Expected a string or buffer while updating the message "
      "digest, but got %p", argv[1]);
  }

  JanetByteView bytes = janet_to_bytes(argv[1]);

  if (bytes.len > 0)
  {
    if (mbedtls_md_update(&digest->context, bytes.bytes, bytes.len))
    {
      digest->flags |= DIGEST_POISONED;
      janet_panicf("An internal error has occurred, Was unable to digest %p", argv[1]);
    }
  }

  return janet_wrap_abstract(digest);
}

static Janet md_finish(int32_t argc, Janet *argv)
{
  janet_arity(argc, 1, 3);
  digest_object * digest = janet_getabstract(argv, 0, &digest_object_type);
  content_encoding encoding = HEX;
  int variant = 0;
  int consumed = extract_encoding(argc, argv, 1, &encoding, &variant);

  // Check that all arguments have been consumed.
  assert_commands_consumed(argc, argv, 1, consumed);

  if (digest->flags & DIGEST_POISONED)
  {
    janet_panicf("An internal error has occurred, Was unable to finish "
      "message digestion, the message digest is poisoned.");
  }

  if (digest->flags & DIGEST_FINISHED)
  {
    // Don't bother finishing it twice, this will actually mutate the
    // digest further into something unrecognizable.
    return content_to_encoding(digest->output, mbedtls_md_get_size(digest->info), encoding, variant);
  }

  if (mbedtls_md_finish(&digest->context, digest->output))
  {
    digest->flags |= DIGEST_POISONED;
    janet_panicf("An internal error has occurred, Was unable to finish "
      "message digestion");
  }
  digest->flags |= DIGEST_FINISHED;

  return content_to_encoding(digest->output, mbedtls_md_get_size(digest->info), encoding, variant);
}

static Janet md_size(int32_t argc, Janet *argv)
{
  janet_fixarity(argc, 1);
  int size = 0;
  if (janet_type(argv[0]) == JANET_ABSTRACT)
  {
    digest_object * digest = janet_getabstract(argv, 0, &digest_object_type);
    size = mbedtls_md_get_size(digest->info);
  }
  else if (janet_is_byte_typed(argv[0]))
  {
    size = mbedtls_md_get_size(mbedtls_md_info_from_type(symbol_to_alg(argv[0])));
  }
  else
  {
    janet_panicf("Expected a message digest or a keyword identifying the "
      "algorithm to get a size from. But got %p", argv[0]);
  }

  return janet_wrap_integer(size);
}

static Janet md_algorithm(int32_t argc, Janet *argv)
{
  janet_fixarity(argc, 1);
  digest_object * digest = janet_getabstract(argv, 0, &digest_object_type);
  return value_to_option(supported_algorithms, SUPPORTED_ALG_COUNT, digest->algorithm);
}

static Janet hmac(int32_t argc, Janet * argv)
{
  janet_arity(argc, 3, 5);

  mbedtls_md_type_t algorithm = symbol_to_alg(argv[0]);
  JanetByteView key = janet_getbytes(argv, 1);
  JanetByteView data = janet_getbytes(argv, 2);
  content_encoding encoding = HEX;
  int variant = 0;
  int consumed = extract_encoding(argc, argv, 3, &encoding, &variant);

  assert_commands_consumed(argc, argv, 3, consumed);

  const mbedtls_md_info_t *md_info;
  md_info = mbedtls_md_info_from_type(algorithm);
  unsigned char digest[MBEDTLS_MD_MAX_SIZE];

  if (mbedtls_md_hmac(md_info, key.bytes, key.len, data.bytes, data.len, digest))
  {
    janet_panicf("Unable to execute hmac for algorithm %p on "
      "input %p", argv[0], argv[1]);
  }

  return content_to_encoding(digest, mbedtls_md_get_size(md_info), encoding, variant);
}


static Janet md_algorithms_set(int32_t argc, Janet *argv)
{
  janet_fixarity(argc, 0);
  return enumerate_option_list(supported_algorithms, SUPPORTED_ALG_COUNT);
}

static const JanetReg cfuns[] =
{
  {"md/digest", md, "(janetls/md/digest alg str &opt encoding-type encoding-variant)\n\n"
    "Applies A message digest to the function, alg must be one of keywords "
    "seen in md/algorithms.\n"
    "The string may have any content as binary.\n"
    "Encoding types can be seen in janetls/encoding/types, variants are "
    "specific to types."
    },
  {"md/digest/start", md_start, "(janetls/md/digest/start alg)\n\n"
    "Applies A message digest to all update calls.\n"
    "The string may have any content as binary.\n"
    "To get the result, finish must be called, it may be called with optional "
    "encoding settings, much like janetls/md/digest. The finish call does not "
    "accept any digestable input."
    },
  {"md/digest/update", md_update, "(janetls/md/digest/update digest str)\n\n"
    "The string may have any content as binary.\n"
    "The digest object is returned for ease of use when folding over data."
    },
  {"md/digest/clone", md_clone, "(janetls/md/digest/update digest)\n\n"
    "Clone the digest in case you plan to gather intermediary results.\n"
    "A new digest object is returned, unless the input digest is finished."
    },
  {"md/digest/finish", md_finish, "(janetls/md/digest/finish digest &opt encoding-type encoding-variant)\n\n"
    "Finish a message digest, this will produce a hash value encoded as requested.\n"
    "Once finished, a message digest cannot be updated or cloned.\n"
    "Finishing can be called multiple times with different encoding parameters.\n"
    "Encoding types can be seen in janetls/encoding/types, variants are "
    "specific to types."
    },
  {"md/digest/algorithm", md_algorithm, "(janetls/md/digest/algorithm digest-or-alg)\n\n"
    "Inspect what algorithm is in use on an existing digest, or an algorithm "
    "as listed in janetls/md/algorithms"
    },
  {"md/digest/size", md_size, "(janetls/md/digest/size digest)\n\n"
    "Inspect how many raw bytes an algorithm will produce upon finishing"
    },
  {"md/hmac", hmac, "(janetls/md/hmac alg key str &opt encoding-type encoding-variant)\n\n"
    "Applies A message hmac to the function, alg must be one of keywords "
    "seen in md/algorithms.\n"
    "The key should be arbitrary data with the same byte count as the "
    "algorithm block size. For example, SHA-256 has a block size of 64 bytes. "
    "The key therefore should be 64 bytes in size.  If it is too long, it will "
    "be hashed automatically to become the hmac key."
    "If it is too short, the remainder of the key will be 0-padded, though "
    "this is not recommended.\n"
    "The string may have any content as binary.\n"
    "Encoding types can be seen in janetls/encoding/types, variants are "
    "specific to types."
    },
  {"md/algorithms", md_algorithms_set, "(janetls/md/algorithms)\n\n"
    "Provides an array of keywords for available algorithms"},
  {NULL, NULL, NULL}
};

void submod_md(JanetTable *env)
{
  janet_cfuns(env, "janetls", cfuns);
}
