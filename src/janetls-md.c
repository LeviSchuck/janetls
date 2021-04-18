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
#include "janetls-encoding.h"

mbedtls_md_type_t symbol_to_alg(Janet value) {
  janetls_md_algorithm result = janetls_md_algorithm_none;
  int ret = janetls_search_md_supported_algorithms(value, &result);
  if (ret == JANETLS_ERR_SEARCH_OPTION_NOT_FOUND)
  {
    janet_panicf("Given algorithm %p is not expected, please review "
      "janetls/md/algorithms for supported values", value);
  }
  check_result(ret);
  return (mbedtls_md_type_t) result;
}

void assert_commands_consumed(int32_t argc, Janet * argv, int required, int optional)
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
  janetls_encoding_type encoding = janetls_encoding_type_hex;
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

int janetls_md_digest(Janet * result, janetls_md_algorithm algorithm, const Janet data)
{
  int ret = 0;
  if (!janet_is_byte_typed(data))
  {
    ret = JANETLS_ERR_INVALID_BOOLEAN_VALUE;
    goto end;
  }
  JanetByteView bytes = janet_to_bytes(data);

  const mbedtls_md_info_t * md_info;
  md_info = mbedtls_md_info_from_type((mbedtls_md_type_t)algorithm);

  if (md_info == NULL)
  {
    ret = JANETLS_ERR_MD_INVALID_ALGORITHM;
    goto end;
  }

  unsigned char digest[MBEDTLS_MD_MAX_SIZE];

  retcheck(mbedtls_md(md_info, bytes.bytes, bytes.len, digest));

  *result = janet_wrap_string(janet_string(digest, mbedtls_md_get_size(md_info)));
end:
  return 0;
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
#define DIGEST_HMAC     4

static int md_gc_fn(void *data, size_t len);
static int md_get_fn(void *data, Janet key, Janet * out);
static Janet md_start(int32_t argc, Janet * argv);
static Janet md_clone(int32_t argc, Janet * argv);
static Janet md_reset(int32_t argc, Janet * argv);
static Janet md_update(int32_t argc, Janet * argv);
static Janet md_finish(int32_t argc, Janet * argv);
static Janet md_size(int32_t argc, Janet * argv);
static Janet md_algorithm(int32_t argc, Janet * argv);
static Janet md(int32_t argc, Janet * argv);
static Janet hmac(int32_t argc, Janet * argv);
static Janet hmac_start(int32_t argc, Janet * argv);

JanetAbstractType digest_object_type = {
  "janetls/digest",
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
  {"reset", md_reset},
  {NULL, NULL}
};

static int md_gc_fn(void * data, size_t len)
{
  (void) len;
  digest_object * digest = (digest_object *)data;
  mbedtls_md_free(&digest->context);
  return 0;
}

static int md_get_fn(void * data, Janet key, Janet * out)
{
  digest_object * digest = (digest_object *)data;

  if (!janet_checktype(key, JANET_KEYWORD))
  {
    // Unexpected type, not found.
    return 0;
  }

  JanetKeyword method = janet_unwrap_keyword(key);

  if (digest->flags & DIGEST_HMAC && !janet_cstrcmp(method, "clone"))
  {
    // override.. clone doesn't work for HMACs.
    return 0;
  }

  return janet_getmethod(method, md_methods, out);
}


static const JanetReg cfuns[] =
{
  {"md/digest", md, "(janetls/md/digest alg str &opt encoding-type encoding-variant)\n\n"
    "Applies A message digest to the provided string, alg must be one of the "
    "keywords found in md/algorithms.\n"
    "The string may have any content as binary.\n"
    "Encoding types can be seen in janetls/encoding/types, variants are "
    "specific to types."
    },
  {"md/digest/start", md_start, "(janetls/md/digest/start alg)\n\n"
    "Applies A message digest to all update calls.\n"
    "To get the result, finish must be called, it may be called with optional "
    "encoding settings, much like janetls/md/digest. The finish call does not "
    "accept any digestable input."
    },
  {"md/update", md_update, "(janetls/md/update digest-or-hmac str)\n\n"
    "The string may have any content as binary.\n"
    "The digest object is returned for ease of use when folding over data."
    },
  {"md/clone", md_clone, "(janetls/md/update digest-or-hmac)\n\n"
    "Clone the digest in case you plan to gather intermediary results.\n"
    "A new digest object is returned, unless the input digest is finished."
    },
  {"md/reset", md_reset, "(janetls/md/update digest)\n\n"
    "Resets the digest in case you plan to gather intermediary results.\n"
    "A new digest object is returned, unless the input digest is finished.\n"
    "Unfortunately, HMACs cannot be cloned, an error will be thrown when "
    "this is attempted."
    },
  {"md/finish", md_finish, "(janetls/md/finish digest-or-hmac &opt encoding-type encoding-variant)\n\n"
    "Finish a message digest, this will produce a hash value encoded as requested.\n"
    "Once finished, a message digest cannot be updated or cloned.\n"
    "Finishing can be called multiple times with different encoding parameters.\n"
    "Encoding types can be seen in janetls/encoding/types, variants are "
    "specific to types.\n"
    "If you wish to reuse this object without allocating any new memory, "
    "janetls/md/reset can be called."
    },
  {"md/algorithm", md_algorithm, "(janetls/md/algorithm digest-or-hmac-or-alg)\n\n"
    "Inspect what algorithm is in use on an existing digest or hmac, or an "
    "algorithm as listed in janetls/md/algorithms"
    },
  {"md/size", md_size, "(janetls/md/size digest-or-hmac-or-alg)\n\n"
    "Inspect how many raw bytes an algorithm will produce upon finishing"
    },
  {"md/hmac", hmac, "(janetls/md/hmac alg key str &opt encoding-type encoding-variant)\n\n"
    "Applies HMAC to the the provided string, alg must be one of the keywords "
    "found in md/algorithms.\n"
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
  {"md/hmac/start", hmac_start, "(janetls/md/digest/start alg key)\n\n"
    "Applies An HMAC to all update calls.\n"
    "The key should be arbitrary data with the same byte count as the "
    "algorithm block size. For example, SHA-256 has a block size of 64 bytes. "
    "The key therefore should be 64 bytes in size.  If it is too long, it will "
    "be hashed automatically to become the HMAC key."
    "If it is too short, the remainder of the key will be 0-padded, though "
    "this is not recommended.\n"
    "The string may have any content as binary.\n"
    "To get the result, finish must be called, it may be called with optional "
    "encoding settings, much like janetls/md/digest. The finish call does not "
    "accept any digestable input.\n"
    "Should you wish to not keep the key around in janet memory, you can "
    "keep the HMAC object in memory but reset the HMAC as needed with "
    "janetls/md/reset. This will allow multiple update and finish calls on "
    "the same object."
    },
  {"md/algorithms", janetls_search_md_supported_algorithms_set, "(janetls/md/algorithms)\n\n"
    "Provides an tuple of keywords for available algorithms"},
  {NULL, NULL, NULL}
};

void submod_md(JanetTable *env)
{
  janet_cfuns(env, "janetls", cfuns);
  janet_register_abstract_type(&digest_object_type);
}

Janet md_hmac_start(Janet alg, Janet key, int hmac)
{
  mbedtls_md_type_t algorithm = symbol_to_alg(alg);
  JanetByteView key_bytes;
  if (hmac)
  {
    if (!janet_is_byte_typed(key))
    {
      janet_panicf("Expected a string or buffer for a key while preparing the "
      "HMAC, but got %p", key);
    }
    else
    {
      key_bytes = janet_to_bytes(key);
    }
  }
  else
  {
    // There is no key, Neo.
    key_bytes.bytes = 0;
    key_bytes.len = 0;
  }

  digest_object * digest = janet_abstract(&digest_object_type, sizeof(digest_object));
  mbedtls_md_init(&digest->context);
  digest->algorithm = algorithm;
  digest->info = mbedtls_md_info_from_type(algorithm);
  digest->flags = 0;

  if (hmac)
  {
    digest->flags |= DIGEST_HMAC;
  }

  if (digest->info == NULL)
  {
    digest->flags |= DIGEST_POISONED;
    janet_panicf("An internal error occurred, unable to get the algorithm %p", alg);
  }

  // Note that 0 here is a boolean on whether it is hmac
  if (mbedtls_md_setup(&digest->context, digest->info, hmac))
  {
    digest->flags |= DIGEST_POISONED;
    janet_panicf("An internal error occurred, unable to get the algorithm %p", alg);
  }

  if (hmac)
  {
    if (mbedtls_md_hmac_starts(&digest->context, key_bytes.bytes, key_bytes.len))
    {
      digest->flags |= DIGEST_POISONED;
      janet_panicf("An internal error occurred, unable to prepare the algorithm %p", alg);
    }
  }
  else
  {
    if (mbedtls_md_starts(&digest->context))
    {
      digest->flags |= DIGEST_POISONED;
      janet_panicf("An internal error occurred, unable to prepare the algorithm %p", alg);
    }
  }

  return janet_wrap_abstract(digest);
}

static Janet md_start(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  return md_hmac_start(argv[0], janet_wrap_nil(), 0);
}

static Janet hmac_start(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 2);

  return md_hmac_start(argv[0], argv[1], 1);
}

static Janet md_clone(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  digest_object * digest = janet_getabstract(argv, 0, &digest_object_type);
  digest_object * clone;

  if (digest->flags & DIGEST_POISONED)
  {
    janet_panic("An internal error has occurred, Was unable to clone "
      "message digestion, the message digest is poisoned.");
  }

  if (digest->flags & DIGEST_HMAC)
  {
    janet_panic("HMACs cannot be cloned, if you plan to reuse an HMAC, "
      "please look at using janetls/md/reset.");
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

static Janet md_update(int32_t argc, Janet * argv)
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
    if (digest->flags & DIGEST_HMAC)
    {
      janet_panic("This HMAC has already finished, therefore it cannot be "
        "updated with any further content. You may want to reset the HMAC "
        "so that more content can be HMACed.");
    }
    else
    {
      janet_panic("This digest has already finished, therefore it cannot be "
        "updated with any further content. You may want to clone the digest "
        "before finishing it, so that more content can be digested.");
    }
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

static Janet md_finish(int32_t argc, Janet * argv)
{
  janet_arity(argc, 1, 3);
  digest_object * digest = janet_getabstract(argv, 0, &digest_object_type);
  janetls_encoding_type encoding = janetls_encoding_type_hex;
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

  if (digest->flags & DIGEST_HMAC)
  {
    if (mbedtls_md_hmac_finish(&digest->context, digest->output))
    {
      digest->flags |= DIGEST_POISONED;
      janet_panicf("An internal error has occurred, Was unable to finish "
        "message digestion");
    }
  }
  else
  {
    if (mbedtls_md_finish(&digest->context, digest->output))
    {
      digest->flags |= DIGEST_POISONED;
      janet_panicf("An internal error has occurred, Was unable to finish "
        "message digestion");
    }
  }

  digest->flags |= DIGEST_FINISHED;

  return content_to_encoding(digest->output, mbedtls_md_get_size(digest->info), encoding, variant);
}

static Janet md_reset(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);

  digest_object * digest = janet_getabstract(argv, 0, &digest_object_type);

  if (digest->flags & DIGEST_HMAC)
  {
    // This re-initializes the digest with the existing algorithm and
    // then re-applies the inner padding to the digest engine.
    if (mbedtls_md_hmac_reset(&digest->context))
    {
      digest->flags |= DIGEST_POISONED;
      janet_panicf("An internal error occurred, unable to reset the HMAC");
    }
  }
  else
  {
    // Re-initializes the digest with the existing algorithm.
    // This is what's done in mbedtls_md_hmac_reset before
    // applying the inner padding.
    if (mbedtls_md_starts(&digest->context))
    {
      digest->flags |= DIGEST_POISONED;
      janet_panicf("An internal error occurred, unable to reset the digest");
    }
  }

  // clear the finished flag
  digest->flags &= ~(DIGEST_FINISHED);

  return janet_wrap_abstract(digest);
}

static Janet md_size(int32_t argc, Janet * argv)
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

static Janet md_algorithm(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  digest_object * digest = janet_getabstract(argv, 0, &digest_object_type);
  return janetls_search_md_supported_algorithms_to_janet((janetls_md_algorithm)digest->algorithm);
}

static Janet hmac(int32_t argc, Janet * argv)
{
  janet_arity(argc, 3, 5);

  mbedtls_md_type_t algorithm = symbol_to_alg(argv[0]);
  JanetByteView key = janet_getbytes(argv, 1);
  JanetByteView data = janet_getbytes(argv, 2);
  janetls_encoding_type encoding = janetls_encoding_type_hex;
  int variant = 0;
  int consumed = extract_encoding(argc, argv, 3, &encoding, &variant);

  assert_commands_consumed(argc, argv, 3, consumed);

  const mbedtls_md_info_t *md_info;
  md_info = mbedtls_md_info_from_type(algorithm);
  unsigned char digest[MBEDTLS_MD_MAX_SIZE];

  if (mbedtls_md_hmac(md_info, key.bytes, key.len, data.bytes, data.len, digest))
  {
    janet_panicf("Unable to execute HMAC for algorithm %p on "
      "input %p", argv[0], argv[1]);
  }

  return content_to_encoding(digest, mbedtls_md_get_size(md_info), encoding, variant);
}