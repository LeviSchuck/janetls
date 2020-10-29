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
#include "janetls-random.h"
#include "janetls-chachapoly.h"
#include "mbedtls/platform_util.h"
#define FLAG_FINISH 1

// Abstract Object functions
static int chachapoly_gc_fn(void * data, size_t len);
static int chachapoly_gcmark(void * data, size_t len);
static int chachapoly_get_fn(void * data, Janet key, Janet * out);

// Janet functions
static Janet chachapoly_start(int32_t argc, Janet * argv);
static Janet chachapoly_update(int32_t argc, Janet * argv);
static Janet chachapoly_finish(int32_t argc, Janet * argv);
static Janet chachapoly_key(int32_t argc, Janet * argv);
static Janet chachapoly_nonce(int32_t argc, Janet * argv);
static Janet chachapoly_ad(int32_t argc, Janet * argv);
static Janet chachapoly_tag(int32_t argc, Janet * argv);

static JanetAbstractType chachapoly_object_type = {
  "janetls/chachapoly",
  chachapoly_gc_fn,
  chachapoly_gcmark,
  chachapoly_get_fn,
  JANET_ATEND_GET
};

static JanetMethod chachapoly_methods[] = {
  {"update", chachapoly_update},
  {"finish", chachapoly_finish},
  {"key", chachapoly_key},
  {"nonce", chachapoly_nonce},
  {"tag", chachapoly_tag},
  {"ad", chachapoly_ad},
  {NULL, NULL},
};

static const JanetReg cfuns[] =
{
  {"chachapoly/start", chachapoly_start,
    "(janetls/chachapoly/start operation key nonce ad)"
    "Prepares a Chacha20-Poly1305 cipher to encrypt or decrypt data using the "
    "update function.\n"
    "After calling :finish, it is vital to do the following...\n"
    "When encrypting, collect the tag with (:tag chachapoly) and "
    "include the value with the ciphertext somehow.\n"
    "When decrypting, assert the plaintext is unmodified by executing "
    "(:tag chachapoly tag). Only when it returns true permit the "
    "application to process the plaintext.\n"
    "Inputs:\n"
    "operation - required, :encrypt or :decrypt\n"
    "key - optional during encryption, required during decryption: "
    "A 256 bit key as a string or buffer, "
    "if not provided, then a key will be generated aurtomatically. "
    "nil will be interpreted as omitted.\n"
    "nonce - optional during encryption, required during decryption: "
    "is a 12 byte string or buffer, will be "
    "generated automatically if not provided during encryption. "
    "nil will be interpreted as omitted.\n"
    "ad - optional associated data: "
    "a string or buffer of data used to prepare the cipher context to provide "
    "both privacy and authenticity. "
    "This data must be identical for encryption and decryption to produce "
    "a valid authenticated decryption.\n"
    "Returns a janetls/chachapoly object, which is a Chacha20-Poly1305 "
    "cipher context."
    },
  {"chachapoly/update", chachapoly_update,
    "(janetls/chachapoly/update chachapoly data buffer)\n\n"
    "Updates a Chacha20-Poly1305 cipher and produces encrypted or decrypted "
    "content.\n"
    "Inputs:\n"
    "chachapoly - Chacha20-Poly1305 cipher object\n"
    "data - data to he encrypted or decrypted\n"
    "buffer - optional output buffer, otherwise a new buffer is allocated.\n"
    "Returns a buffer with output data, which has the same length of "
    "data appended to it."
    },
  {"chachapoly/finish", chachapoly_finish,
    "(janetls/chachapoly/finish chachapoly buffer)\n\n"
    "Updates a Chacha20-Poly1305 cipher and produces encrypted or decrypted "
    "content.\n"
    "Will lock the Chacha20-Poly1305 cipher object from futher :update "
    "function calls.\n"
    "It is vital to use the :tag function after finish is complete to obtain "
    "or verify the authentication tag.\n"
    "Inputs:\n"
    "chachapoly - Chacha20-Poly1305 cipher object\n"
    "buffer - optional output buffer, otherwise a new buffer is allocated.\n"
    "Returns a buffer with output data, for Cchacha20-Poly1305 this will "
    "always be empty."
    },
  {"chachapoly/key", chachapoly_key,
    "(janetls/chachapoly/key chachapoly)\n\n"
    "Fetches the key content within an Chacha20-Poly1305 cipher content, "
    "especially needed if auotmatically generated\n"
    "Inputs:\n"
    "chachapoly - AES GCM cipher object\n"
    "Returns a string with the symmetric key material."
    },
  {"chachapoly/nonce", chachapoly_nonce,
    "(janetls/chachapoly/nonce chachapoly)\n\n"
    "Fetches the nonce content within a Chacha20-Poly1305 cipher "
    "content, especially needed if auotmatically generated.\n"
    "Inputs:\n"
    "chachapoly - Chacha20-Poly1305 cipher object\n"
    "Returns a string with the nonce material."
    },
  {"chachapoly/tag", chachapoly_tag,
    "(janetls/chachapoly/tag chachapoly &opt tag)\n\n"
    "Either fetches the authentication tag from a finished Chacha20-Poly1305 "
    "context or compares the input tag with the authentication tag calculated "
    "from a decrypted ciphertext. "
    "This functionality must be used to correctly use Chacha20-Poly1305. "
    "The plaintext should not be processed until the authentication tag is "
    "verified.\n"
    "Inputs:\n"
    "chachapoly - Chacha20-Poly1305 cipher object\n"
    "tag - optional, an authentication tag to verify\n"
    "When a tag is not provided, the tag is returned if the Chacha20-Poly1305 "
    "context is not finished. "
    "Otherwise it will return nil when there is no "
    "authentication tag.\n"
    "When a tag is provided, true is returned when the input tag matches "
    "the calculated authentication tag in constant time. Otherwise false is "
    "returned.\n"
    "Note that if the input tag is not the full 16 bytes, per GCM "
    "specification, it may still be accepted down to 4 bytes, but this is not "
    "a recommended practice."
    },
  {"chachapoly/ad", chachapoly_ad,
    "(janetls/chachapoly/ad chachapoly)\n\n"
    "Fetches the associated date applied to an Chacha20-Poly1305 cipher "
    "context\n"
    "Inputs:\n"
    "chachapoly - Chacha20-Poly1305 cipher object\n"
    "Returns nil or a string of data used to set up the Poly1305 tag context."
    },
  {NULL, NULL, NULL}
};

void submod_chachapoly(JanetTable * env)
{
  janet_cfuns(env, "janetls", cfuns);
  janet_register_abstract_type(janetls_chachapoly_object_type());
}

janetls_chachapoly_object * janetls_new_chachapoly()
{
  janetls_chachapoly_object * chachapoly = janet_abstract(&chachapoly_object_type, sizeof(janetls_chachapoly_object));
  memset(chachapoly, 0, sizeof(janetls_chachapoly_object));
  mbedtls_chachapoly_init(&chachapoly->ctx);
  return chachapoly;
}

JanetAbstractType * janetls_chachapoly_object_type()
{
  return &chachapoly_object_type;
}

static int chachapoly_gc_fn(void * data, size_t len)
{
  janetls_chachapoly_object * chachapoly = (janetls_chachapoly_object *)data;
  mbedtls_chachapoly_free(&chachapoly->ctx);
  // Ensure the key does not remain in memory
  mbedtls_platform_zeroize(data, len);
  return 0;
}

static int chachapoly_gcmark(void * data, size_t len)
{
  janetls_chachapoly_object * chachapoly = (janetls_chachapoly_object *)data;
  (void)len;

  janet_mark(chachapoly->ad);
  return 0;
}

static int chachapoly_get_fn(void *data, Janet key, Janet * out)
{
  (void)data;

  if (!janet_checktype(key, JANET_KEYWORD))
  {
    janet_panicf("expected keyword, got %p", key);
  }

  return janet_getmethod(janet_unwrap_keyword(key), chachapoly_methods, out);
}

int janetls_setup_chachapoly(
  janetls_chachapoly_object * chachapoly_object,
  const uint8_t * key,
  size_t key_length,
  const uint8_t * nonce,
  size_t nonce_length,
  janetls_cipher_operation operation,
  const uint8_t * ad,
  size_t ad_length
  )
{
  int ret = 0;

  if (key_length == 0)
  {
    // Generate a 256 bit key by default
    janetls_random_set(chachapoly_object->key, 32);
  }
  else if (key_length == 32)
  {
    // accept 128, 192, and 256 bit keys
    memcpy(chachapoly_object->key, key, 32);
  }
  else
  {
    retcheck(JANETLS_ERR_CIPHER_INVALID_KEY_SIZE);
  }

  retcheck(mbedtls_chachapoly_setkey(&chachapoly_object->ctx, chachapoly_object->key));

  if (nonce_length == 0)
  {
    janetls_random_set(chachapoly_object->nonce, 12);
  }
  else if (nonce_length == 12)
  {
    memcpy(chachapoly_object->nonce, nonce, 12);
  }
  else
  {
    retcheck(JANETLS_ERR_CIPHER_INVALID_IV_SIZE);
  }

  chachapoly_object->operation = operation;

  mbedtls_chachapoly_mode_t mode = operation == janetls_cipher_operation_decrypt
    ? MBEDTLS_CHACHAPOLY_DECRYPT
    : MBEDTLS_CHACHAPOLY_ENCRYPT;

  retcheck(mbedtls_chachapoly_starts(&chachapoly_object->ctx, chachapoly_object->nonce, mode));

  // Process associated additional data
  // Technically the interface provided by chacha20 can accept more
  // asynchronously, but this is different from AES GCM in mbedtls
  // which I cannot work around. Therefore, for a unified interface
  // The additional data must be provided upfront.
  if (ad_length)
  {
    retcheck(mbedtls_chachapoly_update_aad(&chachapoly_object->ctx, ad, ad_length));
    chachapoly_object->ad = janet_wrap_string(janet_string(ad, ad_length));
  }
  else
  {
    chachapoly_object->ad = janet_wrap_nil();
  }

  end:
  return ret;
}

int janetls_chachapoly_update(
  janetls_chachapoly_object * chachapoly_object,
  const uint8_t * data,
  size_t length,
  Janet * output)
{
  int ret = 0;
  uint8_t local_output[16];

  if (length == 0)
  {
    // Nothing to process
    goto end;
  }

  if (chachapoly_object->flags & FLAG_FINISH)
  {
    retcheck(JANETLS_ERR_CIPHER_INVALID_STATE);
  }


  JanetBuffer * output_buffer = buffer_from_output(output, length);
  janet_buffer_extra(output_buffer, length);

  int32_t data_blocks = length / 16;
  int32_t data_remainder = length % 16;
  size_t data_offset = 0;

  for (int32_t i = 0; i < data_blocks; i++, data_offset += 16)
  {
    retcheck(mbedtls_chachapoly_update(&chachapoly_object->ctx, 16, data + data_offset, local_output));
    janet_buffer_push_bytes(output_buffer, local_output, 16);
  }

  if (data_remainder)
  {
    retcheck(mbedtls_chachapoly_update(&chachapoly_object->ctx, data_remainder, data + data_offset, local_output));
    janet_buffer_push_bytes(output_buffer, local_output, data_remainder);
  }

  end:
  mbedtls_platform_zeroize(local_output, 16);
  return ret;
}

int janetls_chachapoly_finish(
  janetls_chachapoly_object * chachapoly_object,
  Janet * output)
{
  int ret = 0;

  if (chachapoly_object->flags & FLAG_FINISH)
  {
    retcheck(JANETLS_ERR_CIPHER_INVALID_STATE);
  }

  // In general, there's no output here, but we capture the tag in this step

  JanetBuffer * output_buffer = buffer_from_output(output, 0);
  janet_buffer_extra(output_buffer, 0);

  retcheck(mbedtls_chachapoly_finish(&chachapoly_object->ctx, chachapoly_object->tag));

  chachapoly_object->flags |= FLAG_FINISH;

  end:
  return ret;
}


static Janet chachapoly_start(int32_t argc, Janet * argv)
{
  janet_arity(argc, 1, 4);
  janetls_chachapoly_object * chachapoly_object = janetls_new_chachapoly();
  JanetByteView key = empty_byteview();
  JanetByteView nonce = empty_byteview();
  JanetByteView ad = empty_byteview();
  janetls_cipher_operation operation = janetls_cipher_operation_encrypt;

  check_result(janetls_search_cipher_operation(argv[0], &operation));

  if (argc > 1)
  {
    Janet potential_key = argv[1];
    if (!janet_checktype(potential_key, JANET_NIL))
    {
      key = janet_to_bytes(potential_key);
    }
  }

  if (argc > 2)
  {
    Janet potential_nonce = argv[2];
    if (!janet_checktype(potential_nonce, JANET_NIL))
    {
      nonce = janet_to_bytes(potential_nonce);
    }
  }

  if (argc > 3)
  {
    Janet potential_ad = argv[3];
    if (!janet_checktype(potential_ad, JANET_NIL))
    {
      ad = janet_to_bytes(potential_ad);
    }
  }

  check_result(janetls_setup_chachapoly(
    chachapoly_object,
    key.bytes, key.len,
    nonce.bytes, nonce.len,
    operation,
    ad.bytes, ad.len
    ));
  return janet_wrap_abstract(chachapoly_object);
}

static Janet chachapoly_update(int32_t argc, Janet * argv)
{
  janet_arity(argc, 2, 3);
  Janet output = janet_wrap_nil();
  janetls_chachapoly_object * chachapoly_object = janet_getabstract(argv, 0, janetls_chachapoly_object_type());
  if (!janet_is_byte_typed(argv[1]))
  {
    janet_panic("Expected a buffer or string for the second argument");
  }
  if (argc > 2)
  {
    if (!janet_checktype(argv[2], JANET_BUFFER))
    {
      janet_panicf("Expected a buffer, but got %p", argv[2]);
    }
    output = argv[2];
  }

  JanetByteView data = janet_to_bytes(argv[1]);
  check_result(janetls_chachapoly_update(
    chachapoly_object,
    data.bytes, data.len,
    &output
    ));
  return output;
}

static Janet chachapoly_finish(int32_t argc, Janet * argv)
{
  janet_arity(argc, 1, 2);
  Janet output = janet_wrap_nil();
  janetls_chachapoly_object * chachapoly_object = janet_getabstract(argv, 0, janetls_chachapoly_object_type());
  if (argc > 1)
  {
    if (!janet_checktype(argv[1], JANET_BUFFER))
    {
      janet_panicf("Expected a buffer, but got %p", argv[1]);
    }
    output = argv[1];
  }

  check_result(janetls_chachapoly_finish(chachapoly_object, &output));
  return output;
}

static Janet chachapoly_key(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_chachapoly_object * chachapoly_object = janet_getabstract(argv, 0, janetls_chachapoly_object_type());
  return janet_wrap_string(janet_string(chachapoly_object->key, 32));
}

static Janet chachapoly_nonce(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_chachapoly_object * chachapoly_object = janet_getabstract(argv, 0, janetls_chachapoly_object_type());
  return janet_wrap_string(janet_string(chachapoly_object->nonce, 12));
}

static Janet chachapoly_ad(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_chachapoly_object * chachapoly_object = janet_getabstract(argv, 0, janetls_chachapoly_object_type());
  return chachapoly_object->ad;
}

static Janet chachapoly_tag(int32_t argc, Janet * argv)
{
  janet_arity(argc, 1, 2);
  janetls_chachapoly_object * chachapoly_object = janet_getabstract(argv, 0, janetls_chachapoly_object_type());
  if ((chachapoly_object->flags & FLAG_FINISH) == 0)
  {
    return janet_wrap_nil();
  }

  if (argc == 1)
  {
    // Return the tag
    return janet_wrap_string(janet_string(chachapoly_object->tag, 16));
  }
  else if (argc == 2)
  {
    // compare tags
    if (janet_is_byte_typed(argv[1]))
    {
      JanetByteView other_tag = janet_to_bytes(argv[1]);
      if (other_tag.len != 16)
      {
        janet_panicf("Cchacha20-Poly1305 tags must be 16 bytes, "
          "the length observed is %d bytes.",
          other_tag.len);
      }
      uint8_t * tag = chachapoly_object->tag;
      // Costant time compare
      int diff = 0;

      // Constant time, every byte that is valued is compared
      for (int32_t i = 0; i < 16; i++)
      {
        diff |= other_tag.bytes[i] ^ tag[i];
      }

      // The result will zero if equal
      // Will be between 1-255 otherwise, the actual value
      // carries no meaning.
      return janet_wrap_boolean(diff == 0);
    }
    else
    {
      janet_panicf("Expected buffer or string but got %p", argv[1]);
    }
  }
  return janet_wrap_nil();
}

