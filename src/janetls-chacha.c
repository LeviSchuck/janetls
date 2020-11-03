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
#include "janetls-chacha.h"
#include "mbedtls/platform_util.h"

#define FLAG_FINISH 1

// Abstract Object functions
static int chacha_gc_fn(void * data, size_t len);
static int chacha_gcmark(void * data, size_t len);
static int chacha_get_fn(void * data, Janet key, Janet * out);

// Janet functions
static Janet chacha_start(int32_t argc, Janet * argv);
static Janet chacha_update(int32_t argc, Janet * argv);
static Janet chacha_finish(int32_t argc, Janet * argv);
static Janet chacha_key(int32_t argc, Janet * argv);
static Janet chacha_nonce(int32_t argc, Janet * argv);
static Janet chacha_initial_counter(int32_t argc, Janet * argv);

static JanetAbstractType chacha_object_type = {
  "janetls/chacha",
  chacha_gc_fn,
  chacha_gcmark,
  chacha_get_fn,
  JANET_ATEND_GET
};

static JanetMethod chacha_methods[] = {
  {"update", chacha_update},
  {"finish", chacha_finish},
  {"key", chacha_key},
  {"nonce", chacha_nonce},
  {"initial-counter", chacha_initial_counter},
  {NULL, NULL},
};

static const JanetReg cfuns[] =
{
  {"chacha/start", chacha_start, "(janetls/chacha/start operation key nonce initial-counter)"
    "Prepares a Chacha20 cipher to encrypt or decrypt data using the "
    "update function.\n"
    "After calling :finish, it is vital to do the following...\n"
    "When encrypting, collect the tag with (:tag chacha-object) and include "
    "the value with the ciphertext somehow.\n"
    "When decrypting, assert the plaintext is unmodified by executing "
    "(:tag chacha-object tag). Only when it returns true permit the application "
    "to process the plaintext.\n"
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
    "counter - optional initial block counter: "
    "Offset the first block of this stream by this counter, do not use "
    "uneless specified by a peer reviewed algorithm.\n"
    "Returns a janetls/chacha object, which is a Chacha20 cipher context."
    },
  {"chacha/update", chacha_update, "(janetls/chacha/update chacha data buffer)\n\n"
    "Updates a Chacha20 cipher and produces encrypted or decrypted content.\n"
    "Inputs:\n"
    "chacha - Chacha20 cipher object\n"
    "data - data to he encrypted or decrypted\n"
    "buffer - optional output buffer, otherwise a new buffer is allocated.\n"
    "Returns a buffer with output data, which has the same length of "
    "data appended to it."
    },
  {"chacha/finish", chacha_finish, "(janetls/chacha/finish chacha buffer)\n\n"
    "Updates a Chacha20 cipher and produces encrypted or decrypted content.\n"
    "Will lock the Chacha20 cipher object from futher :update function calls.\n"
    "It is vital to use the :tag function after finish is complete to obtain "
    "or verify the authentication tag.\n"
    "Inputs:\n"
    "chacha - Chacha20 cipher object\n"
    "buffer - optional output buffer, otherwise a new buffer is allocated.\n"
    "Returns a buffer with output data, for chacha20 will always be empty."
    },
  {"chacha/key", chacha_key, "(janetls/chacha/key chacha)\n\n"
    "Fetches the key content within an Chacha20 cipher content, especially needed "
    "if auotmatically generated\n"
    "Inputs:\n"
    "chacha - Chacha20 cipher object\n"
    "Returns a string with the symmetric key material."
    },
  {"chacha/nonce", chacha_nonce, "(janetls/chacha/nonce chacha)\n\n"
    "Fetches the nonce content within a Chacha20 cipher "
    "content, especially needed if auotmatically generated.\n"
    "Inputs:\n"
    "chacha - Chacha20 cipher object\n"
    "Returns a string with the nonce material."
    },
  {"chacha/initial-counter", chacha_initial_counter, "(janetls/chacha/initial-counter chacha)\n\n"
    "Fetches the initial counter within a Chacha20 cipher "
    "content, in nearly all cases this will be 0.\n"
    "Inputs:\n"
    "chacha - Chacha20 cipher object\n"
    "Returns a number."
    },
  {NULL, NULL, NULL}
};

void submod_chacha(JanetTable * env)
{
  janet_cfuns(env, "janetls", cfuns);
  janet_register_abstract_type(janetls_chacha_object_type());
}

janetls_chacha_object * janetls_new_chacha()
{
  janetls_chacha_object * chacha = janet_abstract(&chacha_object_type, sizeof(janetls_chacha_object));
  memset(chacha, 0, sizeof(janetls_chacha_object));
  mbedtls_chacha20_init(&chacha->ctx);
  return chacha;
}

JanetAbstractType * janetls_chacha_object_type()
{
  return &chacha_object_type;
}

static int chacha_gc_fn(void * data, size_t len)
{
  janetls_chacha_object * chacha = (janetls_chacha_object *)data;
  mbedtls_chacha20_free(&chacha->ctx);
  // Ensure the key does not remain in memory
  mbedtls_platform_zeroize(data, len);
  return 0;
}

static int chacha_gcmark(void * data, size_t len)
{
  (void)data;
  (void)len;
  return 0;
}

static int chacha_get_fn(void *data, Janet key, Janet * out)
{
  (void)data;

  if (!janet_checktype(key, JANET_KEYWORD))
  {
    janet_panicf("expected keyword, got %p", key);
  }

  return janet_getmethod(janet_unwrap_keyword(key), chacha_methods, out);
}

int janetls_setup_chacha(
  janetls_chacha_object * chacha_object,
  const uint8_t * key,
  size_t key_length,
  const uint8_t * nonce,
  size_t nonce_length,
  size_t initial_counter,
  janetls_cipher_operation operation
  )
{
  int ret = 0;

  if (key_length == 0)
  {
    // Generate a 256 bit key by default
    janetls_random_set(chacha_object->key, 32);
  }
  else if (key_length == 32)
  {
    // accept 128, 192, and 256 bit keys
    memcpy(chacha_object->key, key, 32);
  }
  else
  {
    retcheck(JANETLS_ERR_CIPHER_INVALID_KEY_SIZE);
  }

  retcheck(mbedtls_chacha20_setkey(&chacha_object->ctx, chacha_object->key));

  if (nonce_length == 0)
  {
    janetls_random_set(chacha_object->nonce, 12);
  }
  else if (nonce_length == 12)
  {
    memcpy(chacha_object->nonce, nonce, 12);
  }
  else
  {
    retcheck(JANETLS_ERR_CIPHER_INVALID_IV_SIZE);
  }

  chacha_object->initial_counter = initial_counter;
  chacha_object->operation = operation;

  retcheck(mbedtls_chacha20_starts(&chacha_object->ctx, chacha_object->nonce, chacha_object->initial_counter));

  end:
  return ret;
}

int janetls_chacha_update(
  janetls_chacha_object * chacha_object,
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

  if (chacha_object->flags & FLAG_FINISH)
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
    retcheck(mbedtls_chacha20_update(&chacha_object->ctx, 16, data + data_offset, local_output));
    janet_buffer_push_bytes(output_buffer, local_output, 16);
  }

  if (data_remainder)
  {
    retcheck(mbedtls_chacha20_update(&chacha_object->ctx, data_remainder, data + data_offset, local_output));
    janet_buffer_push_bytes(output_buffer, local_output, data_remainder);
  }

  end:
  mbedtls_platform_zeroize(local_output, 16);
  return ret;
}

int janetls_chacha_finish(
  janetls_chacha_object * chacha_object,
  Janet * output)
{
  int ret = 0;

  if (chacha_object->flags & FLAG_FINISH)
  {
    retcheck(JANETLS_ERR_CIPHER_INVALID_STATE);
  }

  // In general, there's nothing to do here. Just maintaining a pattern

  JanetBuffer * output_buffer = buffer_from_output(output, 0);
  janet_buffer_extra(output_buffer, 0);

  chacha_object->flags |= FLAG_FINISH;

  end:
  return ret;
}

static Janet chacha_start(int32_t argc, Janet * argv)
{
  janet_arity(argc, 1, 4);
  janetls_chacha_object * chacha_object = janetls_new_chacha();
  JanetByteView key = empty_byteview();
  JanetByteView nonce = empty_byteview();
  janetls_cipher_operation operation = janetls_cipher_operation_encrypt;
  uint32_t initial_counter = 0;

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
    double counter = janet_getnumber(argv, 3);
    initial_counter = counter;
    if (initial_counter != counter)
    {
      janet_panic("Initial counter value not set with a whole 32 bit integer");
    }
  }

  check_result(janetls_setup_chacha(
    chacha_object,
    key.bytes, key.len,
    nonce.bytes, nonce.len,
    initial_counter,
    operation
    ));
  return janet_wrap_abstract(chacha_object);
}

static Janet chacha_update(int32_t argc, Janet * argv)
{
  janet_arity(argc, 2, 3);
  Janet output = janet_wrap_nil();
  janetls_chacha_object * chacha_object = janet_getabstract(argv, 0, janetls_chacha_object_type());
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
  check_result(janetls_chacha_update(
    chacha_object,
    data.bytes, data.len,
    &output
    ));
  return output;
}

static Janet chacha_finish(int32_t argc, Janet * argv)
{
  janet_arity(argc, 1, 2);
  Janet output = janet_wrap_nil();
  janetls_chacha_object * chacha_object = janet_getabstract(argv, 0, janetls_chacha_object_type());
  if (argc > 1)
  {
    if (!janet_checktype(argv[1], JANET_BUFFER))
    {
      janet_panicf("Expected a buffer, but got %p", argv[1]);
    }
    output = argv[1];
  }

  check_result(janetls_chacha_finish(chacha_object, &output));
  return output;
}

static Janet chacha_key(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_chacha_object * chacha_object = janet_getabstract(argv, 0, janetls_chacha_object_type());
  return janet_wrap_string(janet_string(chacha_object->key, 32));
}

static Janet chacha_nonce(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_chacha_object * chacha_object = janet_getabstract(argv, 0, janetls_chacha_object_type());
  return janet_wrap_string(janet_string(chacha_object->nonce, 12));
}

static Janet chacha_initial_counter(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_chacha_object * chacha_object = janet_getabstract(argv, 0, janetls_chacha_object_type());
  return janet_wrap_number(chacha_object->initial_counter);
}

