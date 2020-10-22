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
#include "janetls-aes.h"
#include "mbedtls/platform_util.h"

// Abstract Object functions
static int aes_gc_fn(void * data, size_t len);
static int aes_gcmark(void * data, size_t len);
static int aes_get_fn(void * data, Janet key, Janet * out);

// Janet functions
static Janet aes_aes(int32_t argc, Janet * argv);
static Janet aes_update(int32_t argc, Janet * argv);

static JanetAbstractType aes_object_type = {
  "janetls/aes",
  aes_gc_fn,
  aes_gcmark,
  aes_get_fn,
  JANET_ATEND_GET
};

static JanetMethod aes_methods[] = {
  {"update", aes_update},
  {NULL, NULL},
};

static const JanetReg cfuns[] =
{
  {"aes/modes", janetls_search_aes_mode_set, "(janetls/aes/modes)\n\n"
    "Provides an tuple of keywords for available aes modes"},
  {"aes/cbc-paddings", janetls_search_cipher_padding_set, "(janetls/aes/cbc-paddings)\n\n"
    "Provides an tuple of keywords for available AES CBC paddings"},
  {"aes/encrypt", aes_aes, ""},
  {"aes/update", aes_update, ""},
  {NULL, NULL, NULL}
};

void submod_aes(JanetTable * env)
{
  janet_cfuns(env, "janetls", cfuns);
  janet_register_abstract_type(janetls_aes_object_type());
}

janetls_aes_object * janetls_new_aes()
{
  janetls_aes_object * aes = janet_abstract(&aes_object_type, sizeof(janetls_aes_object));
  memset(aes, 0, sizeof(janetls_aes_object));
  mbedtls_aes_init(&aes->ctx);
  return aes;
}

JanetAbstractType * janetls_aes_object_type()
{
  return &aes_object_type;
}

static int aes_gc_fn(void * data, size_t len)
{
  janetls_aes_object * aes = (janetls_aes_object *)data;
  mbedtls_aes_free(&aes->ctx);
  // Ensure the key does not remain in memory
  mbedtls_platform_zeroize(data, len);
  return 0;
}

static int aes_gcmark(void * data, size_t len)
{
  (void)data;
  (void)len;
  return 0;
}

static int aes_get_fn(void *data, Janet key, Janet * out)
{
  (void)data;

  if (!janet_checktype(key, JANET_KEYWORD))
  {
    janet_panicf("expected keyword, got %p", key);
  }

  return janet_getmethod(janet_unwrap_keyword(key), aes_methods, out);
}

int janetls_setup_aes(
  janetls_aes_object * aes_object,
  janetls_aes_mode mode,
  const uint8_t * key,
  size_t key_length,
  const uint8_t * iv,
  size_t iv_length,
  janetls_cipher_operation operation,
  janetls_cipher_padding padding
  )
{
  int ret = 0;

  if (key_length == 0)
  {
    // Generate a 256 bit key by default
    janetls_random_set(aes_object->key, 32);
    aes_object->key_size = 32;
  }
  else if (key_length == 16 || key_length == 24 || key_length == 32)
  {
    // accept 128, 192, and 256 bit keys
    memcpy(aes_object->key, key, key_length);
    aes_object->key_size = key_length;
  }
  else
  {
    retcheck(JANETLS_ERR_CIPHER_INVALID_KEY_SIZE);
  }

  if (operation == janetls_cipher_operation_decrypt)
  {
    retcheck(mbedtls_aes_setkey_dec(&aes_object->ctx, aes_object->key, aes_object->key_size * 8));
  }
  else
  {
    retcheck(mbedtls_aes_setkey_enc(&aes_object->ctx, aes_object->key, aes_object->key_size * 8));
  }

  aes_object->operation = operation;
  aes_object->mode = mode;
  if (mode == janetls_aes_mode_ecb)
  {
    // there is no nonce
    if (iv_length > 0)
    {
      retcheck(JANETLS_ERR_CIPHER_INVALID_IV_SIZE);
    }
    aes_object->iv_size = 0;
  }
  else
  {
    memset(aes_object->iv, 0, 16);
    if (iv_length == 0)
    {
      // generate an iv
      if (mode == janetls_aes_mode_ctr)
      {
        // Typically CTR does 96 bits of nonce and the remaining bits are
        // incremented for every 16 byte block
        janetls_random_set(aes_object->nonce, 12);
        aes_object->nonce_size = 12;
      }
      else
      {
        janetls_random_set(aes_object->iv, 16);
        aes_object->iv_size = 16;
      }
    }
    else if (iv_length == 16)
    {
      memcpy(aes_object->iv, iv, 16);
      aes_object->iv_size = 16;
    }
    else if (iv_length >= 8 && mode == janetls_aes_mode_ctr)
    {
      // AES CTR may supply different sizes for IVs
      // the remaining bytes are defaulted to zero above.
      memcpy(aes_object->iv, iv, iv_length);
      aes_object->iv_size = iv_length;
    }
    else
    {
      // This is an insecure amount
      retcheck(JANETLS_ERR_CIPHER_INVALID_IV_SIZE);
    }
    // Copy the loaded iv into the working / mutable iv vector
    memcpy(aes_object->working_iv, aes_object->iv, 16);
  }

  if (mode == janetls_aes_mode_ctr)
  {
    memset(aes_object->stream_block, 0, 16);
    aes_object->stream_offset = 0;
  }

  if (mode == janetls_aes_mode_cbc)
  {
    aes_object->padding = padding;
  }
  else if (padding != janetls_cipher_padding_none)
  {
    retcheck(JANETLS_ERR_CIPHER_INVALID_PADDING);
  }

  // Clear all temporary data
  memset(aes_object->buffer, 0, 16);
  aes_object->buffer_length = 0;
  aes_object->flags = 0;

  end:
  return ret;
}

int janetls_aes_update(
  janetls_aes_object * aes_object,
  const uint8_t * data,
  size_t length,
  Janet * output)
{
  int ret = 0;
  int32_t len = length + 16;
  JanetBuffer * output_buffer = buffer_from_output(output, length + 16);
  janet_buffer_extra(output_buffer, len);
  int operation = aes_object->operation == janetls_cipher_operation_decrypt
    ? MBEDTLS_AES_DECRYPT
    : MBEDTLS_AES_ENCRYPT;

  if (aes_object->mode == janetls_aes_mode_ecb)
  {
    if (length != 16)
    {
      retcheck(JANETLS_ERR_CIPHER_INVALID_DATA_SIZE);
    }
    uint8_t block[16];
    retcheck(mbedtls_aes_crypt_ecb(&aes_object->ctx, operation, data, block));
    janet_buffer_push_bytes(output_buffer, block, 16);
  }
  end:
  return ret;
}

int janetls_aes_finish(
  janetls_aes_object * aes_object,
  Janet * output)
{
  return 0;
}

// The following comment was found in mbedtls
// The final block is awlays padded in CBC
// Padding is only for CBC
/* Encryption: only cache partial blocks
* Decryption w/ padding: always keep at least one whole block
* Decryption w/o padding: only cache partial blocks
*/

static Janet aes_aes(int32_t argc, Janet * argv)
{
  janet_arity(argc, 0, 1);
  janetls_aes_object * aes_object = janetls_new_aes();
  JanetByteView key = empty_byteview();
  JanetByteView iv = empty_byteview();
  janetls_cipher_operation operation = janetls_cipher_operation_encrypt;
  janetls_cipher_padding padding = janetls_cipher_padding_none;
  janetls_aes_mode mode = janetls_aes_mode_ecb;
  if (argc > 0)
  {
    key = janet_to_bytes(argv[0]);
  }
  check_result(janetls_setup_aes(aes_object, mode, key.bytes, key.len, iv.bytes, iv.len, operation, padding));
  return janet_wrap_abstract(aes_object);
}

static Janet aes_update(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 2);
  Janet output = janet_wrap_nil();
  janetls_aes_object * aes_object = janet_getabstract(argv, 0, janetls_aes_object_type());
  if (!janet_is_byte_typed(argv[1]))
  {
    janet_panic("Expected a buffer or string for the second argument");
  }
  JanetByteView data = janet_to_bytes(argv[1]);
  check_result(janetls_aes_update(aes_object, data.bytes, data.len, &output));
  return output;
}
