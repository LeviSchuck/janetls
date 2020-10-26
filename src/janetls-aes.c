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

#define FLAG_AES_FINISH 1

// Abstract Object functions
static int aes_gc_fn(void * data, size_t len);
static int aes_gcmark(void * data, size_t len);
static int aes_get_fn(void * data, Janet key, Janet * out);

// Janet functions
static Janet aes_start(int32_t argc, Janet * argv);
static Janet aes_update(int32_t argc, Janet * argv);
static Janet aes_finish(int32_t argc, Janet * argv);
static Janet aes_key(int32_t argc, Janet * argv);
static Janet aes_iv(int32_t argc, Janet * argv);
static Janet aes_mode(int32_t argc, Janet * argv);
static Janet aes_padding(int32_t argc, Janet * argv);

static JanetAbstractType aes_object_type = {
  "janetls/aes",
  aes_gc_fn,
  aes_gcmark,
  aes_get_fn,
  JANET_ATEND_GET
};

static JanetMethod aes_methods[] = {
  {"update", aes_update},
  {"finish", aes_finish},
  {"key", aes_key},
  {"iv", aes_iv},
  {"nonce", aes_iv},
  {"mode", aes_mode},
  {"padding", aes_padding},
  {NULL, NULL},
};

static const JanetReg cfuns[] =
{
  {"aes/modes", janetls_search_aes_mode_set, "(janetls/aes/modes)\n\n"
    "Provides an tuple of keywords for available aes modes"},
  {"aes/cbc-paddings", janetls_search_cipher_padding_set, "(janetls/aes/cbc-paddings)\n\n"
    "Provides an tuple of keywords for available AES CBC paddings"},
  {"aes/start", aes_start, "(janetls/aes/start operation mode padding key iv)\n\n"
    "Prepares an AES cipher to encrypt or decrypt data using the "
    "update function\n"
    "Inputs:\n"
    "operation - required, :encrypt or :decrypt\n"
    "mode - required, see (aes/modes) for valid options, such as :cbc\n"
    "padding - optional, only applies to :cbc mode, skipped if not provided. "
    "Do not put nil in its place.\n"
    "key - optional during encryption, required during decryption: "
    "128, 192, or 256 bit key as a string or buffer, "
    "if not provided, then a key will be generated aurtomatically "
    "at 256 bits during encryption. "
    "nil will be interpreted as omitted.\n"
    "iv - optional during encryption, required during decryption: "
    "also named nonce for some modes, is a 16 byte string or buffer, will be "
    "generated automatically if not provided during encryption. "
    "nil will be interpreted as omitted."
    },
  {"aes/update", aes_update, "(janetls/aes/update aes data buffer)\n\n"
    "Updates an AES cipher and produces encrypted or decrypted content.\n"
    "When using :ecb mode, the data size must be 16 bytes, no more or less.\n"
    "Inputs:\n"
    "aes - AES cipher object\n"
    "data - data to he encrypted or decrypted\n"
    "buffer - optional output buffer, otherwise a new buffer is allocated.\n"
    "Returns a buffer with output data, may be empty or unchanged in :cbc mode."
    },
  {"aes/finish", aes_finish, "(janetls/aes/finish aes buffer)\n\n"
    "Updates an AES cipher and produces encrypted or decrypted content.\n"
    "Will lock the AES cipher object from futher update function calls.\n"
    "Inputs:\n"
    "aes - AES cipher object\n"
    "buffer - optional output buffer, otherwise a new buffer is allocated.\n"
    "Returns a buffer with output data, may be empty or unchanged."
    },
  {"aes/key", aes_key, "(janetls/aes/key aes)\n\n"
    "Fetches the key content within an AES cipher content, especially needed "
    "if auotmatically generated\n"
    "Inputs:\n"
    "aes - AES cipher object\n"
    "Returns a string with the symmetric key material."
    },
  {"aes/iv", aes_iv, "(janetls/aes/iv aes)\n\n"
    "Fetches the initialization vector content within an AES cipher "
    "content, especially needed if auotmatically generated.\n"
    "Inputs:\n"
    "aes - AES cipher object\n"
    "Returns a string with the iv material."
    },
  {"aes/nonce", aes_iv, "(janetls/aes/nonce aes)\n\n"
    "Alias of (janetls/aes/iv)"
    },
  {"aes/mode", aes_mode, "(janetls/aes/mode aes)\n\n"
    "Fetches the cipher mode within an AES cipher context\n"
    "Inputs:\n"
    "aes - AES cipher object\n"
    "Returns a keyword with the mode this context uses."},
  {"aes/padding", aes_padding, "(janetls/aes/padding aes)\n\n"
    "Fetches the cbc padding mode within an AES cipher context\n"
    "Inputs:\n"
    "aes - AES cipher object\n"
    "Returns a keyword with the padding this context uses."},
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
  // Ensure the key and data does not remain in memory
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

  if (operation == janetls_cipher_operation_decrypt
    && (mode == janetls_aes_mode_ecb || mode == janetls_aes_mode_cbc))
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
    memset(aes_object->last_decrypted_block, 0, 16);
    aes_object->last_decrypted = 0;
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
  janetls_aes_mode mode = aes_object->mode;
  janetls_cipher_operation op = aes_object->operation;
  int operation = op == janetls_cipher_operation_decrypt
    ? MBEDTLS_AES_DECRYPT
    : MBEDTLS_AES_ENCRYPT;

  uint8_t block[16];
  size_t blocks = length / 16;
  size_t remainder = length % 16;

  if (length == 0)
  {
    // Nothing to process.
    goto end;
  }
  if (aes_object->flags & FLAG_AES_FINISH)
  {
    retcheck(JANETLS_ERR_CIPHER_INVALID_STATE);
  }

  if (mode == janetls_aes_mode_ecb)
  {
    if (length != 16)
    {
      retcheck(JANETLS_ERR_CIPHER_INVALID_DATA_SIZE);
    }
    retcheck(mbedtls_aes_crypt_ecb(&aes_object->ctx, operation, data, block));
    janet_buffer_push_bytes(output_buffer, block, 16);
  }
  else if (mode == janetls_aes_mode_ctr
    || mode == janetls_aes_mode_cfb128
    || mode == janetls_aes_mode_cfb8
    || mode == janetls_aes_mode_ofb)
  {
    size_t offset = 0;
    for (size_t i = 0; i < blocks; i++, offset += 16)
    {
      switch (mode)
      {
        case janetls_aes_mode_ctr:
          retcheck(mbedtls_aes_crypt_ctr(&aes_object->ctx, 16,
            &aes_object->nonce_offset, aes_object->working_nonce,
            aes_object->stream_block, data + offset, block
            ));
          break;
        case janetls_aes_mode_cfb128:
          retcheck(mbedtls_aes_crypt_cfb128(&aes_object->ctx, operation, 16,
            &aes_object->iv_offset, aes_object->working_iv,
            data + offset, block
            ));
          break;
        case janetls_aes_mode_cfb8:
          retcheck(mbedtls_aes_crypt_cfb8(&aes_object->ctx, operation, 16,
            aes_object->working_iv,
            data + offset, block
            ));
          break;
        case janetls_aes_mode_ofb:
          retcheck(mbedtls_aes_crypt_ofb(&aes_object->ctx, 16,
            &aes_object->iv_offset, aes_object->working_iv,
            data + offset, block
            ));
          break;
        default:
        retcheck(JANETLS_ERR_NOT_IMPLEMENTED);
        break;
      }

      janet_buffer_push_bytes(output_buffer, block, 16);
    }
    if (remainder)
    {
      switch (mode)
      {
        case janetls_aes_mode_ctr:
          retcheck(mbedtls_aes_crypt_ctr(&aes_object->ctx, remainder,
            &aes_object->nonce_offset, aes_object->working_nonce,
            aes_object->stream_block, data + offset, block
            ));
          break;
        case janetls_aes_mode_cfb128:
          retcheck(mbedtls_aes_crypt_cfb128(&aes_object->ctx, operation,
            remainder,
            &aes_object->iv_offset, aes_object->working_iv,
            data + offset, block
            ));
          break;
        case janetls_aes_mode_cfb8:
          retcheck(mbedtls_aes_crypt_cfb8(&aes_object->ctx, operation,
            remainder,
            aes_object->working_iv,
            data + offset, block
            ));
          break;
        case janetls_aes_mode_ofb:
          retcheck(mbedtls_aes_crypt_ofb(&aes_object->ctx, remainder,
            &aes_object->iv_offset, aes_object->working_iv,
            data + offset, block
            ));
          break;
        default:
          retcheck(JANETLS_ERR_NOT_IMPLEMENTED);
          break;
      }
      janet_buffer_push_bytes(output_buffer, block, remainder);
    }
  }
  else if (mode == janetls_aes_mode_cbc)
  {
    janetls_cipher_padding padding = aes_object->padding;
    uint32_t buffer_length = aes_object->buffer_length;
    size_t block_remaining = 16 - buffer_length;
    size_t length_remaining = length;
    size_t offset = 0;
    if (block_remaining < 16)
    {
      size_t copy_length = length < block_remaining
        ? length
        : block_remaining;
      memcpy(aes_object->buffer + buffer_length, data, copy_length);
      block_remaining -= copy_length;
      length_remaining -= copy_length;
      offset += copy_length;
      buffer_length += copy_length;
      aes_object->buffer_length = buffer_length;
    }
    if (length_remaining > 0)
    {
      blocks = length_remaining / 16;
      remainder = length_remaining % 16;
    }
    int buffer_block = op == janetls_cipher_operation_decrypt
      && padding == janetls_cipher_padding_pkcs7;
    if (block_remaining == 0)
    {
      if (buffer_block && aes_object->last_decrypted)
      {
        janet_buffer_push_bytes(output_buffer, aes_object->last_decrypted_block, 16);
        aes_object->last_decrypted = 0;
      }
      retcheck(mbedtls_aes_crypt_cbc(&aes_object->ctx, operation,
        16, aes_object->working_iv, aes_object->buffer, block
        ));
      if (buffer_block && blocks == 0 && remainder == 0)
      {
        memcpy(aes_object->last_decrypted_block, block, 16);
        aes_object->last_decrypted = 1;
      }
      else
      {
        janet_buffer_push_bytes(output_buffer, block, 16);
      }
    }
    else if (block_remaining != 16)
    {
      // then there is no update for this input
      if (blocks == 0 && buffer_block && aes_object->last_decrypted)
      {
        janet_buffer_push_bytes(output_buffer, aes_object->last_decrypted_block, 16);
        aes_object->last_decrypted = 0;
      }
      goto end;
    }
    // If we are going to injest blocks, and a block was buffered, then release it.
    if (blocks > 0 && buffer_block && aes_object->last_decrypted)
    {
      janet_buffer_push_bytes(output_buffer, aes_object->last_decrypted_block, 16);
      aes_object->last_decrypted = 0;
    }
    size_t last_block = blocks - 1;
    for (size_t i = 0; i < blocks; i++, offset += 16)
    {
      retcheck(mbedtls_aes_crypt_cbc(&aes_object->ctx, operation,
        16, aes_object->working_iv, data + offset, block
        ));
      if (buffer_block && i == last_block && remainder == 0)
      {
        memcpy(aes_object->last_decrypted_block, block, 16);
        aes_object->last_decrypted = 1;
      }
      else
      {
        janet_buffer_push_bytes(output_buffer, block, 16);
      }
    }
    if (remainder)
    {
      memcpy(aes_object->buffer, data + offset, remainder);
      aes_object->buffer_length = remainder;
    }
  }
  else
  {
    retcheck(JANETLS_ERR_NOT_IMPLEMENTED);
  }
  end:
  mbedtls_platform_zeroize(block, 16);
  return ret;
}

int janetls_aes_finish(
  janetls_aes_object * aes_object,
  Janet * output)
{
  int ret = 0;
  if (aes_object->flags & FLAG_AES_FINISH)
  {
    retcheck(JANETLS_ERR_CIPHER_INVALID_STATE);
  }
  JanetBuffer * output_buffer = buffer_from_output(output, 16);
  if (aes_object->mode == janetls_aes_mode_cbc
    && aes_object->padding == janetls_cipher_padding_pkcs7)
  {
    uint8_t block[16];
    uint8_t output[16];
    mbedtls_platform_zeroize(block, 16);
    if (aes_object->operation == janetls_cipher_operation_encrypt)
    {
      uint32_t buffer_length = aes_object->buffer_length;
      if (buffer_length)
      {
        memcpy(block, aes_object->buffer, buffer_length);
        retcheck(janetls_util_padding_pkcs7(block, 16, buffer_length));
      }
      else
      {
        memset(block, 16, 16);
      }
      retcheck(mbedtls_aes_crypt_cbc(&aes_object->ctx, MBEDTLS_AES_ENCRYPT,
        16, aes_object->working_iv, block, output
        ));
      janet_buffer_push_bytes(output_buffer, output, 16);
    }
    else if (aes_object->last_decrypted)
    {
      if (aes_object->buffer_length)
      {
        // Can't finish on partial data
        retcheck(JANETLS_ERR_CIPHER_INVALID_DATA_SIZE);
      }
      memcpy(output, aes_object->last_decrypted_block, 16);
      uint8_t size = 0;
      retcheck(janetls_util_padding_unpkcs7(output, 16, &size));
      janet_buffer_push_bytes(output_buffer, output, size);
    }
    else
    {
      // Can't finish on no data?
      retcheck(JANETLS_ERR_CIPHER_INVALID_DATA_SIZE);
    }
    mbedtls_platform_zeroize(output, 16);
    mbedtls_platform_zeroize(block, 16);
  }

  aes_object->flags |= FLAG_AES_FINISH;
  end:
  return ret;
}

// The following comment was found in mbedtls
// The final block is awlays padded in CBC
// Padding is only for CBC
/* Encryption: only cache partial blocks
* Decryption w/ padding: always keep at least one whole block
* Decryption w/o padding: only cache partial blocks
*/

static Janet aes_start(int32_t argc, Janet * argv)
{
  janet_arity(argc, 2, 5);
  janetls_aes_object * aes_object = janetls_new_aes();
  JanetByteView key = empty_byteview();
  JanetByteView iv = empty_byteview();
  janetls_cipher_operation operation = janetls_cipher_operation_encrypt;
  janetls_cipher_padding padding = janetls_cipher_padding_none;
  janetls_aes_mode mode = janetls_aes_mode_ecb;
  int offset = 0;

  check_result(janetls_search_cipher_operation(argv[0], &operation));
  check_result(janetls_search_aes_mode(argv[1], &mode));

  if (argc > 2)
  {
    int pad_ret = janetls_search_cipher_padding(argv[2], &padding);
    if (pad_ret == 0)
    {
      // Found a padding value, all further parameters are offset by 1
      offset++;
    }
  }

  if (argc > offset + 2)
  {
    Janet potential_key = argv[offset + 2];
    if (!janet_checktype(potential_key, JANET_NIL))
    {
      key = janet_to_bytes(potential_key);
    }
  }

  if (argc > offset + 3)
  {
    Janet potential_iv = argv[offset + 3];
    if (!janet_checktype(potential_iv, JANET_NIL))
    {
      iv = janet_to_bytes(potential_iv);
    }
  }

  // Final checks
  if (operation == janetls_cipher_operation_decrypt)
  {
    if (key.len == 0)
    {
      janet_panicf("An key is expected for the mode %p during decryption", argv[0]);
    }

    if (iv.len == 0 && mode != janetls_aes_mode_ecb)
    {
      janet_panicf("An IV or nonce is expected for the mode %p during decryption", argv[0]);
    }
  }

  check_result(janetls_setup_aes(aes_object, mode, key.bytes, key.len, iv.bytes, iv.len, operation, padding));
  return janet_wrap_abstract(aes_object);
}

static Janet aes_update(int32_t argc, Janet * argv)
{
  janet_arity(argc, 2, 3);
  Janet output = janet_wrap_nil();
  janetls_aes_object * aes_object = janet_getabstract(argv, 0, janetls_aes_object_type());
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
  check_result(janetls_aes_update(aes_object, data.bytes, data.len, &output));
  return output;
}

static Janet aes_finish(int32_t argc, Janet * argv)
{
  janet_arity(argc, 1, 2);
  Janet output = janet_wrap_nil();
  janetls_aes_object * aes_object = janet_getabstract(argv, 0, janetls_aes_object_type());
  if (argc > 1)
  {
    if (!janet_checktype(argv[1], JANET_BUFFER))
    {
      janet_panicf("Expected a buffer, but got %p", argv[1]);
    }
    output = argv[1];
  }

  check_result(janetls_aes_finish(aes_object, &output));
  return output;
}

static Janet aes_key(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_aes_object * aes_object = janet_getabstract(argv, 0, janetls_aes_object_type());
  return janet_wrap_string(janet_string(aes_object->key, aes_object->key_size));
}

static Janet aes_iv(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_aes_object * aes_object = janet_getabstract(argv, 0, janetls_aes_object_type());
  if (aes_object->mode == janetls_aes_mode_ecb)
  {
    return janet_wrap_nil();
  }
  return janet_wrap_string(janet_string(aes_object->iv, 16));
}

static Janet aes_mode(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_aes_object * aes_object = janet_getabstract(argv, 0, janetls_aes_object_type());
  return janetls_search_aes_mode_to_janet(aes_object->mode);
}

static Janet aes_padding(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_aes_object * aes_object = janet_getabstract(argv, 0, janetls_aes_object_type());
  return janetls_search_cipher_padding_to_janet(aes_object->padding);
}
