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
#include "janetls-cipher.h"
#include "janetls-random.h"

// Abstract Object functions
static int cipher_gc_fn(void * data, size_t len);
static int cipher_gcmark(void * data, size_t len);
static int cipher_get_fn(void * data, Janet key, Janet * out);

// Janet c functions
static Janet ciphers(int32_t argc, Janet * argv);


// internal helpers
const janetls_cipher_type * cipher_type_from(
  janetls_cipher_algorithm algorithm,
  uint16_t key_size,
  janetls_cipher_mode mode,
  janetls_cipher_cipher cipher);

JanetBuffer * buffer_from_output(Janet * output, int32_t max_size);

JanetAbstractType cipher_object_type = {
  "janetls/cipher",
  cipher_gc_fn,
  cipher_gcmark,
  cipher_get_fn,
  JANET_ATEND_GET
};

static JanetMethod cipher_methods[] = {
  {"update", NULL},
  {"update-ad", NULL},
  {"finish", NULL},
  {"tag", NULL},
  {"iv", NULL},
  {NULL, NULL}
};

static const JanetReg cfuns[] =
{
  {"cipher/algorithms", janetls_search_cipher_algorithm_set, "(janetls/cipher/algorithms)\n\n"
    "Provides an tuple of keywords for available cipher algorithms"},
  {"cipher/modes", janetls_search_cipher_mode_set, "(janetls/cipher/modes)\n\n"
    "Provides an tuple of keywords for available cipher modes"},
  {"cipher/paddings", janetls_search_cipher_padding_set, "(janetls/cipher/paddings)\n\n"
    "Provides an tuple of keywords for available cipher paddings"},
  {"cipher/ciphers", janetls_search_cipher_cipher_set, "(janetls/cipher/ciphers)\n\n"
    "Provides an tuple of keywords for available ciphers (like aes-128-cbc)"},
  {"cipher/native-ciphers", ciphers, "internal use, use (cipher/ciphers)"
    },
  {NULL, NULL, NULL}
};

void submod_cipher(JanetTable * env)
{
  janet_cfuns(env, "janetls", cfuns);
  janet_register_abstract_type(janetls_cipher_object_type());
}

#define FLAG_NONE 0
#define FLAG_IV 1
#define FLAG_AEAD 2
#define FLAG_FINISHED 4
#define FLAG_HAS_IV 8
#define FLAG_HAS_DATA 16
#define FLAG_HAS_KEY 32
#define FLAG_HAS_TAG 64
#define FLAG_HAS_AD 128
#define FLAG_HAS_PADDING 256

janetls_cipher_object * janetls_new_cipher()
{
  janetls_cipher_object * cipher = janet_abstract(&cipher_object_type, sizeof(janetls_cipher_object));
  memset(cipher, 0, sizeof(janetls_cipher_object));
  mbedtls_cipher_init(&cipher->ctx);
  return cipher;
}

JanetAbstractType * janetls_cipher_object_type()
{
  return &cipher_object_type;
}

static int cipher_gc_fn(void * data, size_t len)
{
  janetls_cipher_object * cipher = (janetls_cipher_object *)data;
  mbedtls_cipher_free(&cipher->ctx);
  // Ensure the key does not remain in memory
  mbedtls_platform_zeroize(data, len);
  return 0;
}

static int cipher_gcmark(void * data, size_t len)
{
  (void)data;
  (void)len;
  return 0;
}

static int cipher_get_fn(void * data, Janet key, Janet * out)
{
  (void)data;

  if (!janet_checktype(key, JANET_KEYWORD))
  {
    janet_panicf("expected keyword, got %p", key);
  }

  return janet_getmethod(janet_unwrap_keyword(key), cipher_methods, out);
}

int janetls_setup_cipher(janetls_cipher_object * cipher_object, janetls_cipher_cipher cipher)
{
  int ret = 0;
  if (cipher == janetls_cipher_cipher_none)
  {
    retcheck(JANETLS_ERR_CIPHER_INVALID_CIPHER);
  }

  const janetls_cipher_type * type = cipher_type_from(0, 0, 0, cipher);
  if (type->cipher == janetls_cipher_cipher_none)
  {
    retcheck(JANETLS_ERR_CIPHER_INVALID_CIPHER);
  }

  const mbedtls_cipher_info_t * info = mbedtls_cipher_info_from_type(type->mbedtls_type);

  retcheck(mbedtls_cipher_setup(&cipher_object->ctx, info));

  cipher_object->type = type;
  cipher_object->flags |= type->default_flags;

  end:
  return ret;
}

int janetls_cipher_set_key(janetls_cipher_object * cipher_object, uint8_t * key, size_t length, janetls_cipher_operation operation)
{
  int ret = 0;

  if (cipher_object->type == NULL)
  {
    // No type?
    retcheck(JANETLS_ERR_CIPHER_INVALID_STATE);
  }

  if (cipher_object->flags & (FLAG_HAS_KEY))
  {
    // can only set the key once.
    retcheck(JANETLS_ERR_CIPHER_INVALID_STATE);
  }

  size_t expected_length = mbedtls_cipher_get_key_bitlen(&cipher_object->ctx) / 8;

  if (length > 0)
  {
    if (length != expected_length || expected_length > JANETLS_MAX_CIPHER_KEY_SIZE)
    {
      retcheck(JANETLS_ERR_CIPHER_INVALID_KEY_SIZE);
    }

    memcpy(cipher_object->key, key, length);
  }
  else if (cipher_object->flags & FLAG_HAS_KEY)
  {
    // Already has a key, not setting it again
    goto end;
  }
  else if (expected_length == 0)
  {
    // Cannot generate a key if no key size is known
    retcheck(JANETLS_ERR_CIPHER_INVALID_STATE);
  }
  else
  {
    // Randomly generate an key
    retcheck(janetls_random_set(cipher_object->key, expected_length));
    length = expected_length;
  }

  cipher_object->operation = operation;
  mbedtls_operation_t mbedtls_operation;
  switch (operation)
  {
    case janetls_cipher_operation_decrypt:
      mbedtls_operation = MBEDTLS_DECRYPT;
      break;
    case janetls_cipher_operation_encrypt:
      mbedtls_operation = MBEDTLS_ENCRYPT;
      break;
    default:
    retcheck(JANETLS_ERR_CIPHER_INVALID_OPERATION);
  }

  retcheck(mbedtls_cipher_setkey(&cipher_object->ctx, cipher_object->iv, length, mbedtls_operation));

  cipher_object->flags |= FLAG_HAS_KEY;
  cipher_object->key_size = length;

  end:
  return ret;
}

int janetls_cipher_set_iv(janetls_cipher_object * cipher_object, uint8_t * iv, size_t length)
{
  int ret = 0;


  if (!(cipher_object->flags & FLAG_HAS_KEY))
  {
    retcheck(JANETLS_ERR_CIPHER_INVALID_STATE);
  }


  if ((cipher_object->flags & FLAG_HAS_IV) || !(cipher_object->flags & FLAG_IV))
  {
    // Can only set the IV once, and only on algorithms that need IV
    retcheck(JANETLS_ERR_CIPHER_INVALID_STATE);
  }

  size_t expected_length = mbedtls_cipher_get_iv_size(&cipher_object->ctx);

  if (length > 0)
  {
    if (length != expected_length || expected_length > MBEDTLS_MAX_IV_LENGTH)
    {
      retcheck(JANETLS_ERR_CIPHER_INVALID_IV_SIZE);
    }

    memcpy(cipher_object->iv, iv, length);
  }
  else if (cipher_object->flags & FLAG_HAS_IV || expected_length == 0)
  {
    // Already has an IV, not setting it again
    // Or, no IV is needed
    goto end;
  }
  else
  {
    // Randomly generate an IV
    retcheck(janetls_random_set(cipher_object->iv, expected_length));
    length = expected_length;
  }

  retcheck(mbedtls_cipher_set_iv(&cipher_object->ctx, cipher_object->iv, length));

  cipher_object->flags |= FLAG_HAS_IV;
  cipher_object->iv_size = length;

  end:
  return ret;
}

int janetls_cipher_set_padding(janetls_cipher_object * cipher_object, janetls_cipher_padding padding)
{
  int ret = 0;

  if (!(cipher_object->flags & FLAG_HAS_KEY))
  {
    retcheck(JANETLS_ERR_CIPHER_INVALID_STATE);
  }

  if (cipher_object->flags & FLAG_HAS_DATA)
  {
    // Cannot set padding after data is applied
    retcheck(JANETLS_ERR_CIPHER_INVALID_STATE);
  }

  mbedtls_cipher_padding_t mbedtls_padding = MBEDTLS_PADDING_PKCS7;
  switch (padding)
  {
    case janetls_cipher_padding_none:
    mbedtls_padding = MBEDTLS_PADDING_NONE;
    break;
    case janetls_cipher_padding_one_and_zeros:
    mbedtls_padding = MBEDTLS_PADDING_ONE_AND_ZEROS;
    break;
    case janetls_cipher_padding_pkcs7:
    mbedtls_padding = MBEDTLS_PADDING_PKCS7;
    break;
    case janetls_cipher_padding_zeros:
    mbedtls_padding = MBEDTLS_PADDING_ZEROS;
    break;
    case janetls_cipher_padding_zeros_and_len:
    mbedtls_padding = MBEDTLS_PADDING_ZEROS_AND_LEN;
    break;
    default:
    retcheck(JANETLS_ERR_CIPHER_INVALID_PADDING);
  }

  retcheck(mbedtls_cipher_set_padding_mode(&cipher_object->ctx, mbedtls_padding));
  cipher_object->padding = padding;
  cipher_object->flags |= FLAG_HAS_PADDING;

  end:
  return ret;
}

int janetls_cipher_update(
  janetls_cipher_object * cipher_object,
  uint8_t * data,
  size_t length,
  Janet * output)
{
  int ret = 0;
  uint8_t output_content[MBEDTLS_MAX_BLOCK_LENGTH];
  size_t output_length = 0;
  JanetBuffer * buffer = buffer_from_output(output, MBEDTLS_MAX_BLOCK_LENGTH);

  if (length == 0)
  {
    goto end;
  }

  if (cipher_object->flags &  FLAG_FINISHED)
  {
    retcheck(JANETLS_ERR_CIPHER_INVALID_STATE);
  }

  if (!(cipher_object->flags & FLAG_HAS_KEY))
  {
    retcheck(JANETLS_ERR_CIPHER_INVALID_STATE);
  }

  if ((cipher_object->flags & FLAG_IV) && !(cipher_object->flags & FLAG_HAS_IV))
  {
    retcheck(JANETLS_ERR_CIPHER_INVALID_STATE);
  }

  size_t current_buffer_length = cipher_object->buffer_length;
  size_t total_length = current_buffer_length + length;
  size_t block_size = mbedtls_cipher_get_block_size(&cipher_object->ctx);
  size_t blocks = total_length / block_size;
  size_t blocks_length = blocks * block_size;
  size_t remaining_length = total_length - blocks_length;
  size_t offset = 0;
  int partial_first_block = current_buffer_length != 0;
  int partial_last_block = remaining_length != 0;

  if (partial_first_block)
  {
    offset = block_size - current_buffer_length;
    memcpy(cipher_object->buffer + current_buffer_length, data, offset);
    retcheck(mbedtls_cipher_update(
        &cipher_object->ctx,
        cipher_object->buffer,
        block_size,
        output_content,
        &output_length));
    janet_buffer_push_bytes(buffer, output_content, output_length);
    mbedtls_platform_zeroize(cipher_object->buffer, block_size);
    blocks--;
    cipher_object->buffer_length = 0;
  }

  for (size_t i = 0; i < blocks; i++, offset += block_size)
  {
    retcheck(mbedtls_cipher_update(
        &cipher_object->ctx,
        data + offset,
        block_size,
        output_content,
        &output_length));
    janet_buffer_push_bytes(buffer, output_content, output_length);
  }

  if (partial_last_block)
  {
    memcpy(cipher_object->buffer, data + offset, remaining_length);
    cipher_object->buffer_length = remaining_length;
  }

  end:
  return ret;
}

int janetls_cipher_update_ad(
  janetls_cipher_object * cipher_object,
  uint8_t * data,
  size_t length,
  Janet * output)
{
  int ret = 0;

  if (cipher_object->flags & (FLAG_HAS_DATA | FLAG_FINISHED))
  {
    retcheck(JANETLS_ERR_CIPHER_INVALID_STATE);
  }

  if (!(cipher_object->flags & FLAG_HAS_KEY))
  {
    retcheck(JANETLS_ERR_CIPHER_INVALID_STATE);
  }

  if ((cipher_object->flags & FLAG_IV) && !(cipher_object->flags & FLAG_HAS_IV))
  {
    retcheck(JANETLS_ERR_CIPHER_INVALID_STATE);
  }

  switch (cipher_object->type->mode)
  {
    case janetls_cipher_mode_gcm:
    case janetls_cipher_mode_chachapoly:
      break;
    default:
      retcheck(JANETLS_ERR_CIPHER_INVALID_STATE);
      break;
  }

  retcheck(mbedtls_cipher_update_ad(&cipher_object->ctx, data, length));

  *output = janet_wrap_nil();

  end:
  return ret;
}

int janetls_cipher_finish(
  janetls_cipher_object * cipher_object,
  Janet * output)
{
  int ret = 0;
  uint8_t output_content[MBEDTLS_MAX_BLOCK_LENGTH];
  size_t output_length = 0;
  JanetBuffer * buffer = buffer_from_output(output, MBEDTLS_MAX_BLOCK_LENGTH);

  if (!(cipher_object->flags & FLAG_HAS_KEY))
  {
    // No key? set one up
    retcheck(janetls_cipher_set_key(cipher_object, NULL, 0, janetls_cipher_operation_encrypt));
  }

  if ((cipher_object->flags & FLAG_IV) && !(cipher_object->flags & FLAG_HAS_IV))
  {
    // No IV? set one up
    retcheck(janetls_cipher_set_iv(cipher_object, NULL, 0));
  }

  if (cipher_object->flags & FLAG_FINISHED)
  {
    retcheck(JANETLS_ERR_CIPHER_INVALID_STATE);
  }

  if (cipher_object->buffer_length > 0)
  {
    // commit the last partial block
    retcheck(mbedtls_cipher_update(
        &cipher_object->ctx,
        cipher_object->buffer,
        cipher_object->buffer_length,
        output_content,
        &output_length));
    if (output_length > 0)
    {
      // This is unlikely, given we know it is under the block size.
      janet_buffer_push_bytes(buffer, output_content, output_length);
    }
  }

  retcheck(mbedtls_cipher_finish(&cipher_object->ctx, output_content, &output_length));
  if (output_length > 0)
  {
    janet_buffer_push_bytes(buffer, output_content, output_length);
  }

  cipher_object->flags |= FLAG_FINISHED;

  end:
  return ret;
}

int janetls_cipher_get_tag(
  janetls_cipher_object * cipher_object,
  Janet * output,
  size_t tag_size)
{
  int ret = 0;

  if (cipher_object->type == NULL || !(cipher_object->flags & FLAG_HAS_KEY))
  {
    retcheck(JANETLS_ERR_CIPHER_INVALID_STATE);
  }

  int has_tag;
  size_t tag_min;
  size_t tag_max;
  switch (cipher_object->type->mode)
  {
    case janetls_cipher_mode_gcm:
      has_tag = 1;
      tag_min = 4;
      tag_max = 16;
      break;
    case janetls_cipher_mode_chachapoly:
      tag_min = 16;
      tag_max = 16;
      has_tag = 1;
      break;
    default:
      has_tag = 0;
      break;
  }

  if (!has_tag)
  {
    *output = janet_wrap_nil();
    goto end;
  }

  if (tag_size == 0)
  {
    tag_size = tag_max;
  }
  else if (tag_size < tag_min || tag_size > tag_max)
  {
    retcheck(JANETLS_ERR_CIPHER_INVALID_TAG_SIZE);
  }

  if (!(cipher_object->flags & FLAG_HAS_TAG))
  {
    // always calculate the max tag length
    // For GCM, the tag can be truncated, the input length does not affect the
    // output byte content
    // For Cacha20 Poly1305, the tag length is constant
    // This is checked above.
    retcheck(mbedtls_cipher_write_tag(&cipher_object->ctx, cipher_object->tag, tag_max));
    cipher_object->flags |= FLAG_HAS_TAG;
  }

  JanetBuffer * buffer = buffer_from_output(output, tag_size);
  janet_buffer_push_bytes(buffer, cipher_object->tag, tag_size);

  end:
  return ret;
}

int janetls_cipher_get_iv(
  janetls_cipher_object * cipher_object,
  Janet * output)
{
  int ret = 0;

  if (!(cipher_object->flags & FLAG_HAS_IV))
  {
    retcheck(JANETLS_ERR_CIPHER_INVALID_STATE);
  }

  JanetBuffer * buffer = buffer_from_output(output, MBEDTLS_MAX_IV_LENGTH);

  janet_buffer_push_bytes(buffer, cipher_object->iv, cipher_object->iv_size);

  end:
  return ret;
}

int janetls_cipher_get_key(
  janetls_cipher_object * cipher_object,
  Janet * output)
{
  int ret = 0;

  if (!(cipher_object->flags & FLAG_HAS_KEY))
  {
    retcheck(JANETLS_ERR_CIPHER_INVALID_STATE);
  }

  JanetBuffer * buffer = buffer_from_output(output, JANETLS_MAX_CIPHER_KEY_SIZE);
  janet_buffer_push_bytes(buffer, cipher_object->key, cipher_object->key_size);

  end:
  return ret;
}

static const struct janetls_cipher_type mbedtls_cipher_map[] = {
  {janetls_cipher_cipher_aes_128_cbc, janetls_cipher_algorithm_aes, janetls_cipher_mode_cbc, 128, MBEDTLS_CIPHER_AES_128_CBC, FLAG_IV},
  {janetls_cipher_cipher_aes_192_cbc, janetls_cipher_algorithm_aes, janetls_cipher_mode_cbc, 192, MBEDTLS_CIPHER_AES_192_CBC, FLAG_IV},
  {janetls_cipher_cipher_aes_256_cbc, janetls_cipher_algorithm_aes, janetls_cipher_mode_cbc, 256, MBEDTLS_CIPHER_AES_256_CBC, FLAG_IV},
  // {janetls_cipher_cipher_aes_128_ccm, janetls_cipher_algorithm_aes, janetls_cipher_mode_ccm, 128, MBEDTLS_CIPHER_AES_128_CCM, FLAG_IV | FLAG_AEAD},
  // {janetls_cipher_cipher_aes_192_ccm, janetls_cipher_algorithm_aes, janetls_cipher_mode_ccm, 192, MBEDTLS_CIPHER_AES_192_CCM, FLAG_IV | FLAG_AEAD},
  // {janetls_cipher_cipher_aes_356_ccm, janetls_cipher_algorithm_aes, janetls_cipher_mode_ccm, 256, MBEDTLS_CIPHER_AES_256_CCM, FLAG_IV | FLAG_AEAD},
  {janetls_cipher_cipher_aes_128_cfb, janetls_cipher_algorithm_aes, janetls_cipher_mode_cfb, 128, MBEDTLS_CIPHER_AES_128_CFB128, FLAG_IV},
  {janetls_cipher_cipher_aes_192_cfb, janetls_cipher_algorithm_aes, janetls_cipher_mode_cfb, 192, MBEDTLS_CIPHER_AES_192_CFB128, FLAG_IV},
  {janetls_cipher_cipher_aes_256_cfb, janetls_cipher_algorithm_aes, janetls_cipher_mode_cfb, 256, MBEDTLS_CIPHER_AES_256_CFB128, FLAG_IV},
  {janetls_cipher_cipher_aes_128_ctr, janetls_cipher_algorithm_aes, janetls_cipher_mode_ctr, 128, MBEDTLS_CIPHER_AES_128_CTR, FLAG_IV},
  {janetls_cipher_cipher_aes_192_ctr, janetls_cipher_algorithm_aes, janetls_cipher_mode_ctr, 192, MBEDTLS_CIPHER_AES_192_CTR, FLAG_IV},
  {janetls_cipher_cipher_aes_256_ctr, janetls_cipher_algorithm_aes, janetls_cipher_mode_ctr, 256, MBEDTLS_CIPHER_AES_256_CTR, FLAG_IV},
  {janetls_cipher_cipher_aes_128_ecb, janetls_cipher_algorithm_aes, janetls_cipher_mode_ecb, 128, MBEDTLS_CIPHER_AES_128_ECB, FLAG_NONE},
  {janetls_cipher_cipher_aes_192_ecb, janetls_cipher_algorithm_aes, janetls_cipher_mode_ecb, 192, MBEDTLS_CIPHER_AES_192_ECB, FLAG_NONE},
  {janetls_cipher_cipher_aes_256_ecb, janetls_cipher_algorithm_aes, janetls_cipher_mode_ecb, 256, MBEDTLS_CIPHER_AES_256_ECB, FLAG_NONE},
  {janetls_cipher_cipher_aes_128_gcm, janetls_cipher_algorithm_aes, janetls_cipher_mode_gcm, 128, MBEDTLS_CIPHER_AES_128_GCM, FLAG_IV | FLAG_AEAD},
  {janetls_cipher_cipher_aes_192_gcm, janetls_cipher_algorithm_aes, janetls_cipher_mode_gcm, 192, MBEDTLS_CIPHER_AES_192_GCM, FLAG_IV | FLAG_AEAD},
  {janetls_cipher_cipher_aes_256_gcm, janetls_cipher_algorithm_aes, janetls_cipher_mode_gcm, 256, MBEDTLS_CIPHER_AES_256_GCM, FLAG_IV | FLAG_AEAD},
  {janetls_cipher_cipher_aes_128_ofb, janetls_cipher_algorithm_aes, janetls_cipher_mode_ofb, 128, MBEDTLS_CIPHER_AES_128_OFB, FLAG_IV},
  {janetls_cipher_cipher_aes_192_ofb, janetls_cipher_algorithm_aes, janetls_cipher_mode_ofb, 192, MBEDTLS_CIPHER_AES_192_OFB, FLAG_IV},
  {janetls_cipher_cipher_aes_256_ofb, janetls_cipher_algorithm_aes, janetls_cipher_mode_ofb, 256, MBEDTLS_CIPHER_AES_256_OFB, FLAG_IV},
  {janetls_cipher_cipher_chacha20, janetls_cipher_algorithm_chacha20, janetls_cipher_mode_chachapoly, 256, MBEDTLS_CIPHER_CHACHA20_POLY1305, FLAG_IV | FLAG_AEAD},
  {janetls_cipher_cipher_chacha20_poly1305, janetls_cipher_algorithm_chacha20, janetls_cipher_mode_stream, 256, MBEDTLS_CIPHER_CHACHA20, FLAG_IV},
  {janetls_cipher_cipher_none, janetls_cipher_algorithm_none, janetls_cipher_mode_none, 0, MBEDTLS_CIPHER_NONE, FLAG_FINISHED},
};

#define CIPHERS_COUNT (sizeof(mbedtls_cipher_map) / sizeof(struct janetls_cipher_type))
static Janet ciphers(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 0);
  Janet values[CIPHERS_COUNT];
  int size = CIPHERS_COUNT - 1;
  for (int i = 0; i < size; i++)
  {
    const janetls_cipher_type local = mbedtls_cipher_map[i];
    Janet cipher[4];
    cipher[0] = janetls_search_cipher_algorithm_to_janet(local.algorithm);
    cipher[1] = janetls_search_cipher_mode_to_janet(local.mode);
    cipher[2] = janet_wrap_number(local.key_size);
    cipher[3] = janetls_search_cipher_cipher_to_janet(local.cipher);
    values[i] = janet_wrap_tuple(janet_tuple_n(cipher, 4));
  }
  return janet_wrap_tuple(janet_tuple_n(values, size));
}

const janetls_cipher_type * cipher_type_from(
  janetls_cipher_algorithm algorithm,
  uint16_t key_size,
  janetls_cipher_mode mode,
  janetls_cipher_cipher cipher)
{
  const janetls_cipher_type * mapping = mbedtls_cipher_map;
  for (;mapping->cipher != janetls_cipher_cipher_none; mapping++)
  {
    if (
      (key_size == 0 || key_size == mapping->key_size) &&
      (algorithm == janetls_cipher_algorithm_none || algorithm == mapping->algorithm) &&
      (mode == janetls_cipher_mode_none || mode == mapping->mode) &&
      (cipher == janetls_cipher_cipher_none || cipher == mapping->cipher)
      )
    {
      break;
    }
  }
  return mapping;
}



JanetBuffer * buffer_from_output(Janet * output, int32_t max_size)
{
  JanetBuffer * buffer;
  if (janet_checktype(*output, JANET_BUFFER))
  {
    buffer = janet_unwrap_buffer(*output);
  }
  else
  {
    // create a new buffer for the result
    buffer = janet_buffer(max_size);
    *output = janet_wrap_buffer(buffer);
  }
  return buffer;
}
