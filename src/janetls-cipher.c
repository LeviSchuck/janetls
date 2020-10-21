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
static Janet cipher_encrypt(int32_t argc, Janet * argv);
static Janet cipher_decrypt(int32_t argc, Janet * argv);
static Janet cipher_crypt(int32_t argc, Janet * argv);
static Janet cipher_update(int32_t argc, Janet * argv);
static Janet cipher_update_ad(int32_t argc, Janet * argv);
static Janet cipher_finish(int32_t argc, Janet * argv);
static Janet cipher_tag(int32_t argc, Janet * argv);
static Janet cipher_iv(int32_t argc, Janet * argv);
static Janet cipher_key(int32_t argc, Janet * argv);
static Janet cipher_cipher(int32_t argc, Janet * argv);
static Janet cipher_check_tag(int32_t argc, Janet * argv);


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
  {"update", cipher_update},
  {"update-ad", cipher_update_ad},
  {"finish", cipher_finish},
  {"tag", cipher_tag},
  {"iv", cipher_iv},
  {"key", cipher_key},
  {"cipher", cipher_cipher},
  {"check-tag", cipher_check_tag},
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
  {"cipher/update", cipher_update, ""},
  {"cipher/update-ad", cipher_update_ad, ""},
  {"cipher/finish", cipher_finish, ""},
  {"cipher/tag", cipher_tag, ""},
  {"cipher/iv", cipher_iv, ""},
  {"cipher/key", cipher_key, ""},
  {"cipher/encrypt", cipher_encrypt, ""},
  {"cipher/decrypt", cipher_decrypt, ""},
  {"cipher/crypt", cipher_crypt, ""},
  {"cipher/cipher", cipher_cipher, ""},
  {"cipher/check-tag", cipher_check_tag, ""},
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
  janet_eprintf("Calling init\n");
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
  janet_eprintf("Calling free\n");
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

  janet_eprintf("Setting up cipher to %p\n", janetls_search_cipher_cipher_to_janet(cipher));

  const mbedtls_cipher_info_t * info = mbedtls_cipher_info_from_type(type->mbedtls_type);

  janet_eprintf("Calling setup\n");
  retcheck(mbedtls_cipher_setup(&cipher_object->ctx, info));

  cipher_object->type = type;
  cipher_object->flags |= type->default_flags;

  end:
  return ret;
}

int janetls_cipher_set_key(janetls_cipher_object * cipher_object, const uint8_t * key, size_t length, janetls_cipher_operation operation)
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
      janet_eprintf("Expected length %d but got %d\n", expected_length, length);
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
  janet_eprintf("Before set key with length %d\n", length);
  janet_eprintf("Calling setkey\n");
  retcheck(mbedtls_cipher_setkey(&cipher_object->ctx, cipher_object->key, length * 8, mbedtls_operation));
  janet_eprintf("Key written is %p\n", janet_wrap_string(janet_string(cipher_object->key, length)));

  cipher_object->flags |= FLAG_HAS_KEY;
  cipher_object->key_size = length;

  end:
  return ret;
}

int janetls_cipher_set_iv(janetls_cipher_object * cipher_object, const uint8_t * iv, size_t length)
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
      janet_eprintf("Expected length %d but got %d\n", expected_length, length);
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
    janet_eprintf("Randomly generating IV\n");
    retcheck(janetls_random_set(cipher_object->iv, expected_length));
    length = expected_length;
  }

  janet_eprintf("Calling set_iv\n");
  retcheck(mbedtls_cipher_set_iv(&cipher_object->ctx, cipher_object->iv, length));
  janet_eprintf("IV written is %p\n", janet_wrap_string(janet_string(cipher_object->iv, length)));

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
    // case janetls_cipher_padding_one_and_zeros:
    // mbedtls_padding = MBEDTLS_PADDING_ONE_AND_ZEROS;
    // break;
    case janetls_cipher_padding_pkcs7:
    mbedtls_padding = MBEDTLS_PADDING_PKCS7;
    break;
    // case janetls_cipher_padding_zeros:
    // mbedtls_padding = MBEDTLS_PADDING_ZEROS;
    // break;
    // case janetls_cipher_padding_zeros_and_len:
    // mbedtls_padding = MBEDTLS_PADDING_ZEROS_AND_LEN;
    // break;
    default:
    retcheck(JANETLS_ERR_CIPHER_INVALID_PADDING);
  }

  janet_eprintf("Calling set_padding_mode\n");
  retcheck(mbedtls_cipher_set_padding_mode(&cipher_object->ctx, mbedtls_padding));
  cipher_object->padding = padding;
  cipher_object->flags |= FLAG_HAS_PADDING;

  end:
  return ret;
}

int janetls_cipher_update(
  janetls_cipher_object * cipher_object,
  const uint8_t * data,
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
    janet_eprintf("Calling update\n");
    retcheck(mbedtls_cipher_update(
        &cipher_object->ctx,
        cipher_object->buffer,
        block_size,
        output_content,
        &output_length));
    janet_eprintf("Update with data %p\n", janet_wrap_string(janet_string(cipher_object->buffer, block_size)));
    janet_buffer_push_bytes(buffer, output_content, output_length);
    mbedtls_platform_zeroize(cipher_object->buffer, block_size);
    blocks--;
    cipher_object->buffer_length = 0;
  }

  for (size_t i = 0; i < blocks; i++, offset += block_size)
  {
    janet_eprintf("Calling update\n");
    retcheck(mbedtls_cipher_update(
        &cipher_object->ctx,
        data + offset,
        block_size,
        output_content,
        &output_length));
    janet_eprintf("Update with data %p\n", janet_wrap_string(janet_string(data + offset, block_size)));
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
  const uint8_t * data,
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

  janet_eprintf("Calling update_ad\n");
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
    janet_eprintf("Calling update\n");
    retcheck(mbedtls_cipher_update(
        &cipher_object->ctx,
        cipher_object->buffer,
        cipher_object->buffer_length,
        output_content,
        &output_length));
    janet_eprintf("Finish with data %p\n", janet_wrap_string(janet_string(cipher_object->buffer, cipher_object->buffer_length)));
    if (output_length > 0)
    {
      // This is unlikely, given we know it is under the block size.
      janet_buffer_push_bytes(buffer, output_content, output_length);
    }
  }

  janet_eprintf("Calling finish\n");
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

  if (cipher_object->type == NULL || !(cipher_object->flags & FLAG_FINISHED))
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
    janet_eprintf("Calling write_tag\n");
    retcheck(mbedtls_cipher_write_tag(&cipher_object->ctx, cipher_object->tag, tag_max));
    cipher_object->flags |= FLAG_HAS_TAG;
    janet_eprintf("Tag written is %p\n", janet_wrap_string(janet_string(cipher_object->tag, tag_max)));
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

int janetls_cipher_check_tag(
  janetls_cipher_object * cipher_object,
  const uint8_t * data,
  size_t length,
  Janet * output)
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

  if (length < tag_min || length > tag_max)
  {
    retcheck(JANETLS_ERR_CIPHER_INVALID_TAG_SIZE);
  }

  janet_eprintf("Calling check_tag\n");
  ret = mbedtls_cipher_check_tag(&cipher_object->ctx, data, length);
  if (ret == 0)
  {
    janet_eprintf("Successfully authenticated tag\n");
    *output = janet_wrap_true();
  }
  else if (ret == MBEDTLS_ERR_CIPHER_AUTH_FAILED)
  {
    janet_eprintf("Failed to authenticate tag\n");
    *output = janet_wrap_false();
    ret = 0;
  }

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

static void cipher_setup_options(
  Janet value,
  janetls_cipher_cipher * cipher,
  janetls_cipher_padding * padding,
  janetls_cipher_operation * operation,
  JanetByteView * key,
  JanetByteView * iv,
  JanetByteView * data,
  JanetByteView * additional_data,
  JanetByteView * tag,
  int * padding_set
  )
{
  const JanetKV * kv = NULL;
  const JanetKV * kvs = NULL;
  int32_t len;
  int32_t cap = 0;
  janet_dictionary_view(value, &kvs, &len, &cap);
  janet_eprintf("Options dictionary has %d entries\n", len);
  while ((kv = janet_dictionary_next(kvs, cap, kv)))
  {
    if (janet_is_byte_typed(kv->key))
    {
      JanetByteView option = janet_to_bytes(kv->key);
      if (janet_byte_cstrcmp_insensitive(option, "iv") == 0
        || janet_byte_cstrcmp_insensitive(option, "nonce") == 0)
      {
        if (!janet_is_byte_typed(kv->value))
        {
          janet_panicf("Expected a string or buffer for %p but got %p", kv->key, kv->value);
        }
        *iv = janet_to_bytes(kv->value);
      }
      else if (janet_byte_cstrcmp_insensitive(option, "key") == 0)
      {
        if (!janet_is_byte_typed(kv->value))
        {
          janet_panicf("Expected a string or buffer for %p but got %p", kv->key, kv->value);
        }
        *key = janet_to_bytes(kv->value);
      }
      else if (janet_byte_cstrcmp_insensitive(option, "data") == 0)
      {
        if (!janet_is_byte_typed(kv->value))
        {
          janet_panicf("Expected a string or buffer for %p but got %p", kv->key, kv->value);
        }
        *data = janet_to_bytes(kv->value);
      }
      else if (janet_byte_cstrcmp_insensitive(option, "additional-data") == 0
        || janet_byte_cstrcmp_insensitive(option, "ad") == 0)
      {
        if (!janet_is_byte_typed(kv->value))
        {
          janet_panicf("Expected a string or buffer for %p but got %p", kv->key, kv->value);
        }
        *additional_data = janet_to_bytes(kv->value);
      }
      else if (janet_byte_cstrcmp_insensitive(option, "tag") == 0)
      {
        if (!janet_is_byte_typed(kv->value))
        {
          janet_panicf("Expected a string or buffer for %p but got %p", kv->key, kv->value);
        }
        *tag = janet_to_bytes(kv->value);
      }
      else if (janet_byte_cstrcmp_insensitive(option, "cipher") == 0)
      {
        check_result(janetls_search_cipher_cipher(kv->value, cipher));
      }
      else if (janet_byte_cstrcmp_insensitive(option, "padding") == 0)
      {
        check_result(janetls_search_cipher_padding(kv->value, padding));
        *padding_set = 1;
      }
      else if (janet_byte_cstrcmp_insensitive(option, "operation") == 0)
      {
        check_result(janetls_search_cipher_operation(kv->value, operation));
      }
      else
      {
        janet_eprintf("Unexpected key %p with value %p\n", kv->key, kv->value);
      }
    }
    else
    {
      janet_eprintf("Unexpected key %p with value %p\n", kv->key, kv->value);
    }
  }
}

static Janet cipher_encrypt(int32_t argc, Janet * argv)
{
  janet_arity(argc, 0, 1);
  janetls_cipher_object * cipher_object = janetls_new_cipher();
  janetls_cipher_cipher cipher = janetls_cipher_cipher_aes_256_gcm;
  janetls_cipher_padding padding = janetls_cipher_padding_none;
  int padding_set = 0;
  JanetByteView iv = empty_byteview();
  JanetByteView key = empty_byteview();
  JanetByteView data = empty_byteview();
  JanetByteView additional_data = empty_byteview();

  if (argc > 0)
  {
    Janet value = argv[0];
    if (!janet_checktype(value, JANET_STRUCT)
      && !janet_checktype(value, JANET_TABLE))
    {
      janet_panicf("Expected a struct or table but got %p", value);
    }
    janetls_cipher_operation ignored_operation;
    JanetByteView ignored_tag;
    cipher_setup_options(value, &cipher, &padding, &ignored_operation, &key, &iv, &data, &additional_data, &ignored_tag, &padding_set);
    (void)ignored_operation;
    (void)ignored_tag;
  }

  check_result(janetls_setup_cipher(cipher_object, cipher));
  check_result(janetls_cipher_set_key(cipher_object, key.bytes, key.len, janetls_cipher_operation_encrypt));
  check_result(janetls_cipher_set_iv(cipher_object, iv.bytes, iv.len));
  if (padding_set)
  {
    check_result(janetls_cipher_set_padding(cipher_object, padding));
  }

  // check_result(mbedtls_cipher_reset(&cipher_object->ctx));

  if (additional_data.len > 0)
  {
    Janet ignored;
    check_result(janetls_cipher_update_ad(cipher_object, additional_data.bytes, additional_data.len, &ignored));
    (void)ignored;
  }
  Janet result[2] =
  {
    janet_wrap_abstract(cipher_object),
    janet_wrap_buffer(janet_buffer(data.len + MBEDTLS_MAX_BLOCK_LENGTH)),
  };

  if (data.len > 0)
  {
    check_result(janetls_cipher_update(cipher_object, data.bytes, data.len, result + 1));
    check_result(janetls_cipher_finish(cipher_object, result + 1));
  }

  return janet_wrap_tuple(janet_tuple_n(result, 2));
}

static Janet cipher_decrypt(int32_t argc, Janet * argv)
{
  janet_arity(argc, 0, 1);
  janetls_cipher_object * cipher_object = janetls_new_cipher();
  janetls_cipher_cipher cipher = janetls_cipher_cipher_aes_256_gcm;
  janetls_cipher_padding padding = janetls_cipher_padding_none;
  int padding_set = 0;
  JanetByteView iv = empty_byteview();
  JanetByteView key = empty_byteview();
  JanetByteView data = empty_byteview();
  JanetByteView additional_data = empty_byteview();
  JanetByteView tag = empty_byteview();

  if (argc > 0)
  {
    Janet value = argv[0];
    if (!janet_checktype(value, JANET_STRUCT)
      && !janet_checktype(value, JANET_TABLE))
    {
      janet_panicf("Expected a struct or table but got %p", value);
    }
    janetls_cipher_operation ignored_operation;
    cipher_setup_options(value, &cipher, &padding, &ignored_operation, &key, &iv, &data, &additional_data, &tag, &padding_set);
    (void)ignored_operation;
  }

  if (key.len == 0)
  {
    janet_panic("A :key must be specified in order to decrypt!");
  }

  check_result(janetls_setup_cipher(cipher_object, cipher));
  check_result(janetls_cipher_set_key(cipher_object, key.bytes, key.len, janetls_cipher_operation_decrypt));

  if (iv.len == 0 && cipher_object->flags & FLAG_IV)
  {
    janet_panic("An :iv or :nonce must be specified in order to decrypt!");
  }

  check_result(janetls_cipher_set_iv(cipher_object, iv.bytes, iv.len));
  if (padding_set)
  {
    check_result(janetls_cipher_set_padding(cipher_object, padding));
  }

  // check_result(mbedtls_cipher_reset(&cipher_object->ctx));

  if (additional_data.len > 0)
  {
    Janet ignored;
    check_result(janetls_cipher_update_ad(cipher_object, additional_data.bytes, additional_data.len, &ignored));
    (void)ignored;
  }
  JanetBuffer * output_buffer = janet_buffer(data.len + MBEDTLS_MAX_BLOCK_LENGTH);
  Janet result[2] =
  {
    janet_wrap_abstract(cipher_object),
    janet_wrap_buffer(output_buffer),
  };

  if (data.len > 0)
  {
    janet_eprintf("Data appears to be %p\n", janet_wrap_string(janet_string(data.bytes, data.len)));
    check_result(janetls_cipher_update(cipher_object, data.bytes, data.len, result + 1));
    check_result(janetls_cipher_finish(cipher_object, result + 1));
  }

  if (tag.len > 0)
  {
    if (data.len == 0)
    {
      janet_panic("A :tag can only be specified if the :data is also specified");
    }
    Janet tag_check = janet_wrap_nil();
    check_result(janetls_cipher_check_tag(cipher_object, tag.bytes, tag.len, &tag_check));
    if (!janet_checktype(tag_check, JANET_BOOLEAN) || !janet_unwrap_boolean(tag_check))
    {
      janet_eprintf("Decrypted content was %p\n", janet_wrap_buffer(output_buffer));
      janet_eprintf("Tag appears to be %p\n", janet_wrap_string(janet_string(tag.bytes, tag.len)));
      janet_panic("A :tag was specified but did not authenticate the content successfully");
    }
  }

  return janet_wrap_tuple(janet_tuple_n(result, 2));
}

static Janet cipher_crypt(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 0);

  uint8_t zeros[64];
  uint8_t cipher_text[64];
  uint8_t decrypted_text[64];
  uint8_t tag[64];
  size_t size = 0;
  size_t cipher_text_size = 0;
  size_t decrypted_text_size = 0;
  size_t tag_size = 16;
  size_t plaintext_length = 0;

  mbedtls_platform_zeroize(zeros, 64);
  mbedtls_platform_zeroize(cipher_text, 64);
  mbedtls_platform_zeroize(tag, 64);

  for (size_t i = 0; i < 64; i++)
  {
    tag[i] = i;
  }

  mbedtls_cipher_context_t ctx;
  //    mbedtls_cipher_context_t *pctx = &ctx;
  mbedtls_cipher_init (&ctx);
  check_result(mbedtls_cipher_setup(&ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_GCM)));
  check_result(mbedtls_cipher_setkey(&ctx, zeros, 128, MBEDTLS_ENCRYPT));
  janet_eprintf("\nkey: ");
  for (size_t i = 0; i < 128 / 8; i++)
  {
    janet_eprintf("%02X", zeros[i]);
  }
  check_result(mbedtls_cipher_set_iv (&ctx, zeros, 12));
  janet_eprintf("\niv: ");
  for (size_t i = 0; i < 12; i++)
  {
    janet_eprintf("%02X", zeros[i]);
  }
  check_result(mbedtls_cipher_reset(&ctx));
  // mbedtls_cipher_update_ad (&ctx, aad.data, aad.size);
  // In a loop to work the whole plained input file
  check_result(mbedtls_cipher_update(&ctx, zeros, plaintext_length, cipher_text + cipher_text_size, &size));
  janet_eprintf("\nplaintext: ");
  for (size_t i = 0; i < plaintext_length; i++)
  {
    janet_eprintf("%02X", zeros[i]);
  }
  cipher_text_size += size;
  // After the loop
  check_result(mbedtls_cipher_finish(&ctx, cipher_text + cipher_text_size, &size));
  cipher_text_size += size;

  check_result(mbedtls_cipher_write_tag(&ctx, tag, tag_size));
  mbedtls_cipher_free(&ctx);
  janet_eprintf("\nciphertext: ");
  for (size_t i = 0; i < cipher_text_size; i++)
  {
    janet_eprintf("%02X", cipher_text[i]);
  }
  janet_eprintf("\ntag: ");
  for (size_t i = 0; i < tag_size; i++)
  {
    janet_eprintf("%02X", tag[i]);
  }
  janet_eprintf("\n");

  // Decryption
  mbedtls_cipher_init(&ctx);
  check_result(mbedtls_cipher_setup(&ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_GCM)));
  check_result(mbedtls_cipher_setkey(&ctx, zeros, 128, MBEDTLS_DECRYPT));
  check_result(mbedtls_cipher_set_iv(&ctx, zeros, 12));
  //  mbedtls_cipher_check_tag (&ctx, pTag, tag.size);
  mbedtls_cipher_reset(&ctx);
  check_result(mbedtls_cipher_update_ad(&ctx, zeros, 0));
  // In a loop to work the whole encrypted input file
  check_result(mbedtls_cipher_update(&ctx, cipher_text, cipher_text_size, decrypted_text + decrypted_text_size, &size));
  decrypted_text_size+= size;
  //    mbedtls_cipher_check_tag (&ctx, pTag, tag.size);
  // After the loop
  check_result(mbedtls_cipher_finish(&ctx, decrypted_text + decrypted_text_size, &size));
  decrypted_text_size+= size;

  check_result(mbedtls_cipher_check_tag(&ctx, tag, tag_size));
  mbedtls_cipher_free (&ctx);

  return janet_wrap_nil();
}


static Janet cipher_update(int32_t argc, Janet * argv)
{
  janet_arity(argc, 2, 3);

  Janet output = janet_wrap_nil();

  if (!janet_is_byte_typed(argv[1]))
  {
    janet_panicf("Expected a string or buffer but got %p", argv[1]);
  }

  JanetByteView data = janet_to_bytes(argv[1]);

  if (argc > 2)
  {
    output = argv[2];
  }

  janetls_cipher_object * cipher_object = janet_getabstract(argv, 0, janetls_cipher_object_type());
  check_result(janetls_cipher_update(cipher_object, data.bytes, data.len, &output));

  return output;
}

static Janet cipher_update_ad(int32_t argc, Janet * argv)
{
  janet_arity(argc, 2, 3);

  Janet output = janet_wrap_nil();

  if (!janet_is_byte_typed(argv[1]))
  {
    janet_panicf("Expected a string or buffer but got %p", argv[1]);
  }

  JanetByteView data = janet_to_bytes(argv[1]);

  if (argc > 2)
  {
    output = argv[2];
  }

  janetls_cipher_object * cipher_object = janet_getabstract(argv, 0, janetls_cipher_object_type());
  check_result(janetls_cipher_update_ad(cipher_object, data.bytes, data.len, &output));

  return output;
}

static Janet cipher_finish(int32_t argc, Janet * argv)
{
  janet_arity(argc, 1, 2);

  Janet output = janet_wrap_nil();

  if (argc > 1)
  {
    output = argv[1];
  }

  janetls_cipher_object * cipher_object = janet_getabstract(argv, 0, janetls_cipher_object_type());
  check_result(janetls_cipher_finish(cipher_object, &output));

  return output;
}

static Janet cipher_tag(int32_t argc, Janet * argv)
{
  janet_arity(argc, 1, 3);

  Janet output = janet_wrap_nil();
  size_t tag_size = 0;

  if (argc > 1)
  {
    output = argv[1];
  }

  if (argc > 2)
  {
    double tag_size_number = janet_getnumber(argv, 2);
    tag_size = tag_size_number;
    if (tag_size_number != tag_size)
    {
      janet_panic("The tag size must be a whole number between 4 to 16");
    }
  }


  janetls_cipher_object * cipher_object = janet_getabstract(argv, 0, janetls_cipher_object_type());
  check_result(janetls_cipher_get_tag(cipher_object, &output, tag_size));

  return output;
}

static Janet cipher_iv(int32_t argc, Janet * argv)
{
  janet_arity(argc, 1, 2);

  Janet output = janet_wrap_nil();

  if (argc > 1)
  {
    output = argv[1];
  }

  janetls_cipher_object * cipher_object = janet_getabstract(argv, 0, janetls_cipher_object_type());
  check_result(janetls_cipher_get_iv(cipher_object, &output));

  return output;
}

static Janet cipher_key(int32_t argc, Janet * argv)
{
  janet_arity(argc, 1, 2);

  Janet output = janet_wrap_nil();

  if (argc > 1)
  {
    output = argv[1];
  }

  janetls_cipher_object * cipher_object = janet_getabstract(argv, 0, janetls_cipher_object_type());
  check_result(janetls_cipher_get_key(cipher_object, &output));

  return output;
}

static Janet cipher_cipher(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);

  janetls_cipher_object * cipher_object = janet_getabstract(argv, 0, janetls_cipher_object_type());

  if (cipher_object->type == NULL)
  {
    return janetls_search_cipher_cipher_to_janet(janetls_cipher_cipher_none);
  }

  return janetls_search_cipher_cipher_to_janet(cipher_object->type->cipher);
}

static Janet cipher_check_tag(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 2);

  Janet output = janet_wrap_nil();

  if (!janet_is_byte_typed(argv[1]))
  {
    janet_panicf("Expected string or buffer for tag but got %p", argv[1]);
  }

  janetls_cipher_object * cipher_object = janet_getabstract(argv, 0, janetls_cipher_object_type());
  JanetByteView tag = janet_to_bytes(argv[1]);

  check_result(janetls_cipher_check_tag(cipher_object, tag.bytes, tag.len, &output));

  return output;
}
