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
#include "janetls-gcm.h"
#include "mbedtls/platform_util.h"

#define FLAG_FINISH 1

// Abstract Object functions
static int gcm_gc_fn(void * data, size_t len);
static int gcm_gcmark(void * data, size_t len);
static int gcm_get_fn(void * data, Janet key, Janet * out);

// Janet functions
static Janet gcm_encrypt(int32_t argc, Janet * argv);
static Janet gcm_decrypt(int32_t argc, Janet * argv);
static Janet gcm_update(int32_t argc, Janet * argv);
static Janet gcm_finish(int32_t argc, Janet * argv);
static Janet gcm_key(int32_t argc, Janet * argv);
static Janet gcm_iv(int32_t argc, Janet * argv);
static Janet gcm_tag(int32_t argc, Janet * argv);
static Janet gcm_ad(int32_t argc, Janet * argv);

static JanetAbstractType gcm_object_type = {
  "janetls/gcm",
  gcm_gc_fn,
  gcm_gcmark,
  gcm_get_fn,
  JANET_ATEND_GET
};

static JanetMethod gcm_methods[] = {
  {"update", gcm_update},
  {"finish", gcm_finish},
  {"key", gcm_key},
  {"iv", gcm_iv},
  {"tag", gcm_tag},
  {"ad", gcm_ad},
  {NULL, NULL},
};

static const JanetReg cfuns[] =
{
  {"encrypt", gcm_encrypt, ""},
  {"decrypt", gcm_decrypt, ""},
  {"update", gcm_update, ""},
  {"finish", gcm_finish, ""},
  {"key", gcm_key, ""},
  {"iv", gcm_iv, ""},
  {"tag", gcm_tag, ""},
  {"ad", gcm_ad, ""},
  {NULL, NULL, NULL}
};

void submod_gcm(JanetTable * env)
{
  janet_cfuns(env, "janetls", cfuns);
  janet_register_abstract_type(janetls_gcm_object_type());
}

janetls_gcm_object * janetls_new_gcm()
{
  janetls_gcm_object * gcm = janet_abstract(&gcm_object_type, sizeof(janetls_gcm_object));
  memset(gcm, 0, sizeof(janetls_gcm_object));
  mbedtls_gcm_init(&gcm->ctx);
  gcm->ad = janet_wrap_nil();
  gcm->iv = janet_wrap_nil();
  return gcm;
}

JanetAbstractType * janetls_gcm_object_type()
{
  return &gcm_object_type;
}

static int gcm_gc_fn(void * data, size_t len)
{
  janetls_gcm_object * gcm = (janetls_gcm_object *)data;
  mbedtls_gcm_free(&gcm->ctx);
  // Ensure the key and other data does not remain in memory
  mbedtls_platform_zeroize(data, len);
  return 0;
}

static int gcm_gcmark(void * data, size_t len)
{
  janetls_gcm_object * gcm = (janetls_gcm_object *)data;
  (void)len;

  janet_mark(gcm->ad);
  janet_mark(gcm->iv);

  return 0;
}

static int gcm_get_fn(void *data, Janet key, Janet * out)
{
  (void)data;

  if (!janet_checktype(key, JANET_KEYWORD))
  {
    janet_panicf("expected keyword, got %p", key);
  }

  return janet_getmethod(janet_unwrap_keyword(key), gcm_methods, out);
}

int janetls_setup_gcm(
  janetls_gcm_object * gcm_object,
  const uint8_t * key,
  size_t key_length,
  const uint8_t * iv,
  size_t iv_length,
  janetls_cipher_operation operation,
  const uint8_t * ad,
  size_t ad_length
  )
{
  int ret = 0;
  if (key_length == 0)
  {
    // Generate a 256 bit key by default
    janetls_random_set(gcm_object->key, 32);
    gcm_object->key_size = 32;
  }
  else if (key_length == 16 || key_length == 24 || key_length == 32)
  {
    // accept 128, 192, and 256 bit keys
    memcpy(gcm_object->key, key, key_length);
    gcm_object->key_size = key_length;
  }
  else
  {
    retcheck(JANETLS_ERR_CIPHER_INVALID_KEY_SIZE);
  }

  retcheck(mbedtls_gcm_setkey(&gcm_object->ctx, MBEDTLS_CIPHER_ID_AES, gcm_object->key, gcm_object->key_size * 8));

  uint8_t local_iv[12];
  JanetByteView iv_view = empty_byteview();
  if (iv_length == 0)
  {
    janetls_random_set(local_iv, 12);
    iv_view.bytes = local_iv;
    iv_view.len = 12;
  }
  else
  {
    iv_view.bytes = iv;
    iv_view.len = iv_length;
  }

  int op = operation == janetls_cipher_operation_decrypt
    ? MBEDTLS_GCM_DECRYPT
    : MBEDTLS_GCM_ENCRYPT;

  retcheck(mbedtls_gcm_starts(&gcm_object->ctx, op, iv_view.bytes, iv_view.len, ad, ad_length));

  // Now that the GCM context is set up, persist the data received so that
  // it may be retrieved later
  gcm_object->ad = ad_length
    ? janet_wrap_string(janet_string(ad, ad_length))
    : janet_wrap_nil();

  gcm_object->iv = janet_wrap_string(janet_string(iv_view.bytes, iv_view.len));
  gcm_object->operation = operation;

  // And any other temporary or delayed things
  gcm_object->flags = 0;
  gcm_object->buffer_length = 0;
  mbedtls_platform_zeroize(gcm_object->buffer, 16);
  mbedtls_platform_zeroize(gcm_object->tag, 16);

  end:
  mbedtls_platform_zeroize(local_iv, 12);
  return ret;
}

int janetls_gcm_update(
  janetls_gcm_object * gcm_object,
  const uint8_t * data,
  size_t length,
  Janet * output)
{
  int ret = 0;
  if (length == 0)
  {
    // Nothing to process
    goto end;
  }

  if (gcm_object->flags & FLAG_FINISH)
  {
    retcheck(JANETLS_ERR_CIPHER_INVALID_STATE);
  }

  JanetBuffer * output_buffer = buffer_from_output(output, length + 16);
  janet_buffer_extra(output_buffer, length + 16);

  int32_t buffer_used = gcm_object->buffer_length;
  int32_t buffer_remaining = 16 - buffer_used;
  int32_t data_offset = buffer_used == 0 ? 0 : buffer_remaining;
  int32_t blocks_length = length - data_offset;
  int32_t data_blocks = blocks_length / 16;
  int32_t data_remainder = blocks_length % 16;
  uint8_t local_output[16];

  if (data_offset)
  {
    memcpy(gcm_object->buffer + buffer_used, data, data_offset);
    buffer_used += data_offset;
    if (buffer_used >= 16)
    {
      retcheck(mbedtls_gcm_update(&gcm_object->ctx, 16, gcm_object->buffer, local_output));
      janet_buffer_push_bytes(output_buffer, local_output, 16);
      gcm_object->buffer_length = 0;
    }
    else
    {
      gcm_object->buffer_length = buffer_used;
    }
  }
  for (int32_t i = 0; i < data_blocks; i++, data_offset += 16)
  {
    retcheck(mbedtls_gcm_update(&gcm_object->ctx, 16, data + data_offset, local_output));
    janet_buffer_push_bytes(output_buffer, local_output, 16);
  }
  if (data_remainder)
  {
    memcpy(gcm_object->buffer, data + data_offset, data_remainder);
    gcm_object->buffer_length = data_remainder;
  }

  end:
  mbedtls_platform_zeroize(local_output, 16);
  return ret;
}

int janetls_gcm_finish(
  janetls_gcm_object * gcm_object,
  Janet * output)
{
  int ret = 0;
  uint8_t local_output[16];

  if (gcm_object->flags & FLAG_FINISH)
  {
    retcheck(JANETLS_ERR_CIPHER_INVALID_STATE);
  }

  JanetBuffer * output_buffer = buffer_from_output(output, 16);

  uint32_t buffer_length = gcm_object->buffer_length;
  if (buffer_length)
  {
    retcheck(mbedtls_gcm_update(&gcm_object->ctx, buffer_length, gcm_object->buffer, local_output));
    janet_buffer_push_bytes(output_buffer, local_output, buffer_length);
    gcm_object->buffer_length = 0;
    mbedtls_platform_zeroize(gcm_object->buffer, 16);
  }

  retcheck(mbedtls_gcm_finish(&gcm_object->ctx, gcm_object->tag, 16));

  gcm_object->flags |= FLAG_FINISH;

  end:
  mbedtls_platform_zeroize(local_output, 16);
  return ret;
}

static Janet gcm_encrypt(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  return janet_wrap_nil();
}

static Janet gcm_decrypt(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  return janet_wrap_nil();
}

static Janet gcm_update(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  return janet_wrap_nil();
}

static Janet gcm_finish(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  return janet_wrap_nil();
}

static Janet gcm_key(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  return janet_wrap_nil();
}

static Janet gcm_iv(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  return janet_wrap_nil();
}

static Janet gcm_tag(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  return janet_wrap_nil();
}

static Janet gcm_ad(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  return janet_wrap_nil();
}
