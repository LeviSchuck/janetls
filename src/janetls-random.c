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

static int random_gc_fn(void * data, size_t len);
static int random_get_fn(void * data, Janet key, Janet * out);
static Janet random_get_bytes(int32_t argc, Janet * argv);

static JanetAbstractType random_object_type = {
  "janetls/random",
  random_gc_fn,
  NULL,
  random_get_fn,
  JANET_ATEND_GET
};

static JanetMethod random_methods[] = {
  {"get", random_get_bytes},
  {NULL, NULL}
};

// Note that all janet numbers are internally as doubles.
// They can be casted to 32 bit ints and a subset of 64 bit ints.
// janet_checkint64range and janet_checkintrange will check that the conversion
// poses no loss, in that there is no fractional portion.

static int random_get_fn(void * data, Janet key, Janet * out)
{
  (void)data;

  if (!janet_checktype(key, JANET_KEYWORD))
  {
    // Unexpected type, not found.
    return 0;
  }

  return janet_getmethod(janet_unwrap_keyword(key), random_methods, out);
}

static int random_gc_fn(void * data, size_t len)
{
  janetls_random_object * random = (janetls_random_object *)data;
  mbedtls_ctr_drbg_free(&random->drbg);
  mbedtls_entropy_free(&random->entropy);
  return 0;
}

JanetAbstractType * janetls_random_object_type()
{
  return &random_object_type;
}

static const JanetReg cfuns[] =
{
  {"util/random", random_get_bytes, "(janetls/util/random length)\n\n"
    "Returns a binary string of length using the random number generator."
    "The internal mechanism uses a deterministic random bit generator, "
    "which means that additional entropy from the system is not used. "
    "However for infrequent cases outside of the janetls library, "
    "os/cryptorand may suit your needs better."
    },

  {NULL, NULL, NULL}
};

void submod_random(JanetTable *env)
{
  janet_cfuns(env, "janetls", cfuns);
  janet_register_abstract_type(&random_object_type);
}

static janetls_random_object * janetls_new_random()
{
  janetls_random_object * random = janet_abstract(&random_object_type, sizeof(janetls_random_object));
  memset(random, 0, sizeof(janetls_random_object));
  mbedtls_entropy_init(&random->entropy);
  mbedtls_ctr_drbg_init(&random->drbg);
  int ret = mbedtls_ctr_drbg_seed(&random->drbg, mbedtls_entropy_func, &random->entropy, NULL, 0);
  if (ret != 0)
  {
    janet_panicf("Could not setup randomness with seed data, error %X", (long)ret);
  }
  return random;
}


static Janet random_get_bytes(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_random_object * random = janetls_get_random();
  double num = janet_getnumber(argv, 0);
  size_t bytes = (size_t)num;

  if (num != (double)bytes)
  {
    janet_panicf("Expected a whole number of bytes, but got %p", argv[0]);
  }

  if (bytes > MBEDTLS_CTR_DRBG_MAX_REQUEST)
  {
    janet_panicf("Cannot request more than %d bytes", (long)(MBEDTLS_CTR_DRBG_MAX_REQUEST));
  }

  uint8_t * buffer = janet_smalloc(bytes);

  if (buffer == NULL)
  {
    janet_panic("Could not allocate memory");
  }

  int ret = mbedtls_ctr_drbg_random(&random->drbg, buffer, bytes);
  if (ret != 0)
  {
    janet_sfree(buffer);
    janet_panicf("Could not fill random data, error %X", (long)ret);
  }

  Janet value = janet_wrap_string(janet_string(buffer, bytes));
  janet_sfree(buffer);
  return value;
}

int janetls_random_rng(void * untyped_random, unsigned char * buffer, size_t size)
{
  janetls_random_object * random = (janetls_random_object *) untyped_random;
  if (random == NULL)
  {
    random = janetls_get_random();
  }
  return mbedtls_ctr_drbg_random(&random->drbg, buffer, size);
}

int janetls_random_set(uint8_t * buffer, size_t size)
{
  janetls_random_object * random = janetls_get_random();
  return mbedtls_ctr_drbg_random(&random->drbg, buffer, size);
}

janetls_random_object * janetls_get_random()
{
  static JANET_THREAD_LOCAL janetls_random_object * thread_random = NULL;
  if (thread_random == NULL)
  {
    thread_random = janetls_new_random();
    // make sure it doesn't get evicted.
    janet_gcroot(janet_wrap_abstract(thread_random));
  }
  return thread_random;
}

