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
#include "janetls-bignum.h"
#include "janetls-random.h"
#include "mbedtls/entropy.h"
#include "mbedtls/hmac_drbg.h"

static int bignum_gc_fn(void * data, size_t len);
static int bignum_get_fn(void * data, Janet key, Janet * out);
static Janet bignum_parse(int32_t argc, Janet * argv);
static Janet bignum_parse_bytes(int32_t argc, Janet * argv);
static Janet bignum_generate_prime(int32_t argc, Janet * argv);
static Janet bignum_bit_length(int32_t argc, Janet * argv);
static Janet bignum_size(int32_t argc, Janet * argv);
static Janet bignum_to_string(int32_t argc, Janet * argv);
static Janet bignum_to_bytes(int32_t argc, Janet * argv);
static Janet bignum_add(int32_t argc, Janet * argv);
static Janet bignum_subtract(int32_t argc, Janet * argv);
static Janet bignum_multiply(int32_t argc, Janet * argv);
static Janet bignum_divide(int32_t argc, Janet * argv);
static Janet bignum_divide_remainder(int32_t argc, Janet * argv);
static Janet bignum_modulo(int32_t argc, Janet * argv);
static Janet bignum_inverse_modulo(int32_t argc, Janet * argv);
static Janet bignum_exponent_modulo(int32_t argc, Janet * argv);
static Janet bignum_greatest_common_denominator(int32_t argc, Janet * argv);
static Janet bignum_is_prime(int32_t argc, Janet * argv);
static Janet bignum_compare_janet(int32_t argc, Janet * argv);
static int bignum_compare_untyped(void * x, void * y);
int bignum_compare(bignum_object * x, bignum_object * y);
static void bignum_to_string_untyped(void * bignum, JanetBuffer * buffer);
static void bignum_marshal(void * bignum, JanetMarshalContext * ctx);
static void *bignum_unmarshal(JanetMarshalContext * ctx);
int valid_digits(const uint8_t * bytes, int32_t size, int radix);
void check_result(int mbedtls_result);
static int32_t bignum_hash(void *p, size_t len);
bignum_object * new_bignum();

Janet unknown_to_bignum(Janet value);
Janet unknown_to_bignum_opt(Janet value, int panic, int radix);

JanetAbstractType bignum_object_type = {
  "janetls/bignum",
  bignum_gc_fn,
  NULL,
  bignum_get_fn,
  NULL,
  bignum_marshal,
  bignum_unmarshal,
  bignum_to_string_untyped,
  bignum_compare_untyped,
  bignum_hash,
  JANET_ATEND_HASH
};

static JanetMethod bignum_methods[] = {
  {"bit-length", bignum_bit_length},
  {"size", bignum_size},
  {"to-string", bignum_to_string},
  {"to-bytes", bignum_to_bytes},
  {"+", bignum_add},
  {"-", bignum_subtract},
  {"*", bignum_multiply},
  {"/", bignum_divide},
  {"/%", bignum_divide_remainder},
  {"%", bignum_modulo},
  {"-%", bignum_inverse_modulo},
  {"^%", bignum_exponent_modulo},
  {"greatest-common-denominator", bignum_greatest_common_denominator},
  {"gcd", bignum_greatest_common_denominator},
  {"prime?", bignum_is_prime},
  {"compare", bignum_compare_janet},
  {NULL, NULL}
};

// Note that all janet numbers are internally as doubles.
// They can be casted to 32 bit ints and a subset of 64 bit ints.
// janet_checkint64range and janet_checkintrange will check that the conversion
// poses no loss, in that there is no fractional portion.

static int bignum_get_fn(void *data, Janet key, Janet * out)
{
  (void)data;

  if (!janet_checktype(key, JANET_KEYWORD))
  {
    janet_panicf("expected keyword, got %p", key);
  }

  return janet_getmethod(janet_unwrap_keyword(key), bignum_methods, out);
}

static int bignum_gc_fn(void * data, size_t len)
{
  bignum_object * bignum = (bignum_object *)data;
  mbedtls_mpi_free(&bignum->mpi);
  return 0;
}

static int32_t bignum_hash(void *data, size_t len)
{
  bignum_object * bignum = (bignum_object *)data;
  (void)len;

  // Hash exists, return it
  if (bignum->hash != 0)
  {
    return bignum->hash;
  }

  // Hashing is necessary because structures like tuples
  // rely on hashing for equality checking

  // Lazily create the hash..
  // Unfortunately the mbed TLS library does not provide a means to
  // introspect the data. So a binary must be hashed instead.
  Janet argv[] = {janet_wrap_abstract(bignum)};
  Janet bytes = bignum_to_bytes(1, argv);
  int32_t hash = janet_string_hash(janet_unwrap_string(bytes));
  bignum->hash = hash;
  return hash;
}

static const JanetReg cfuns[] =
{
  {"bignum/parse", bignum_parse, "(janetls/bignum/parse value & opt radix)\n\n"
    "value should be a string, but it will accept anything that turns into a "
    "string of digits. For example, it'll accept native whole-numbers, "
    "buffers, and even abstract objects who's tostring results in a sequence "
    "of digits.\n"
    "radix is by default 10, valid values are 3 to 16. This unfortunately "
    "means binary strings are not accepted as of this version.\n"
    "As a note, all functions below which expect a bignum object will attempt "
    "to use this parsing behavior on all applicable parameters. So bit-length "
    "can be used on a native number, it will internally convert to a bignum "
    "and then run the operation."
    },
  {"bignum/parse-bytes", bignum_parse_bytes, "(janetls/bignum/parse-bytes value &opt variant)\n\n"
    "value should be a string or buffer. All bytes will be read according to "
    "the variant to construct a big number.\n"
    "By default, variant is :big-endian, as most standards expect this "
    "format. Valid options are (for big endian): :big-endian or :big or :be, "
    "(for little endian): :little-endian or :little or :le."
    },
  {"bignum/generate-prime", bignum_generate_prime, "(janetls/bignum/generate-prime bits &opt random quality)\n\n"
    "Generates a bignumber, which is prime, which has a bit-length of the "
    "input: bits. Note that the bit count should be between 3 and 4096. It may "
    "be more on 64 bit platforms, but the higher the bit count, the longer it "
    "takes to generate a prime number.\n"
    "The optional random value is to re-use a random source generator. This "
    "can be obtained from janetls/random/start. If not provided, it will poll "
    "for entropy from the system and allocate a new one. Ideally, reuse one if "
    "you call this function repeatedly.\n"
    "The optional quality value may apply more conditions to the prime. "
    "Valid values are :low-err (lower error probability) or "
    ":dh ((X-1)/2 is prime too), or :low-err-dh (for both)."
    "For Diffie-Hellman key exchange, use :dh.\n"
    "You may want to consult https://www.keylength.com/en/3/\n"
    "This library's documentation should not "
    "in isolation be used to determine the cryptographic strength for your "
    "application! In fact, if you've never used these before, look for a "
    "library that makes these decisions for you."
    },
  {"bignum/bit-length", bignum_bit_length, "(janetls/bignum/bit-length bignum)\n\n"
    "Returns the count of bits required to express this bignumber. When prime "
    "this may be used as a measure of cryptographic strength for that "
    "component. This entirely depends on the algorithm! RSA 3072 is "
    "comparable to a 256 bit elliptic curve, according to "
    "https://www.keylength.com/en/3/\n"
    "This library's documentation should not "
    "in isolation be used to determine the cryptographic strength for your "
    "application! In fact, if you've never used these before, look for a "
    "library that makes these decisions for you."
    },
  {"bignum/size", bignum_size, "(janetls/bignum/size bignum)\n\n"
    "Returns the count of bytes one should expect from calling to-bytes. This "
    "does not allocate a buffer."
    },
  {"bignum/to-string", bignum_to_string, "(janetls/bignum/to-string bignum &opt radix)\n\n"
    "Returns a string of digits for this bignum.\n"
    "radix is by default 10, valid values are 3-16, so bit strings are not "
    "available in this version. You may want to use janetls/bignum/to-bytes "
    "and encode the bytes as a bit-string if you want radix 2."
    },
  {"bignum/to-bytes", bignum_to_bytes, "(janetls/bignum/to-bytes bignum &opt variant)\n\n"
    "Returns bytes as a string encoded in big or little endian.\n"
    "By default, variant is :big-endian, as most standards expect this "
    "format. Valid options are (for big endian): :big-endian or :big or :be, "
    "(for little endian): :little-endian or :little or :le."
    },
  {"bignum/add", bignum_add, "(janetls/bignum/add bignum-x bignum-y)\n\n"
    "Adds x and y together, returns a bignum."
    },
  {"bignum/subtract", bignum_subtract, "(janetls/bignum/subtract bignum-x bignum-y)\n\n"
    "Subtracts y from x, returns a bignum."
    },
  {"bignum/multiply", bignum_multiply, "(janetls/bignum/multiply bignum-x bignum-y)\n\n"
    "Multiplies x by y, returns a bignum."
    },
  {"bignum/divide", bignum_divide, "(janetls/bignum/divide bignum-x bignum-y)\n\n"
    "Divides x over y, returns a bignum, the remainder is lost."
    },
  {"bignum/divide-with-remainder", bignum_divide, "(janetls/bignum/divide-with-remainder bignum-x bignum-y)\n\n"
    "Divides x over y, returns a tuple of (quotient remainder)"
    },
  {"bignum/modulo", bignum_modulo, "(janetls/bignum/modulo bignum-x bignum-y)\n\n"
    "Returns the result of x modulo y as a bignum"
    },
  {"bignum/inverse-modulo", bignum_inverse_modulo, "(janetls/bignum/inverse-modulo bignum-x bignum-y)\n\n"
    "Returns the result of X ^ -1 mod Y, or will return nil if there is no "
    "modular inverse with respect to Y."
    },
  {"bignum/exponent-modulo", bignum_exponent_modulo, "(janetls/bignum/exponent bignum-x bignum-y bignum-z)\n\n"
    "Runs modular exponentiation on the inputs X ^ Y MOD Z. When successful "
    "returns a bignum\n"
    "Note that the modulo Z must be an odd number."
    },
  {"bignum/greatest-common-denominator", bignum_greatest_common_denominator, "(janetls/bignum/greatest-common-denominator bignum-x bignum-y)\n\n"
    "Returns the greatest common denominator of X and Y, that is: the largest "
    "integer that divides for both X and Y. The result will be 1 (as a bignum) "
    "when there is no other candidate."
    },
  {"bignum/prime?", bignum_is_prime, "(janetls/bignum/prime? bignum &opt random)\n\n"
    "Returns a boolean on if this bignum is a prime with a low probability, "
    "sufficient for key generation.\n"
    "The optional random value is to re-use a random source generator. This "
    "can be obtained from janetls/random/start. If not provided, it will poll "
    "for entropy from the system and allocate a new one. Ideally, reuse one if "
    "you call this function repeatedly.\n"
    },
  {"bignum/compare", bignum_compare_janet, "(janetls/bignum/compare x y)\n\n"
    "Returns the standard comparison (-1, 0, 1) between bignums and other "
    "values. If it can be converted to a bignum for proper comparison, it will "
    "sort accordingly. If X is not a convertable to bignum, then X will be "
    "greater than Y. Similarly, if Y is not a convertable to bignum, then Y "
    "will be greater."
    },
  {NULL, NULL, NULL}
};

void submod_bignum(JanetTable *env)
{
  janet_cfuns(env, "janetls", cfuns);
  janet_register_abstract_type(&bignum_object_type);
}

static Janet bignum_parse(int32_t argc, Janet * argv)
{
  int radix = 10;
  janet_arity(argc, 1, 2);

  if (argc > 1)
  {
    double num = janet_getnumber(argv, 1);
    if (janet_checkintrange(num))
    {
      radix = (int)num;
      if (radix == 64)
      {
        janet_panic("janetls/bignum/parse can only handle base 2-16, for "
          "Base64, first decode the value to bytes and use "
          "janetls/bignum/parse-bytes.");
      }
      if (radix < 2 || radix > 16)
      {
        janet_panicf("janetls/bignum/parse can only handle base 2-16, instead, "
          "decode your value to bytes and then use janetls/bignum/parse-bytes.");
      }
    }
    else
    {
      janet_panicf("Expected a whole number for the radix but got %p", argv[1]);
    }
  }

  return unknown_to_bignum_opt(argv[0], 1, radix);
}

static Janet bignum_generate_prime(int32_t argc, Janet * argv)
{
  janet_arity(argc, 1, 3);
  bignum_object * bignum;
  double bits = janet_getnumber(argv, 0);
  int flags = 0;

  size_t gen_bits = (size_t)bits;
  if ((double)gen_bits != bits)
  {
    janet_panicf("The input %f is not a whole number, after all, you can't have a fraction of a bit!", bits);
  }

  if (bits < 3 || bits > MBEDTLS_MPI_MAX_BITS)
  {
    janet_panicf("To generate a prime, you'll need to provide how many bits it'll be. Valid values are between 3 and %d", (long)(MBEDTLS_MPI_MAX_BITS));
  }

  random_object * random = get_or_gen_random_object(argc, argv, 1);

  if (argc > 2)
  {
    if (!janet_checktype(argv[2], JANET_KEYWORD))
    {
      janet_panicf("Expected a keyword like :low-err (lower error probability) "
        "or :dh ((X-1)/2 is prime too), or :low-err-dh (for both) to affect "
        "prime quality, but got %p", argv[2]);
    }
    JanetKeyword keyword = janet_getkeyword(argv, 2);
    if (janet_cstrcmp(keyword, "low-err"))
    {
      flags |= MBEDTLS_MPI_GEN_PRIME_FLAG_LOW_ERR;
    }
    else if (janet_cstrcmp(keyword, "dh"))
    {
      flags |= MBEDTLS_MPI_GEN_PRIME_FLAG_DH;
    }
    else if (janet_cstrcmp(keyword, "low-err-dh"))
    {
      flags |= MBEDTLS_MPI_GEN_PRIME_FLAG_DH | MBEDTLS_MPI_GEN_PRIME_FLAG_LOW_ERR;
    }
    else
    {
      janet_panicf("Expected a keyword like :low-err (lower error probability) "
        "or :dh ((X-1)/2 is prime too), or :low-err-dh (for both) to affect "
        "prime quality, but got %p", argv[2]);
    }
  }

  bignum = new_bignum();
  int ret = mbedtls_mpi_gen_prime(&bignum->mpi, gen_bits, flags, janetls_random_rng, random);

  if (ret != 0)
  {
    janet_panicf("An internal error has occurred generating the random "
      "bignum: %X", (long)ret);
  }

  return janet_wrap_abstract(bignum);
}

static Janet bignum_bit_length(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  bignum_object * bignum = janet_unwrap_abstract(unknown_to_bignum(argv[0]));
  size_t bits = mbedtls_mpi_bitlen(&bignum->mpi);
  return janet_wrap_integer((int32_t) bits);
}

static Janet bignum_size(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  bignum_object * bignum = janet_unwrap_abstract(unknown_to_bignum(argv[0]));
  size_t bytes = mbedtls_mpi_size(&bignum->mpi);
  return janet_wrap_integer((int32_t) bytes);
}

static Janet bignum_to_string(int32_t argc, Janet * argv)
{
  janet_arity(argc, 1, 2);
  bignum_object * bignum = janet_unwrap_abstract(unknown_to_bignum(argv[0]));
  int radix = 10;
  if (argc > 1)
  {
    double num = janet_getnumber(argv, 1);
    if (janet_checkintrange(num))
    {
      radix = (int)num;
      if (radix == 64)
      {
        janet_panic("janetls/bignum/to-string can only handle base 2-16, for "
          "Base64, first use janetls/bignum/to-bytes and then encode with "
          "base64.");
      }
      if (radix < 2 || radix > 16)
      {
        janet_panicf("janetls/bignum/to-string can only handle base 2-16, "
          "instead use jantels/bignum/to-bytes and then encode your value "
          "as desired");
      }
    }
  }
  size_t bytes = 0;
  mbedtls_mpi_write_string(&bignum->mpi, radix, NULL, 0, &bytes);
  char * value = janet_smalloc(bytes);
  if (value == NULL)
  {
    janet_panicf("Could not allocate memory");
  }
  int ret  = mbedtls_mpi_write_string(&bignum->mpi, radix, value, bytes, &bytes);
  if (ret != 0)
  {
    // Free the intermediate value as it will not be used
    janet_sfree(value);
    janet_panicf("An internal error has occurred: %X", (long)ret);
  }
  Janet return_value = janet_cstringv(value);
  // Make sure to free the intermediate value
  janet_sfree(value);

  return return_value;
}

static Janet bignum_compare_janet(int32_t argc, Janet * argv)
{
  Janet first = unknown_to_bignum_opt(argv[0], 0, 10);
  Janet second = unknown_to_bignum_opt(argv[1], 0, 10);
  bignum_object * x = janet_checktype(first, JANET_NIL)
    ? NULL
    : janet_unwrap_abstract(first);
  bignum_object * y = janet_checktype(second, JANET_NIL)
    ? NULL
    : janet_unwrap_abstract(second);
  return janet_wrap_integer(bignum_compare(x, y));
}

static int bignum_compare_untyped(void * x, void * y)
{
  return bignum_compare((bignum_object *) x, (bignum_object *) y);
}

int bignum_compare(bignum_object * x, bignum_object * y)
{
  if (x == NULL)
  {
    return 1;
  }
  else if (y == NULL)
  {
    return -1;
  }
  return mbedtls_mpi_cmp_mpi(&x->mpi, &y->mpi);
}

static Janet bignum_add(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 2);
  bignum_object * x = janet_unwrap_abstract(unknown_to_bignum(argv[0]));
  bignum_object * y = janet_unwrap_abstract(unknown_to_bignum(argv[1]));
  bignum_object * result = new_bignum();
  check_result(mbedtls_mpi_add_mpi(&result->mpi, &x->mpi, &y->mpi));
  return janet_wrap_abstract(result);
}

static Janet bignum_subtract(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 2);
  bignum_object * x = janet_unwrap_abstract(unknown_to_bignum(argv[0]));
  bignum_object * y = janet_unwrap_abstract(unknown_to_bignum(argv[1]));
  bignum_object * result = new_bignum();
  check_result(mbedtls_mpi_sub_mpi(&result->mpi, &x->mpi, &y->mpi));
  return janet_wrap_abstract(result);
}

static Janet bignum_multiply(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 2);
  bignum_object * x = janet_unwrap_abstract(unknown_to_bignum(argv[0]));
  bignum_object * y = janet_unwrap_abstract(unknown_to_bignum(argv[1]));
  bignum_object * result = new_bignum();
  check_result(mbedtls_mpi_mul_mpi(&result->mpi, &x->mpi, &y->mpi));
  return janet_wrap_abstract(result);
}

static Janet bignum_divide(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 2);
  bignum_object * x = janet_unwrap_abstract(unknown_to_bignum(argv[0]));
  bignum_object * y = janet_unwrap_abstract(unknown_to_bignum(argv[1]));
  bignum_object * result = new_bignum();
  bignum_object * remainder = new_bignum();
  check_result(mbedtls_mpi_div_mpi(&result->mpi, &remainder->mpi, &x->mpi, &y->mpi));
  // Remainder is a temporary vailue, it is returned as a result in divide_remainder
  return janet_wrap_abstract(result);
}

static Janet bignum_divide_remainder(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 2);
  bignum_object * x = janet_unwrap_abstract(unknown_to_bignum(argv[0]));
  bignum_object * y = janet_unwrap_abstract(unknown_to_bignum(argv[1]));
  bignum_object * result = new_bignum();
  bignum_object * remainder = new_bignum();
  check_result(mbedtls_mpi_div_mpi(&result->mpi, &remainder->mpi, &x->mpi, &y->mpi));
  Janet return_result[2] = {janet_wrap_abstract(result), janet_wrap_abstract(remainder)};
  return janet_wrap_tuple(janet_tuple_n(return_result, 2));
}

static Janet bignum_modulo(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 2);
  bignum_object * x = janet_unwrap_abstract(unknown_to_bignum(argv[0]));
  bignum_object * y = janet_unwrap_abstract(unknown_to_bignum(argv[1]));
  bignum_object * result = new_bignum();
  check_result(mbedtls_mpi_mod_mpi(&result->mpi, &x->mpi, &y->mpi));
  return janet_wrap_abstract(result);
}

static Janet bignum_inverse_modulo(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 2);
  bignum_object * x = janet_unwrap_abstract(unknown_to_bignum(argv[0]));
  bignum_object * y = janet_unwrap_abstract(unknown_to_bignum(argv[1]));
  bignum_object * result = new_bignum();

  if (mbedtls_mpi_cmp_int(&y->mpi, 1) == 0)
  {
    // Anything mod 1 is 0
    check_result(mbedtls_mpi_lset(&result->mpi, 0));
    return janet_wrap_abstract(result);
  }

  int ret = 0;

  if (mbedtls_mpi_cmp_int(&y->mpi, 0) == -1)
  {
    // This number is negative.. we can flip it to positive.
    mbedtls_mpi negative_one;
    mbedtls_mpi_init(&negative_one);
    mbedtls_mpi_lset(&negative_one, -1);

    mbedtls_mpi negative;
    mbedtls_mpi_init(&negative);

    int ret = mbedtls_mpi_mul_mpi(&negative, &negative_one, &y->mpi);
    mbedtls_mpi_free(&negative_one);
    if (ret != 0)
    {
      mbedtls_mpi_free(&negative);
      check_result(ret);
    }
    ret = mbedtls_mpi_inv_mod(&result->mpi, &x->mpi, &negative);
    mbedtls_mpi_free(&negative);
  }
  else
  {
    ret = mbedtls_mpi_inv_mod(&result->mpi, &x->mpi, &y->mpi);
  }

  if (ret == MBEDTLS_ERR_MPI_NOT_ACCEPTABLE)
  {
    // This means that there won't be a inverse modulo.
    return janet_wrap_nil();
  }

  check_result(ret);
  return janet_wrap_abstract(result);
}

static Janet bignum_exponent_modulo(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 3);
  bignum_object * x = janet_unwrap_abstract(unknown_to_bignum(argv[0]));
  bignum_object * y = janet_unwrap_abstract(unknown_to_bignum(argv[1]));
  bignum_object * z = janet_unwrap_abstract(unknown_to_bignum(argv[2]));

  if (mbedtls_mpi_cmp_int(&z->mpi, 0 ) <= 0)
  {
    janet_panicf("The exponent %p cannot be less than or equal to 0", argv[2]);
  }
  if ((z->mpi.p[0] & 1) == 0)
  {
    janet_panicf("The exponent %p must be odd for the underlying library to accept it", argv[2]);
  }

  bignum_object * result = new_bignum();
  // TODO thread local cache of the helper MPI value here in the last parameter.
  check_result(mbedtls_mpi_exp_mod(&result->mpi, &x->mpi, &y->mpi, &z->mpi, NULL));
  return janet_wrap_abstract(result);
}

static Janet bignum_greatest_common_denominator(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 2);
  bignum_object * x = janet_unwrap_abstract(unknown_to_bignum(argv[0]));
  bignum_object * y = janet_unwrap_abstract(unknown_to_bignum(argv[1]));
  bignum_object * result = new_bignum();
  check_result(mbedtls_mpi_gcd(&result->mpi, &x->mpi, &y->mpi));
  return janet_wrap_abstract(result);
}

static Janet bignum_is_prime(int32_t argc, Janet * argv)
{
  janet_arity(argc, 1, 2);
  bignum_object * bignum = janet_unwrap_abstract(unknown_to_bignum(argv[0]));
  random_object * random = get_or_gen_random_object(argc, argv, 1);
  // 50 rounds is sufficient for key generation
  // Keeps crashing.. TODO
  return janet_wrap_boolean(mbedtls_mpi_is_prime_ext(&bignum->mpi, 50, janetls_random_rng, random) == 0);
}

int check_little_endian(int32_t argc, Janet * argv, int offset)
{
  if (argc > offset)
  {
    JanetKeyword keyword = janet_getkeyword(argv, offset);
    if (janet_cstrcmp(keyword, "le")
      || janet_cstrcmp(keyword, "little")
      || janet_cstrcmp(keyword, "little-endian")) {
      return 1;
    }
    else if (janet_cstrcmp(keyword, "be")
      || janet_cstrcmp(keyword, "big")
      || janet_cstrcmp(keyword, "big-endian"))
    {
      return 0;
    }
    else
    {
      janet_panicf("Expected a keyword like :little, :le, :little-endian, or "
        ":big, :be, :big-endian, but got %p", argv[offset]);
    }
  }
  return 0;
}

static Janet bignum_parse_bytes(int32_t argc, Janet * argv)
{
  janet_arity(argc, 1, 2);

  if (!janet_is_byte_typed(argv[0]))
  {
    janet_panicf("Expected string or buffer, but got %p", argv[0]);
  }

  int little_endian = check_little_endian(argc, argv, 1);
  JanetByteView bytes = janet_to_bytes(argv[0]);
  bignum_object * bignum = new_bignum();
  int ret = 0;
  if (bytes.len > 0)
  {
    ret = little_endian
      ? mbedtls_mpi_read_binary_le(&bignum->mpi, bytes.bytes, bytes.len)
      : mbedtls_mpi_read_binary(&bignum->mpi, bytes.bytes, bytes.len);
  }
  if (ret != 0)
  {
    janet_panicf("Could not decode bignum from bytes %x", (long)ret);
  }

  return janet_wrap_abstract(bignum);
}

static Janet bignum_to_bytes(int32_t argc, Janet * argv)
{
  bignum_object * bignum = janet_getabstract(argv, 0, &bignum_object_type);
  int little_endian = check_little_endian(argc, argv, 1);
  size_t size = mbedtls_mpi_size(&bignum->mpi);
  uint8_t * bytes = janet_smalloc(size);
  if (bytes == NULL)
  {
    janet_panic("Ran out of memory");
  }
  int ret = little_endian
    ? mbedtls_mpi_write_binary_le(&bignum->mpi, bytes, size)
    : mbedtls_mpi_write_binary(&bignum->mpi, bytes, size);
  if (ret != 0)
  {
    janet_sfree(bytes);
    janet_panicf("Could not encode bignum to bytes while marshalling %x", (long)ret);
  }

  return janet_wrap_string(janet_string(bytes, size));
}

static void bignum_to_string_untyped(void * bignum, JanetBuffer * buffer)
{
  Janet argv[1] = {janet_wrap_abstract(bignum)};
  Janet result = bignum_to_string(1, argv);
  janet_buffer_push_string(buffer, janet_unwrap_string(result));
}

static void bignum_marshal(void * bignum_untyped, JanetMarshalContext * ctx)
{
  bignum_object * bignum = (bignum_object *)bignum_untyped;
  size_t size = mbedtls_mpi_size(&bignum->mpi);
  uint8_t * bytes = janet_smalloc(size);
  if (bytes == NULL)
  {
    janet_panic("Ran out of memory");
  }
  int ret = mbedtls_mpi_write_binary(&bignum->mpi, bytes, size);
  if (ret != 0)
  {
    janet_sfree(bytes);
    janet_panicf("Could not encode bignum to bytes while marshalling %x", (long)ret);
  }
  janet_marshal_size(ctx, size);
  janet_marshal_bytes(ctx, bytes, size);
  janet_sfree(bytes);
}

static void * bignum_unmarshal(JanetMarshalContext * ctx)
{
  bignum_object * bignum = janet_unmarshal_abstract(ctx, sizeof(bignum_object));
  mbedtls_mpi_init(&bignum->mpi);
  size_t size = janet_unmarshal_size(ctx);
  int ret = 0;
  if (size > 0)
  {
    uint8_t * bytes = janet_smalloc(size);
    if (bytes == NULL)
    {
      janet_panic("Ran out of memory");
    }
    janet_unmarshal_bytes(ctx, bytes, size);
    mbedtls_mpi_read_binary(&bignum->mpi, bytes, size);
    janet_sfree(bytes);
  }
  if (ret != 0)
  {
    janet_panicf("Internal error while unmarshalling bignum from bytes %x", (long)ret);
  }
  return bignum;
}

Janet unknown_to_bignum(Janet value)
{
  return unknown_to_bignum_opt(value, 1, 10);
}

Janet unknown_to_bignum_opt(Janet value, int panic, int radix)
{
  if (janet_checktype(value, JANET_NUMBER))
  {
    double number = janet_unwrap_number(value);
    mbedtls_mpi_sint integer = (mbedtls_mpi_sint)number;
    if ((double)integer == number)
    {
      bignum_object * converted = new_bignum();
      int ret = mbedtls_mpi_lset(&converted->mpi, integer);
      if (ret != 0)
      {
        if (panic)
        {
          janet_panicf("Could not create a bignum from a number %x", ret);
        }
        else
        {
          return janet_wrap_nil();
        }
      }
      return janet_wrap_abstract(converted);
    }
    else if (panic)
    {
      janet_panicf("Could not convert %p into a bignum, it appears to have a fraction", value);
    }
    else
    {
      return janet_wrap_nil();
    }
  }
  else if (janet_is_byte_typed(value))
  {
    JanetByteView bytes = janet_to_bytes(value);
    // Validate it first..
    if (valid_digits(bytes.bytes, bytes.len, radix))
    {
      bignum_object * converted = new_bignum();
      int ret = mbedtls_mpi_read_string(&converted->mpi, radix, (const char *)bytes.bytes);
      if (ret != 0) {
        if (panic)
        {
          janet_panicf("Could not create a bignum from string or buffer %p", value);
        }
        else
        {
          return janet_wrap_nil();
        }
      }
      return janet_wrap_abstract(converted);
    }
  }
  else if (janet_checktype(value, JANET_ABSTRACT))
  {
    void * untyped_value = janet_unwrap_abstract(value);
    JanetAbstractHead * abstract_head = janet_abstract_head(untyped_value);
    const JanetAbstractType * abstract_type = abstract_head->type;
    if (abstract_type == &bignum_object_type)
    {
      // Good news! this is already a bignum!
      return value;
    }
    // We can handle this type if it comes up
    if (sizeof(mbedtls_mpi_sint) == sizeof(int64_t) && strcmp(abstract_type->name, "core/s64") == 0)
    {
      int64_t * typed_value = (int64_t *) untyped_value;
      bignum_object * converted = new_bignum();
      int ret = mbedtls_mpi_lset(&converted->mpi, *typed_value);
      if (ret != 0)
      {
        if (panic)
        {
          janet_panicf("Could not create a bignum from a s64 %x", ret);
        }
        else
        {
          return janet_wrap_nil();
        }
      }
      return janet_wrap_abstract(converted);
    }
    if (sizeof(mbedtls_mpi_sint) == sizeof(uint64_t) && strcmp(abstract_type->name, "core/u64") == 0)
    {
      uint64_t * typed_value = (uint64_t *) untyped_value;
      // 0x7FF.. is the max value for a 64 bit signed integer
      // We check this before casting to mbedtls_mpi_sint so that no precision
      // is lost.
      if (*typed_value <= 0x7FFFFFFFFFFFFFFF)
      {
        mbedtls_mpi_sint downcasted_value = (mbedtls_mpi_sint)(*typed_value);
        bignum_object * converted = new_bignum();
        int ret = mbedtls_mpi_lset(&converted->mpi, downcasted_value);
        if (ret != 0)
        {
          if (panic)
          {
            janet_panicf("Could not create a bignum from a u64 %x", ret);
          }
          else
          {
            return janet_wrap_nil();
          }
        }
        return janet_wrap_abstract(converted);
      }
    }
    // Fall back to tostring
    if (abstract_type->tostring != NULL)
    {
      JanetBuffer * buffer = janet_buffer(64);
      abstract_type->tostring(untyped_value, buffer);
      // Validate it first..
      if (valid_digits(buffer->data, buffer->count, radix))
      {
        bignum_object * converted = new_bignum();
        int ret = mbedtls_mpi_read_string(&converted->mpi, 10, (const char *)buffer->data);
        if (ret != 0) {
          if (panic)
          {
            janet_panicf("Could not create a bignum from a interpreted string %p", value);
          }
          else
          {
            return janet_wrap_nil();
          }
        }
        return janet_wrap_abstract(converted);
      }
    }
  }
  if (panic)
  {
    janet_panicf("Could not convert %p to a bignum", value);
  }
  // unreachable
  return janet_wrap_nil();
}

int valid_digits(const uint8_t * data, int32_t size, int radix)
{
  for (int32_t i = 0; i < size; i++)
  {
    uint8_t c = data[i];
    if (i == 0 && c == '-')
    {
      continue;
    }
    else if (radix >= 10 && c >= '0' && c <= '9')
    {
      continue;
    }
    else if (c == 0)
    {
      return 1;
    }
    else if (
      c == '0' ||
      c == '1' ||
      ((c == '2') && radix > 2) ||
      ((c == '3') && radix > 3) ||
      ((c == '4') && radix > 4) ||
      ((c == '5') && radix > 5) ||
      ((c == '6') && radix > 6) ||
      ((c == '7') && radix > 7) ||
      ((c == '8') && radix > 8) ||
      ((c == '9') && radix > 9) ||
      ((c == 'a' || c == 'A') && radix > 10) ||
      ((c == 'b' || c == 'B') && radix > 11) ||
      ((c == 'c' || c == 'C') && radix > 12) ||
      ((c == 'd' || c == 'D') && radix > 13) ||
      ((c == 'e' || c == 'E') && radix > 14) ||
      ((c == 'f' || c == 'F') && radix > 15)
      )
    {
      continue;
    }
    return 0;
  }
  return 1;
}

void check_result(int mbedtls_result)
{
  if (mbedtls_result == 0)
  {
    return;
  }
  switch (mbedtls_result)
  {
    case MBEDTLS_ERR_MPI_NOT_ACCEPTABLE: janet_panic("The input value was not acceptable");
    case MBEDTLS_ERR_MPI_NEGATIVE_VALUE: janet_panic("An input value was negative when it cannot be");
    case MBEDTLS_ERR_MPI_INVALID_CHARACTER: janet_panic("Cannot parse, an invalid character was found");
    case MBEDTLS_ERR_MPI_DIVISION_BY_ZERO: janet_panic("Division by zero");
    case MBEDTLS_ERR_MPI_ALLOC_FAILED: janet_panic("Ran out of memory");
    case MBEDTLS_ERR_MPI_BAD_INPUT_DATA: janet_panic("One of the inputs is bad");
    case MBEDTLS_ERR_MPI_FILE_IO_ERROR: janet_panic("File IO error with bignum");
  }
  janet_panicf("An internal error occurred: %x");
}

bignum_object * new_bignum()
{
  bignum_object * result = janet_abstract(&bignum_object_type, sizeof(bignum_object));
  result->flags = 0;
  result->hash = 0;
  mbedtls_mpi_init(&result->mpi);
  return result;
}