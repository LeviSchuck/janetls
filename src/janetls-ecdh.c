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
#include "janetls-ecdh.h"
#include "janetls-ecp.h"
#include "janetls-bignum.h"

static Janet ecdh_generate_key(int32_t argc, Janet * argv);
static Janet ecdh_compute(int32_t argc, Janet * argv);

static const JanetReg cfuns[] =
{
  {"ecdh/generate-key", ecdh_generate_key, ""},
  {"ecdh/compute", ecdh_compute, ""},
  {NULL, NULL, NULL}
};

void submod_ecdh(JanetTable * env)
{
  janet_cfuns(env, "janetls", cfuns);
}

static Janet ecdh_generate_key(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);

  janetls_ecp_group_object * group = group_from_janet(argv[0], 1);
  janetls_ecp_keypair_object * keypair = janetls_new_ecp_keypair_object();
  keypair->group = group;
  check_result(mbedtls_ecp_group_copy(&keypair->keypair.grp, &group->ecp_group));
  check_result(mbedtls_ecdh_gen_public(
    &group->ecp_group,
    &keypair->keypair.d,
    &keypair->keypair.Q,
    janetls_random_rng,
    janetls_get_random()
    ));

  uint8_t buf[MBEDTLS_ECP_MAX_BYTES];
  size_t length = (keypair->group->ecp_group.nbits + 7) / 8;
  if (length > MBEDTLS_ECP_MAX_BYTES)
  {
    janet_panicf("The given curve has a larger bit size than is "
      "supported, the bit size appears to be %d", keypair->group->ecp_group.nbits);
  }

  check_result(mbedtls_ecp_write_key(&keypair->keypair, buf, length));
  keypair->secret = janet_wrap_string(janet_string(buf, length));

  return janet_wrap_abstract(keypair);
}

static Janet ecdh_compute(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 2);
  janetls_ecp_keypair_object * private =
    janet_getabstract(argv, 0, janetls_ecp_keypair_object_type());
  janetls_ecp_point_object * public = point_from_janet(argv[1], 1);
  // TODO check group equality
  janetls_bignum_object * secret = janetls_new_bignum();
  check_result(mbedtls_ecdh_compute_shared(
    &private->group->ecp_group,
    &secret->mpi,
    &public->point,
    &private->keypair.d,
    janetls_random_rng,
    janetls_get_random()
    ));
  uint8_t buf[MBEDTLS_ECP_MAX_BYTES];

  size_t len = mbedtls_mpi_size(&secret->mpi);
  if (len > MBEDTLS_ECP_MAX_BYTES)
  {
    janet_panic("Internal error, cannot export secret");
  }
  check_result(mbedtls_mpi_write_binary(&secret->mpi, buf, len));
  return janet_wrap_string(janet_string(buf, len));
}
