/*
 * Copyright (c) 2021 Levi Schuck
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

#include <ctype.h>
#include "janetls.h"
#include "janetls-tls.h"

static int tls_config_gc_fn(void * data, size_t len);
static int tls_config_gcmark(void * data, size_t len);
static int tls_config_get_fn(void * data, Janet key, Janet * out);
static Janet tls_config_client(int32_t argc, Janet * argv);
static Janet tls_config_server(int32_t argc, Janet * argv);
static Janet tls_config_get_verify(int32_t argc, Janet * argv);
static Janet tls_config_get_endpoint(int32_t argc, Janet * argv);
static Janet tls_config_get_transport(int32_t argc, Janet * argv);
static Janet tls_config_get_cert_chain(int32_t argc, Janet * argv);
static Janet tls_config_get_own_cert(int32_t argc, Janet * argv);
static int endpoint_to_int(janetls_tls_endpoint endpoint);
static int transport_to_int(janetls_tls_transport transport);
static int verify_to_int(janetls_tls_verify verify);

static JanetAbstractType tls_config_object_type = {
  "janetls/tls_config",
  tls_config_gc_fn,
  tls_config_gcmark,
  tls_config_get_fn,
  JANET_ATEND_GET
  // TODO marshalling so it can cross thread boundaries
};

static JanetMethod tls_config_methods[] = {
  {"get-verify", tls_config_get_verify},
  {"get-endpoint", tls_config_get_endpoint},
  {"get-transport", tls_config_get_transport},
  {"get-cert-chain", tls_config_get_cert_chain},
  {"get-own-cert", tls_config_get_own_cert},
  {NULL, NULL}
};

static int tls_config_get_fn(void * data, Janet key, Janet * out)
{
  (void)data;

  if (!janet_checktype(key, JANET_KEYWORD))
  {
    // Unexpected type, not found.
    return 0;
  }

  return janet_getmethod(janet_unwrap_keyword(key), tls_config_methods, out);
}

static int tls_config_gc_fn(void * data, size_t len)
{
  janetls_tls_config_object * tls_config = (janetls_tls_config_object *)data;

  mbedtls_ssl_config_free(&tls_config->config);
  return 0;
}

static int tls_config_gcmark(void *data, size_t len)
{
  (void)len;
  janetls_tls_config_object * tls_config = (janetls_tls_config_object *)data;

  if (tls_config->cert_chain != NULL)
  {
    janet_mark(janet_wrap_abstract(tls_config->cert_chain));
  }

  // if (tls_config->own_cert != NULL)
  // {
  //   janet_mark(janet_wrap_abstract(tls_config->own_cert));
  // }

  if (tls_config->random != NULL)
  {
    janet_mark(janet_wrap_abstract(tls_config->random));
  }

  return 0;
}

janetls_tls_config_object * new_tls_config()
{
  janetls_tls_config_object * tls_config = janet_abstract(&tls_config_object_type, sizeof(janetls_tls_config_object));
  memset(tls_config, 0, sizeof(janetls_tls_config_object));
  mbedtls_ssl_config_init(&tls_config->config);
  tls_config->random = janetls_get_random();
  tls_config->cert_chain = NULL;
  // tls_config->own_cert = NULL;
  tls_config->verify = janetls_tls_verify_required;
  tls_config->endpoint = janetls_tls_endpoint_client;
  tls_config->transport = janetls_tls_transport_stream;
  mbedtls_ssl_conf_rng(&tls_config->config, janetls_random_rng, tls_config->random);
  return tls_config;
}

JanetAbstractType * janetls_tls_config_object_type()
{
  return &tls_config_object_type;
}

static const JanetReg cfuns[] =
{
  {"tls/transports", janetls_search_tls_transport_set, "(janetls/tls/transports)\n\n"
    "Provides a tuple of keywords for available transports"},
  {"tls/verifications", janetls_search_tls_verify_set, "(janetls/tls/verifications)\n\n"
    "Provides a tuple of keywords for available verification modes"},
  {"tls/endpoints", janetls_search_tls_endpoint_set, "(janetls/tls/endpoints)\n\n"
    "Provides a tuple of keywords for available endpoint modes"},
  {"tls/get-verify", tls_config_get_verify, "(janetls/tls/get-verify tls-conf)\n\n"
    "Gets the verification mode on a TLS Config object"},
  {"tls/get-endpoint", tls_config_get_endpoint, "(janetls/tls/get-endpoint tls-conf)\n\n"
    "Gets the endpoint mode on a TLS Config object"},
  {"tls/get-transport", tls_config_get_transport, "(janetls/tls/get-transport tls-conf)\n\n"
    "Gets the transport mode on a TLS Config object"},
  {"tls/get-cert-chain", tls_config_get_cert_chain, "(janetls/tls/get-cert-chain tls-conf)\n\n"
    "Gets the Certificate Authority chain on a TLS Config object"},
  {"tls/get-own-cert", tls_config_get_cert_chain, "(janetls/tls/get-own-cert tls-conf)\n\n"
    "Gets the own certificate on a TLS Config object, a client may present this to a server."},
  {"tls/new-client-config", tls_config_client, "(janetls/tls/new-client-config &opt verify-mode certificate-chain transport-mode own-certificate private-key)\n\n"
    "Creates a new TLS Config made for a client. "
    "The optional flags may be set to null in which the defaults are used.\n"
    "Inputs:\n"
    "verify-mode - keyword for verification mode, see (janetls/tls/verifications)\n"
    "certificate-chain - an x509 certificate authority chain, see janetls/x509 module\n"
    "transport-mode - keyword for transport mode, see (janetls/tls/transports), not likely to be used\n"
    "own-certificate - certificate to present to the server peer, not likely to be used\n"
    "private-key - private key (must be wrapped by janetls/tls/pk-wrap)\n"
    "Returns a TLS Config object for use in a TLS Context, can be shared among contexts."
    },
  {"tls/new-server-config", tls_config_server, "(janetls/tls/new-server-config &opt own-certificate private-key transport-mode verify-mode certificate-chain)\n\n"
    "Creates a new TLS Config made for a server. "
    "The optional flags may be set to null in which the defaults are used.\n"
    "Inputs:\n"
    "own-certificate - certificate to present to the client peer\n"
    "private-key - private key (must be wrapped by janetls/tls/pk-wrap)\n"
    "transport-mode - keyword for transport mode, see (janetls/tls/transports), not likely to be used\n"
    "verify-mode - keyword for verification mode, see (janetls/tls/verifications), not likely to be used\n"
    "certificate-chain - an x509 certificate authority chain, see janetls/x509 module, "
    "for mutual auth client certificate validation, not likely to be used\n"
    "Returns a TLS Config object for use in a TLS Context, can be shared among contexts."
    },
  {NULL, NULL, NULL}
};

void submod_tls(JanetTable * env)
{
  janet_cfuns(env, "janetls", cfuns);
  janet_register_abstract_type(&tls_config_object_type);
}

static Janet tls_config_client(int32_t argc, Janet * argv)
{
  janet_arity(argc, 0, 4);
  janetls_tls_config_object * config = new_tls_config();
  janetls_x509_crt_object * cert_chain = NULL;
  // janetls_x509_crt_object * own_cert = NULL;
  janetls_tls_verify verify = janetls_tls_verify_required;
  janetls_tls_transport transport = janetls_tls_transport_stream;

  if (argc > 0 && !janet_checktype(argv[0], JANET_NIL)) {
    if (janetls_search_tls_verify(argv[0], &verify) != 0)
    {
      janet_panicf("Could not find a verification mode for %p, see (janetls/tls/verifications) for options", argv[0]);
    }
  }

  if (argc > 1 && !janet_checktype(argv[1], JANET_NIL)) {
    cert_chain = janet_getabstract(argv, 1, janetls_x509_crt_object_type());
  }

  if (argc > 2 && !janet_checktype(argv[2], JANET_NIL)) {
    if (janetls_search_tls_transport(argv[2], &transport) != 0)
    {
      janet_panicf("Could not find a transport mode for %p, see (janetls/tls/transports) for options", argv[0]);
    }
  }

  if (argc > 3 && !janet_checktype(argv[1], JANET_NIL)) {
    janet_panic("own-cert is not supported yet");
  }

  if (verify == janetls_tls_verify_required && cert_chain == NULL)
  {
    janet_panic("By default the TLS config will verify connections, "
      "however no certificate chain was supplied, see (doc janetls/tls/new-client-config)");
  }

  config->verify = verify;
  config->endpoint = janetls_tls_endpoint_client;
  config->transport = transport;
  mbedtls_ssl_config_defaults(&config->config, endpoint_to_int(janetls_tls_endpoint_client), transport_to_int(transport), MBEDTLS_SSL_PRESET_DEFAULT);
  mbedtls_ssl_conf_authmode(&config->config, verify_to_int(verify));

  if (cert_chain)
  {
    config->cert_chain = cert_chain;
    // No CRL support
    mbedtls_ssl_conf_ca_chain(&config->config, &cert_chain->crt, NULL);
  }

  // Own cert requires a private key using the pk namespace.
  // Janetls does not currently implement a pathway from janetls pk to mbedtls pk
  // if (own_cert)
  // {
  //   config->own_cert = own_cert;
  //   mbedtls_ssl_conf_own_cert(&config->config, &cert_chain->crt, TODO);
  // }

  return janet_wrap_abstract(config);
}

static Janet tls_config_server(int32_t argc, Janet * argv)
{
  janet_panic("Not yet implemented");
  return janet_wrap_nil();
}

static Janet tls_config_get_verify(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_tls_config_object * config = janet_getabstract(argv, 0, &tls_config_object_type);
  return janetls_search_tls_verify_to_janet(config->verify);
}

static Janet tls_config_get_endpoint(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_tls_config_object * config = janet_getabstract(argv, 0, &tls_config_object_type);
  return janetls_search_tls_endpoint_to_janet(config->endpoint);
}

static Janet tls_config_get_transport(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_tls_config_object * config = janet_getabstract(argv, 0, &tls_config_object_type);
  return janetls_search_tls_transport_to_janet(config->transport);
}

static Janet tls_config_get_cert_chain(int32_t argc, Janet * argv)
{
  janet_fixarity(argc, 1);
  janetls_tls_config_object * config = janet_getabstract(argv, 0, &tls_config_object_type);
  if (config->cert_chain != NULL)
  {
    return janet_wrap_abstract(config->cert_chain);
  }
  return janet_wrap_nil();
}

static Janet tls_config_get_own_cert(int32_t argc, Janet * argv)
{
  // janet_fixarity(argc, 1);
  // janetls_tls_config_object * config = janet_getabstract(argv, 0, &tls_config_object_type);
  // if (config->own_cert != NULL)
  // {
  //   return janet_wrap_abstract(config->own_cert);
  // }
  return janet_wrap_nil();
}

static int endpoint_to_int(janetls_tls_endpoint endpoint)
{
  if (endpoint == janetls_tls_endpoint_server)
  {
    return MBEDTLS_SSL_IS_SERVER;
  }
  return MBEDTLS_SSL_IS_CLIENT;
}

static int transport_to_int(janetls_tls_transport transport)
{
  if (transport == janetls_tls_transport_datagram)
  {
    return MBEDTLS_SSL_TRANSPORT_DATAGRAM;
  }
  return MBEDTLS_SSL_TRANSPORT_STREAM;
}

static int verify_to_int(janetls_tls_verify verify)
{
  switch (verify)
  {
    case janetls_tls_verify_none: return MBEDTLS_SSL_VERIFY_NONE;
    case janetls_tls_verify_optional: return MBEDTLS_SSL_VERIFY_OPTIONAL;
    case janetls_tls_verify_required: return MBEDTLS_SSL_VERIFY_REQUIRED;
    case janetls_tls_verify_unset: return MBEDTLS_SSL_VERIFY_UNSET;
  }
  return MBEDTLS_SSL_VERIFY_REQUIRED;
}
