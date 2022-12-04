/*
 * client-coap.c -- LwIP example
 *
 * Copyright (C) 2013-2016 Christian Amsüss <chrysn@fsfe.org>
 * Copyright (C) 2018-2022 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#include "coap_config.h"
#include <coap3/coap.h>
#include <coap3/coap_debug_macros.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "client-coap.h"

#ifndef COAP_URI
#define COAP_URI "coap://libcoap.net"
#endif /* COAP_URI */

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

static coap_context_t *main_coap_context = NULL;
static coap_optlist_t *optlist = NULL;

static int quit = 0;

static coap_response_t
message_handler(coap_session_t *session,
                const coap_pdu_t *sent,
                const coap_pdu_t *received,
                const coap_mid_t id) {
  const uint8_t *data;
  size_t len;
  size_t offset;
  size_t total;

  (void)session;
  (void)sent;
  (void)id;
  if (coap_get_data_large(received, &len, &data, &offset, &total)) {
    printf("%*.*s", (int)len, (int)len, (const char*)data);
    if (len + offset == total) {
      printf("\n");
      quit = 1;
    }
  }
  return COAP_RESPONSE_OK;
}

static void
nack_handler(coap_session_t *session COAP_UNUSED,
             const coap_pdu_t *sent COAP_UNUSED,
             const coap_nack_reason_t reason,
             const coap_mid_t id COAP_UNUSED) {

  switch(reason) {
  case COAP_NACK_TOO_MANY_RETRIES:
  case COAP_NACK_NOT_DELIVERABLE:
  case COAP_NACK_RST:
  case COAP_NACK_TLS_FAILED:
    coap_log(LOG_ERR, "cannot send CoAP pdu\n");
    quit = 1;
    break;
  case COAP_NACK_ICMP_ISSUE:
  default:
    ;
  }
  return;
}

static int
resolve_address(const char *host, const char *service, coap_address_t *dst) {

  struct addrinfo *res, *ainfo;
  struct addrinfo hints;
  int error, len=-1;
  struct sockaddr_in *sock4;
  struct sockaddr_in6 *sock6;

  memset(&hints, 0, sizeof(hints));
  memset(dst, 0, sizeof(*dst));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_family = AF_UNSPEC;

  error = getaddrinfo(host, service, &hints, &res);

  if (error != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
    return error;
  }

  for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {
    switch (ainfo->ai_family) {
    case AF_INET:
      sock4 = (struct sockaddr_in *)ainfo->ai_addr;
      dst->port = ntohs(sock4->sin_port);
      len = ainfo->ai_addrlen;
      memcpy(&dst->addr, &sock4->sin_addr, 4);
      dst->addr.type = IPADDR_TYPE_V4;
      goto finish;
    case AF_INET6:
      sock6 = (struct sockaddr_in6 *)ainfo->ai_addr;
      dst->port = ntohs(sock6->sin6_port);
      len = ainfo->ai_addrlen;
      memcpy(&dst->addr, &sock6->sin6_addr, 16);
      dst->addr.type = IPADDR_TYPE_V6;
      goto finish;
    default:
      ;
    }
  }

 finish:
  freeaddrinfo(res);
  return len;
}

void
client_coap_init(coap_lwip_input_wait_handler_t input_wait, void *input_arg,
                 int argc, char **argv) {
  coap_session_t *session = NULL;
  coap_pdu_t *pdu;
  coap_address_t dst;
  coap_mid_t mid;
  int len;
  coap_uri_t uri;
  char portbuf[8];
#define BUFSIZE 100
  unsigned char buf[BUFSIZE];
  int res;
  const char *use_uri = COAP_URI;
  int opt;
  coap_log_t log_level = LOG_WARNING;
  coap_log_t dtls_log_level = LOG_ERR;
  const char *use_psk = "secretPSK";
  const char *use_id = "abc";

  while ((opt = getopt(argc, argv, ":k:u:v:V:")) != -1) {
    switch (opt) {
    case 'k':
      use_psk = optarg;
      break;
    case 'u':
      use_id = optarg;
      break;
    case 'v':
      log_level = atoi(optarg);
      break;
    case 'V':
      dtls_log_level = atoi(optarg);
      break;
    default:
      printf("%s [-k PSK] [-u id] [-v level] [ -V level] [URI]\n", argv[0]);
      exit(1);
    }
  }

  if (optind < argc) {
    use_uri = argv[optind];
  }

  coap_set_log_level(log_level);
  coap_dtls_set_log_level(dtls_log_level);

  /* Parse the URI */
  len = coap_split_uri((const unsigned char *)use_uri, strlen(use_uri), &uri);
  LWIP_ASSERT("Failed to parse uri", len == 0);
  LWIP_ASSERT("Unsupported URI type", uri.scheme == COAP_URI_SCHEME_COAP ||
                                      uri.scheme == COAP_URI_SCHEME_COAPS);

  snprintf(portbuf, sizeof(portbuf), "%d", uri.port);
  snprintf((char *)buf, sizeof(buf), "%*.*s", (int)uri.host.length,
           (int)uri.host.length, (const char *)uri.host.s);
  /* resolve destination address where server should be sent */
  len = resolve_address((const char*)buf, portbuf, &dst);
  LWIP_ASSERT("Failed to resolve address", len > 0);

  main_coap_context = coap_new_context(NULL);
  LWIP_ASSERT("Failed to initialize context", main_coap_context != NULL);

  coap_context_set_block_mode(main_coap_context, COAP_BLOCK_USE_LIBCOAP);
  coap_lwip_set_input_wait_handler(main_coap_context, input_wait, input_arg);

  if (uri.scheme == COAP_URI_SCHEME_COAP) {
    session = coap_new_client_session(main_coap_context, NULL, &dst,
                                      COAP_PROTO_UDP);
  } else {
    static coap_dtls_cpsk_t dtls_psk;
    static char client_sni[256];

    memset(client_sni, 0, sizeof(client_sni));
    memset (&dtls_psk, 0, sizeof(dtls_psk));
    dtls_psk.version = COAP_DTLS_CPSK_SETUP_VERSION;
    if (uri.host.length)
      memcpy(client_sni, uri.host.s,
             min(uri.host.length, sizeof(client_sni) - 1));
    else
      memcpy(client_sni, "localhost", 9);
    dtls_psk.client_sni = client_sni;
    dtls_psk.psk_info.identity.s = (const uint8_t *)use_id;
    dtls_psk.psk_info.identity.length = strlen(use_id);
    dtls_psk.psk_info.key.s = (const uint8_t *)use_psk;
    dtls_psk.psk_info.key.length = strlen(use_psk);

    session = coap_new_client_session_psk2(main_coap_context, NULL, &dst,
                                           COAP_PROTO_DTLS, &dtls_psk);
  }

  LWIP_ASSERT("Failed to create session", session != NULL);

  coap_register_response_handler(main_coap_context, message_handler);
  coap_register_nack_handler(main_coap_context, nack_handler);

  /* construct CoAP message */
  pdu = coap_pdu_init(COAP_MESSAGE_CON,
                      COAP_REQUEST_CODE_GET,
                      coap_new_message_id(session),
                      coap_session_max_pdu_size(session));
  LWIP_ASSERT("Failed to create PDU", pdu != NULL);

  len = coap_uri_into_options(&uri, &optlist, 1, buf, sizeof(buf));
  LWIP_ASSERT("Failed to create options", len == 0);

  /* Add option list (which will be sorted) to the PDU */
  if (optlist) {
    res = coap_add_optlist_pdu(pdu, &optlist);
    LWIP_ASSERT("Failed to add options to PDU", res == 1);
  }

  /* and send the PDU */
  mid = coap_send(session, pdu);
  LWIP_ASSERT("Failed to send PDU", mid != COAP_INVALID_MID);
}

void
client_coap_finished(void) {
  coap_delete_optlist(optlist);
  coap_free_context(main_coap_context);
  main_coap_context = NULL;
}

int
client_coap_poll(void) {
  coap_io_process(main_coap_context, 1000);
  return quit;
}
