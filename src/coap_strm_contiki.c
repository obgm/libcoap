/* coap_strm_contiki.c -- TCP Network I/O functions for libcoap on Contiki-NG
 *
 * Copyright (C) 2012,2014,2024-2025 Olaf Bergmann <bergmann@tzi.org>
 *               2014      chrysn <chrysn@fsfe.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file coap_strm_contiki.c
 * @brief Contiki-NG-specific Stream (TCP) functions
 */

#include "coap3/coap_libcoap_build.h"

#if defined(WITH_CONTIKI)

#include "contiki-net.h"

int
coap_tcp_is_supported(void) {
  return 0;
}

#if ! COAP_DISABLE_TCP

#if COAP_CLIENT_SUPPORT
int
coap_socket_connect_tcp1(coap_socket_t *sock,
                         const coap_address_t *local_if,
                         const coap_address_t *server,
                         int default_port,
                         coap_address_t *local_addr,
                         coap_address_t *remote_addr) {
  (void)sock;
  (void)local_if;
  (void)server;
  (void)default_port;
  (void)local_addr;
  (void)remote_addr;

  return -1;
}

int
coap_socket_connect_tcp2(coap_socket_t *sock,
                         coap_address_t *local_addr,
                         coap_address_t *remote_addr) {
  (void)sock;
  (void)local_addr;
  (void)remote_addr;

  return -1;
}
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT

int
coap_socket_bind_tcp(coap_socket_t *sock,
                     const coap_address_t *listen_addr,
                     coap_address_t *bound_addr) {
  (void)sock;
  (void)listen_addr;
  (void)bound_addr;

  return -1;
}

int
coap_socket_accept_tcp(coap_socket_t *server,
                       coap_socket_t *new_client,
                       coap_address_t *local_addr,
                       coap_address_t *remote_addr,
                       void *extra) {
  (void)server;
  (void)new_client;
  (void)local_addr;
  (void)remote_addr;
  (void)extra;

  return -1;
}
#endif /* COAP_SERVER_SUPPORT */

ssize_t
coap_socket_write(coap_socket_t *sock, const uint8_t *data, size_t data_len) {
  (void)sock;
  (void)data;
  (void)data_len;
  return -1;
}

ssize_t
coap_socket_read(coap_socket_t *sock, uint8_t *data, size_t data_len) {
  (void)sock;
  (void)data;
  (void)data_len;
  return -1;
}

void
coap_socket_strm_close(coap_socket_t *sock) {
  (void)sock;
}

#endif /* ! COAP_DISABLE_TCP */

#else /* ! WITH_CONTIKI */

#ifdef __clang__
/* Make compilers happy that do not like empty modules. As this function is
 * never used, we ignore -Wunused-function at the end of compiling this file
 */
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
static inline void
dummy(void) {
}

#endif /* ! WITH_CONTIKI */
