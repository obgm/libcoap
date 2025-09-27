/* coap_dgrm_contiki.c -- UDP Network I/O functions for libcoap on Contiki-NG
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
 * @file coap_dgrm_contiki.c
 * @brief Contiki-NG-specific Datagram (UDP) functions
 */

#include "coap3/coap_libcoap_build.h"

#if defined(WITH_CONTIKI)

#include "contiki-net.h"

extern struct process libcoap_io_process;

int
coap_socket_bind_udp(coap_socket_t *sock,
                     const coap_address_t *listen_addr,
                     coap_address_t *bound_addr) {
  uip_ds6_addr_t *addr;

  addr = uip_ds6_get_global(ADDR_PREFERRED);
  if (!addr) {
    coap_log_err("coap_socket_bind_udp: called before getting an IPv6 address\n");
    return 0;
  }
  PROCESS_CONTEXT_BEGIN(&libcoap_io_process);
  sock->udp_conn = udp_new(NULL, 0, sock);
  PROCESS_CONTEXT_END(&libcoap_io_process);
  if (!sock->udp_conn) {
    coap_log_err("coap_socket_bind_udp: udp_new returned NULL\n");
    return 0;
  }
  udp_bind(sock->udp_conn, listen_addr->port);
  uip_ipaddr_copy(&bound_addr->addr, &addr->ipaddr);
  bound_addr->port = sock->udp_conn->lport;
  return 1;
}

int
coap_socket_connect_udp(coap_socket_t *sock,
                        const coap_address_t *local_if,
                        const coap_address_t *server,
                        int default_port,
                        coap_address_t *local_addr,
                        coap_address_t *remote_addr) {
  uip_ds6_addr_t *addr;

  if (local_if) {
    coap_log_warn("coap_socket_connect_udp: ignoring local_if parameter\n");
  }
  addr = uip_ds6_get_global(ADDR_PREFERRED);
  if (!addr) {
    coap_log_err("coap_socket_connect_udp: called before getting an IPv6 address\n");
    return 0;
  }
  PROCESS_CONTEXT_BEGIN(&libcoap_io_process);
  sock->udp_conn = udp_new(&server->addr, server->port ? server->port : default_port, sock);
  PROCESS_CONTEXT_END(&libcoap_io_process);
  if (!sock->udp_conn) {
    coap_log_err("coap_socket_connect_udp: udp_new returned NULL\n");
    return 0;
  }
  uip_ipaddr_copy(&local_addr->addr, &addr->ipaddr);
  local_addr->port = sock->udp_conn->lport;
  uip_ipaddr_copy(&remote_addr->addr, &server->addr);
  remote_addr->port = sock->udp_conn->rport;
  sock->flags |= COAP_SOCKET_CONNECTED;
  return 1;
}

ssize_t
coap_socket_write(coap_socket_t *sock, const uint8_t *data, size_t data_len) {
  return -1;
}

ssize_t
coap_socket_read(coap_socket_t *sock, uint8_t *data, size_t data_len) {
  return -1;
}

void
coap_socket_dgrm_close(coap_socket_t *sock) {
  uip_udp_remove(sock->udp_conn);
  sock->udp_conn = NULL;
  sock->flags = COAP_SOCKET_EMPTY;
}

/*
 * dgram
 * return +ve Number of bytes written.
 *         -1 Error error in errno).
 */
ssize_t
coap_socket_send(coap_socket_t *sock, coap_session_t *session, const uint8_t *data,
                 size_t datalen) {
  ssize_t bytes_written = 0;

  if (!coap_debug_send_packet()) {
    bytes_written = (ssize_t)datalen;
  } else {
    uip_udp_packet_sendto(sock->udp_conn, data, datalen,
                          &session->addr_info.remote.addr, session->addr_info.remote.port);
    bytes_written = datalen;
  }

  if (bytes_written < 0) {
    coap_log_crit("coap_socket_send: %s\n", coap_socket_strerror());
  }

  return bytes_written;
}

/*
 * dgram
 * return +ve Number of bytes written.
 *         -1 Error error in errno).
 *         -2 ICMP error response
 */
ssize_t
coap_socket_recv(coap_socket_t *sock, coap_packet_t *packet) {
  ssize_t len;

  assert(sock);
  assert(packet);

  if (!(sock->flags & COAP_SOCKET_CAN_READ)) {
    return -1;
  }
  /* clear has-data flag */
  sock->flags &= ~COAP_SOCKET_CAN_READ;

  uip_ipaddr_copy(&packet->addr_info.remote.addr, &UIP_IP_BUF->srcipaddr);
  packet->addr_info.remote.port = UIP_UDP_BUF->srcport;
  uip_ipaddr_copy(&packet->addr_info.local.addr, &UIP_IP_BUF->destipaddr);
  packet->addr_info.local.port = UIP_UDP_BUF->destport;

  len = uip_datalen();

  if (len > COAP_RXBUFFER_SIZE) {
    coap_log_warn("Received message does not fit within buffer\n");
    return -1;
  }
  packet->length = len;
  packet->payload = uip_appdata;

  return len;
}

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
