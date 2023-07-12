/* coap_io_contiki.c -- Network I/O functions for libcoap on Contiki-NG
 *
 * Copyright (C) 2012,2014 Olaf Bergmann <bergmann@tzi.org>
 *               2014 chrysn <chrysn@fsfe.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file coap_io_contiki.c
 * @brief Contiki-NG-specific functions
 */

#include "coap3/coap_internal.h"
#include "contiki-net.h"

PROCESS(libcoap_io_process, "libcoap I/O");
static int was_io_process_stopped;

void
coap_start_io_process(void) {
  was_io_process_stopped = 0;
  process_start(&libcoap_io_process, NULL);
}

void
coap_stop_io_process(void) {
  was_io_process_stopped = 1;
  process_poll(&libcoap_io_process);
}

static void
on_prepare_timer_expired(void *ptr) {
  coap_context_t *ctx;
  coap_tick_t now;
  coap_socket_t *sockets[1];
  unsigned int max_sockets = sizeof(sockets)/sizeof(sockets[0]);
  unsigned int num_sockets;
  unsigned timeout;

  ctx = (coap_context_t *)ptr;
  coap_ticks(&now);
  timeout = coap_io_prepare_io(ctx, sockets, max_sockets, &num_sockets, now);
  if (!timeout) {
    return;
  }
  ctimer_set(&ctx->prepare_timer,
             CLOCK_SECOND * timeout / 1000,
             on_prepare_timer_expired,
             ctx);
}

PROCESS_THREAD(libcoap_io_process, ev, data) {
  coap_socket_t *coap_socket;

  PROCESS_BEGIN();
  while (!was_io_process_stopped) {
    PROCESS_WAIT_EVENT();
    if (was_io_process_stopped) {
      break;
    }
    if (ev == tcpip_event) {
      coap_socket = (struct coap_socket_t *)data;
      if (!coap_socket) {
        coap_log_crit("libcoap_io_process: data should never be NULL\n");
        continue;
      }
      if (uip_newdata()) {
        coap_socket->flags |= COAP_SOCKET_CAN_READ;
        coap_io_process(coap_socket->context, 0);
        ctimer_stop(&coap_socket->context->prepare_timer);
        on_prepare_timer_expired(coap_socket->context);
      }
    }
  }
  PROCESS_END();
}

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
  PROCESS_CONTEXT_END();
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
  PROCESS_CONTEXT_END();
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
coap_socket_close(coap_socket_t *sock) {
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
coap_socket_send(coap_socket_t *sock, const coap_session_t *session, const uint8_t *data,
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

int
coap_io_process(coap_context_t *ctx, uint32_t timeout_ms) {
  coap_tick_t before, now;

  coap_ticks(&before);
  coap_io_do_io(ctx, before);
  coap_ticks(&now);
  return (int)(((now - before) * 1000) / COAP_TICKS_PER_SECOND);
}
