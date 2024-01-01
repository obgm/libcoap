/* coap_io_contiki.c -- Network I/O functions for libcoap on Contiki-NG
 *
 * Copyright (C) 2012,2014 Olaf Bergmann <bergmann@tzi.org>
 *               2014      chrysn <chrysn@fsfe.org>
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

static void prepare_io(coap_context_t *ctx);
PROCESS(libcoap_io_process, "libcoap I/O");

void
coap_start_io_process(void) {
  process_start(&libcoap_io_process, NULL);
}

void
coap_stop_io_process(void) {
  process_exit(&libcoap_io_process);
}

static void
on_io_timer_expired(void *ptr) {
  PROCESS_CONTEXT_BEGIN(&libcoap_io_process);
  prepare_io((coap_context_t *)ptr);
  PROCESS_CONTEXT_END(&libcoap_io_process);
}

void
coap_update_io_timer(coap_context_t *ctx, coap_tick_t delay) {
  if (!ctimer_expired(&ctx->io_timer)) {
    ctimer_stop(&ctx->io_timer);
  }
  if (!delay) {
    process_post(&libcoap_io_process, PROCESS_EVENT_POLL, ctx);
  } else {
    ctimer_set(&ctx->io_timer,
               CLOCK_SECOND * delay / 1000,
               on_io_timer_expired,
               ctx);
  }
}

static void
prepare_io(coap_context_t *ctx) {
  coap_tick_t now;
  coap_socket_t *sockets[1];
  static const unsigned int max_sockets = sizeof(sockets)/sizeof(sockets[0]);
  unsigned int num_sockets;
  unsigned next_io;

  coap_ticks(&now);
  next_io = coap_io_prepare_io(ctx, sockets, max_sockets, &num_sockets, now);
  if (next_io) {
    coap_update_io_timer(ctx, next_io);
  }
}

PROCESS_THREAD(libcoap_io_process, ev, data) {
  PROCESS_EXITHANDLER(goto exit);
  PROCESS_BEGIN();

  while (1) {
    PROCESS_WAIT_EVENT();
    if (ev == tcpip_event) {
      coap_socket_t *coap_socket = (coap_socket_t *)data;
      if (!coap_socket) {
        coap_log_crit("libcoap_io_process: coap_socket should never be NULL\n");
        continue;
      }
      if (uip_newdata()) {
        coap_tick_t now;

        coap_socket->flags |= COAP_SOCKET_CAN_READ;
        coap_ticks(&now);
        coap_io_do_io(coap_socket->context, now);
      }
    }
    if (ev == PROCESS_EVENT_POLL) {
      coap_context_t *ctx = (coap_context_t *)data;
      if (!ctx) {
        coap_log_crit("libcoap_io_process: ctx should never be NULL\n");
        continue;
      }
      prepare_io(ctx);
    }
  }
exit:
  coap_log_info("libcoap_io_process: stopping\n");
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

  coap_lock_check_locked(ctx);
  if (timeout_ms != COAP_IO_NO_WAIT) {
    coap_log_err("coap_io_process must be called with COAP_IO_NO_WAIT\n");
    return -1;
  }

  coap_ticks(&before);
  PROCESS_CONTEXT_BEGIN(&libcoap_io_process);
  prepare_io(ctx);
  coap_io_do_io(ctx, before);
  PROCESS_CONTEXT_END(&libcoap_io_process);
  coap_ticks(&now);
  return (int)(((now - before) * 1000) / COAP_TICKS_PER_SECOND);
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

#endif /* ! COAP_DISABLE_TCP */
