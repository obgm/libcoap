/*
 * Copyright (C) 2012,2014 Olaf Bergmann <bergmann@tzi.org>
 *               2014      chrysn <chrysn@fsfe.org>
 *               2022-2024 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file coap_io_lwip.c
 * @brief LwIP specific functions
 */

#include "coap3/coap_internal.h"
#include <lwip/udp.h>
#include <lwip/timeouts.h>
#include <lwip/tcpip.h>

void
coap_lwip_dump_memory_pools(coap_log_t log_level) {
#if MEMP_STATS && LWIP_STATS_DISPLAY
  int i;

  /* Save time if not needed */
  if (log_level > coap_get_log_level())
    return;

  coap_log(log_level, "*   LwIP custom memory pools information\n");
  /*
   * Make sure LwIP and libcoap have been built with the same
   * -DCOAP_CLIENT_ONLY or -DCOAP_SERVER_ONLY options for
   * MEMP_MAX to be correct.
   */
  for (i = 0; i < MEMP_MAX; i++) {
    coap_log(log_level, "*    %-17s avail %3d  in-use %3d  peak %3d failed %3d\n",
             memp_pools[i]->stats->name, memp_pools[i]->stats->avail,
             memp_pools[i]->stats->used, memp_pools[i]->stats->max,
             memp_pools[i]->stats->err);
  }
#endif /* MEMP_STATS && LWIP_STATS_DISPLAY */
}

void
coap_lwip_set_input_wait_handler(coap_context_t *context,
                                 coap_lwip_input_wait_handler_t handler,
                                 void *input_arg) {
  context->input_wait = handler;
  context->input_arg = input_arg;
}

void
coap_io_process_timeout(void *arg) {
  coap_context_t *context = (coap_context_t *)arg;
  coap_tick_t before;
  unsigned int num_sockets;
  unsigned int timeout;

  coap_lock_lock(context, return);
  coap_ticks(&before);
  timeout = coap_io_prepare_io(context, NULL, 0, &num_sockets, before);
  if (context->timer_configured) {
    sys_untimeout(coap_io_process_timeout, (void *)context);
    context->timer_configured = 0;
  }
  if (timeout == 0) {
    /* Garbage collect 1 sec hence */
    timeout = 1000;
  }
#ifdef COAP_DEBUG_WAKEUP_TIMES
  coap_log_info("****** Next wakeup msecs %u (1)\n",
                timeout);
#endif /* COAP_DEBUG_WAKEUP_TIMES */
  sys_timeout(timeout, coap_io_process_timeout, context);
  context->timer_configured = 1;
  coap_lock_unlock(context);
}

int
coap_io_process(coap_context_t *context, uint32_t timeout_ms) {
  coap_tick_t before;
  coap_tick_t now;
  unsigned int num_sockets;
  unsigned int timeout;

  coap_lock_check_locked(context);
  coap_ticks(&before);
  timeout = coap_io_prepare_io(context, NULL, 0, &num_sockets, before);
  if (timeout_ms != 0 && timeout_ms != COAP_IO_NO_WAIT &&
      timeout > timeout_ms) {
    timeout = timeout_ms;
  }

  coap_lock_invert(context,
                   LOCK_TCPIP_CORE(),
                   UNLOCK_TCPIP_CORE(); return 0);

  if (context->timer_configured) {
    sys_untimeout(coap_io_process_timeout, (void *)context);
    context->timer_configured = 0;
  }
  if (timeout == 0) {
    /* Garbage collect 1 sec hence */
    timeout = 1000;
  }
#ifdef COAP_DEBUG_WAKEUP_TIMES
  coap_log_info("****** Next wakeup msecs %u (2)\n",
                timeout);
#endif /* COAP_DEBUG_WAKEUP_TIMES */
  sys_timeout(timeout, coap_io_process_timeout, context);
  context->timer_configured = 1;

  UNLOCK_TCPIP_CORE();

  if (context->input_wait) {
    context->input_wait(context->input_arg, timeout);
  }

  coap_lock_invert(context,
                   LOCK_TCPIP_CORE(),
                   UNLOCK_TCPIP_CORE(); return 0);

  sys_check_timeouts();

  UNLOCK_TCPIP_CORE();

  coap_ticks(&now);
  return (int)(((now - before) * 1000) / COAP_TICKS_PER_SECOND);
}

/*
 * Not used for LwIP (done with coap_recvc()), but need dummy function.
 */
ssize_t
coap_socket_recv(coap_socket_t *sock, coap_packet_t *packet) {
  (void)sock;
  (void)packet;
  assert(0);
  return -1;
}

#if COAP_CLIENT_SUPPORT
/** Callback from lwIP when a package was received for a client.
 *
 * The current implementation deals this to coap_dispatch immediately, but
 * other mechanisms (as storing the package in a queue and later fetching it
 * when coap_io_do_io is called) can be envisioned.
 *
 * It handles everything coap_io_do_io does on other implementations.
 */
static void
coap_recvc(void *arg, struct udp_pcb *upcb, struct pbuf *p,
           const ip_addr_t *addr, u16_t port) {
  coap_pdu_t *pdu = NULL;
  coap_session_t *session = (coap_session_t *)arg;
  int result = -1;
  (void)upcb;
  (void)addr;
  (void)port;

  assert(session);
  LWIP_ASSERT("Proto not supported for LWIP", COAP_PROTO_NOT_RELIABLE(session->proto));

  if (p->len < 4) {
    /* Minimum size of CoAP header - ignore runt */
    return;
  }

  coap_log_debug("*  %s: lwip:  recv %4d bytes\n",
                 coap_session_str(session), p->len);
  if (session->proto == COAP_PROTO_DTLS) {
    if (session->tls) {
      result = coap_dtls_receive(session, p->payload, p->len);
      if (result < 0)
        goto error;
    }
    pbuf_free(p);
  } else {
    pdu = coap_pdu_from_pbuf(p);
    if (!pdu)
      goto error;

    if (!coap_pdu_parse(session->proto, p->payload, p->len, pdu)) {
      goto error;
    }
    coap_lock_lock(session->context, return);
    coap_dispatch(session->context, session, pdu);
    coap_lock_unlock(session->context);
  }
  coap_delete_pdu(pdu);
  return;

error:
  /*
   * https://rfc-editor.org/rfc/rfc7252#section-4.2 MUST send RST
   * https://rfc-editor.org/rfc/rfc7252#section-4.3 MAY send RST
   */
  if (session)
    coap_send_rst(session, pdu);
  coap_delete_pdu(pdu);
  return;
}
#endif /* ! COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT

static void
coap_free_packet(coap_packet_t *packet) {
  coap_free_type(COAP_PACKET, packet);
}

/** Callback from lwIP when a UDP packet was received for a server.
 *
 * The current implementation deals this to coap_dispatch immediately, but
 * other mechanisms (as storing the package in a queue and later fetching it
 * when coap_io_do_io is called) can be envisioned.
 *
 * It handles everything coap_io_do_io does on other implementations.
 */
static void
coap_udp_recvs(void *arg, struct udp_pcb *upcb, struct pbuf *p,
               const ip_addr_t *addr, u16_t port) {
  coap_endpoint_t *ep = (coap_endpoint_t *)arg;
  coap_pdu_t *pdu = NULL;
  coap_session_t *session = NULL;
  coap_tick_t now;
  coap_packet_t *packet;
  int result = -1;

  if (p->len < 4) {
    /* Minimum size of CoAP header - ignore runt */
    return;
  }

  packet = coap_malloc_type(COAP_PACKET, sizeof(coap_packet_t));

  /* this is fatal because due to the short life of the packet, never should
     there be more than one coap_packet_t required */
  LWIP_ASSERT("Insufficient coap_packet_t resources.", packet != NULL);
  /* Need to do this as there may be holes in addr_info */
  memset(&packet->addr_info, 0, sizeof(packet->addr_info));
  packet->length = p->len;
  packet->payload = p->payload;
  packet->addr_info.remote.port = port;
  packet->addr_info.remote.addr = *addr;
  packet->addr_info.local.port = upcb->local_port;
  packet->addr_info.local.addr = *ip_current_dest_addr();
  packet->ifindex = netif_get_index(ip_current_netif());

  coap_ticks(&now);

  coap_lock_lock(ep->context, return);
  session = coap_endpoint_get_session(ep, packet, now);
  if (!session)
    goto error;
  LWIP_ASSERT("Proto not supported for LWIP", COAP_PROTO_NOT_RELIABLE(session->proto));

  coap_log_debug("*  %s: lwip:  recv %4d bytes\n",
                 coap_session_str(session), p->len);

  if (session->proto == COAP_PROTO_DTLS) {
    if (session->type == COAP_SESSION_TYPE_HELLO)
      result = coap_dtls_hello(session, p->payload, p->len);
    else if (session->tls)
      result = coap_dtls_receive(session, p->payload, p->len);
    if (session->type == COAP_SESSION_TYPE_HELLO && result == 1)
      coap_session_new_dtls_session(session, now);
    pbuf_free(p);
  } else {
    pdu = coap_pdu_from_pbuf(p);
    if (!pdu)
      goto error;

    if (!coap_pdu_parse(ep->proto, p->payload, p->len, pdu)) {
      goto error;
    }
    coap_dispatch(ep->context, session, pdu);
  }

  coap_delete_pdu(pdu);
  coap_free_packet(packet);
  coap_lock_unlock(ep->context);
  return;

error:
  /*
   * https://rfc-editor.org/rfc/rfc7252#section-4.2 MUST send RST
   * https://rfc-editor.org/rfc/rfc7252#section-4.3 MAY send RST
   */
  if (session)
    coap_send_rst(session, pdu);
  coap_delete_pdu(pdu);
  coap_free_packet(packet);
  coap_lock_unlock(ep->context);
  return;
}

#endif /* ! COAP_SERVER_SUPPORT */

ssize_t
coap_socket_send_pdu(coap_socket_t *sock, coap_session_t *session,
                     coap_pdu_t *pdu) {
  /* FIXME: we can't check this here with the existing infrastructure, but we
  * should actually check that the pdu is not held by anyone but us. the
  * respective pbuf is already exclusively owned by the pdu. */
  struct pbuf *pbuf;
  int err;

  pbuf_realloc(pdu->pbuf, pdu->used_size + coap_pdu_parse_header_size(session->proto,
               pdu->pbuf->payload));

  if (coap_debug_send_packet()) {
    /* Need to take a copy as we may be re-using the origin in a retransmit */
    pbuf = pbuf_clone(PBUF_TRANSPORT, PBUF_RAM, pdu->pbuf);
    if (pbuf == NULL)
      return -1;
    err = udp_sendto(sock->udp_pcb, pbuf, &session->addr_info.remote.addr,
                     session->addr_info.remote.port);
    pbuf_free(pbuf);
    if (err < 0)
      return -1;
  }
  return pdu->used_size;
}

/*
 * dgram
 * return +ve Number of bytes written.
 *         -1 Error error in errno).
 */
ssize_t
coap_socket_send(coap_socket_t *sock, const coap_session_t *session,
                 const uint8_t *data, size_t data_len) {
  struct pbuf *pbuf;
  int err;

  if (coap_debug_send_packet()) {
    pbuf = pbuf_alloc(PBUF_TRANSPORT, data_len, PBUF_RAM);
    if (pbuf == NULL)
      return -1;
    memcpy(pbuf->payload, data, data_len);

    coap_lock_invert(session->context,
                     LOCK_TCPIP_CORE(),
                     UNLOCK_TCPIP_CORE(); return -1);

    err = udp_sendto(sock->udp_pcb, pbuf, &session->addr_info.remote.addr,
                     session->addr_info.remote.port);

    UNLOCK_TCPIP_CORE();

    pbuf_free(pbuf);
    if (err < 0)
      return -1;
  }
  return data_len;
}

#if COAP_SERVER_SUPPORT
int
coap_socket_bind_udp(coap_socket_t *sock,
                     const coap_address_t *listen_addr,
                     coap_address_t *bound_addr) {
  int err;
  coap_address_t l_listen = *listen_addr;

  sock->udp_pcb = udp_new_ip_type(IPADDR_TYPE_ANY);
  if (sock->udp_pcb == NULL)
    return 0;

#if LWIP_IPV6 && LWIP_IPV4
  if (l_listen.addr.type == IPADDR_TYPE_V6)
    l_listen.addr.type = IPADDR_TYPE_ANY;
#endif /* LWIP_IPV6 && LWIP_IPV4 */
  udp_recv(sock->udp_pcb, coap_udp_recvs, (void *)sock->endpoint);
  err = udp_bind(sock->udp_pcb, &l_listen.addr, l_listen.port);
  if (err) {
    udp_remove(sock->udp_pcb);
    sock->udp_pcb = NULL;
  }
  *bound_addr = l_listen;
  return err ? 0 : 1;
}
#endif /* COAP_SERVER_SUPPORT */

#if COAP_CLIENT_SUPPORT
int
coap_socket_connect_udp(coap_socket_t *sock,
                        const coap_address_t *local_if,
                        const coap_address_t *server,
                        int default_port,
                        coap_address_t *local_addr,
                        coap_address_t *remote_addr) {
  err_t err;
  struct udp_pcb *pcb;

  (void)local_if;
  (void)default_port;
  (void)local_addr;
  (void)remote_addr;

  coap_lock_invert(sock->session->context,
                   LOCK_TCPIP_CORE(),
                   goto err_unlock);

  pcb = udp_new();

  if (!pcb) {
    goto err_unlock;
  }

  err = udp_bind(pcb, &pcb->local_ip, pcb->local_port);
  if (err) {
    LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS,
                ("coap_socket_connect_udp: port bind failed\n"));
    goto err_udp_remove;
  }

  sock->session->addr_info.local.port = pcb->local_port;

  err = udp_connect(pcb, &server->addr, server->port);
  if (err) {
    goto err_udp_unbind;
  }

#if LWIP_IPV6 && LWIP_IPV4
  pcb->local_ip.type = pcb->remote_ip.type;
#endif /* LWIP_IPV6 && LWIP_IPV4 */

  sock->udp_pcb = pcb;

  udp_recv(sock->udp_pcb, coap_recvc, (void *)sock->session);

  UNLOCK_TCPIP_CORE();

  return 1;

err_udp_unbind:
err_udp_remove:
  udp_remove(pcb);
err_unlock:
  UNLOCK_TCPIP_CORE();
  return 0;
}
#endif /* ! COAP_CLIENT_SUPPORT */

#if ! COAP_DISABLE_TCP

#include <lwip/tcp.h>

static void
do_tcp_err(void *arg, err_t err) {
  coap_session_t *session = (coap_session_t *)arg;

  (void)err;

  coap_handle_event(session->context, COAP_EVENT_TCP_FAILED, session);
  /*
   * as per tcp_err() documentation, the corresponding pcb is already freed
   * when this callback is called.  So, stop a double free when
   * coap_session_disconnected() eventually coap_socket_close() is called.
   */
  session->sock.tcp_pcb = NULL;
  coap_session_disconnected(session, COAP_NACK_NOT_DELIVERABLE);
}

/** Callback from lwIP when a TCP packet is received.
 *
 * The current implementation invokes coap_read_session() to do the bulk of the
 * work.
 */
static err_t
coap_tcp_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
  coap_session_t *session = (coap_session_t *)arg;
  coap_socket_t *sock = &session->sock;
  coap_tick_t now;

  (void)tpcb;
  if (p == NULL) {
    /* remote host closed connection */
    tcp_arg(sock->tcp_pcb, NULL);
    tcp_recv(sock->tcp_pcb, NULL);
    tcp_close(sock->tcp_pcb);
    sock->tcp_pcb = NULL;
    coap_session_disconnected(session, COAP_NACK_NOT_DELIVERABLE);
    return ERR_OK;
  } else if (err != ERR_OK) {
    /* cleanup, for unknown reason */
    if (p != NULL) {
      pbuf_free(p);
    }
    return err;
  }

  sock->p = p;
  coap_ticks(&now);
  coap_read_session(session->context, session, now);
  return ERR_OK;
}

#if COAP_CLIENT_SUPPORT

static err_t
do_tcp_connected(void *arg, struct tcp_pcb *tpcb, err_t err) {
  coap_session_t *session = (coap_session_t *)arg;
  coap_tick_t now;

  if (err)
    return err;
  session->sock.flags |= COAP_SOCKET_CONNECTED;
  session->addr_info.local.addr = tpcb->local_ip;
  session->addr_info.local.port = tpcb->local_port;
  tcp_recv(tpcb, coap_tcp_recv);
  coap_ticks(&now);
  coap_connect_session(session, now);
  return ERR_OK;
}

int
coap_socket_connect_tcp1(coap_socket_t *sock,
                         const coap_address_t *local_if,
                         const coap_address_t *server,
                         int default_port,
                         coap_address_t *local_addr,
                         coap_address_t *remote_addr) {
  coap_address_t connect_addr;
  err_t err;

  (void)local_addr;
  (void)remote_addr;

  sock->flags &= ~(COAP_SOCKET_WANT_CONNECT | COAP_SOCKET_CONNECTED);

  sock->tcp_pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
  if (sock->tcp_pcb == NULL)
    return 0;

  tcp_arg(sock->tcp_pcb, sock->session);
  tcp_recv(sock->tcp_pcb, coap_tcp_recv);
  tcp_err(sock->tcp_pcb, do_tcp_err);
  if (local_if) {
    coap_address_t l_local_if = *local_if;
#if LWIP_IPV6 && LWIP_IPV4
    if (l_local_if.addr.type == IPADDR_TYPE_V6)
      l_local_if.addr.type = IPADDR_TYPE_ANY;
#endif /* LWIP_IPV6 && LWIP_IPV4 */
    err = tcp_bind(sock->tcp_pcb, &l_local_if.addr, l_local_if.port);
    if (err != ERR_OK) {
      tcp_arg(sock->tcp_pcb, NULL);
      tcp_recv(sock->tcp_pcb, NULL);
      tcp_close(sock->tcp_pcb);
      sock->tcp_pcb = NULL;
      return 0;
    }
  }
  coap_address_copy(&connect_addr, server);
  if (connect_addr.port == 0)
    connect_addr.port = htons(default_port);

  err = tcp_connect(sock->tcp_pcb, &connect_addr.addr, connect_addr.port,
                    do_tcp_connected);
  if (err == ERR_OK)
    sock->flags |= COAP_SOCKET_WANT_CONNECT | COAP_SOCKET_CONNECTED;
  return err ? 0 : 1;
}

int
coap_socket_connect_tcp2(coap_socket_t *sock,
                         coap_address_t *local_addr,
                         coap_address_t *remote_addr) {
  (void)sock;
  (void)local_addr;
  (void)remote_addr;

  sock->flags &= ~(COAP_SOCKET_WANT_CONNECT | COAP_SOCKET_CAN_CONNECT);
  return 1;
}
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT

static err_t
do_tcp_accept(void *arg, struct tcp_pcb *newpcb, err_t err) {
  coap_endpoint_t *endpoint = arg;
  coap_session_t *session;
  coap_tick_t now;
  err_t ret_err = ERR_OK;

  if ((err != ERR_OK) || (newpcb == NULL)) {
    return ERR_VAL;
  }
  coap_ticks(&now);

  session = coap_new_server_session(endpoint->context, endpoint, newpcb);

  if (session) {
    session->sock.tcp_pcb = newpcb;
    session->last_rx_tx = now;
    tcp_arg(newpcb, session);
    tcp_setprio(newpcb, TCP_PRIO_MIN);
    tcp_recv(newpcb, coap_tcp_recv);
    tcp_err(newpcb, do_tcp_err);
  } else {
    ret_err = ERR_MEM;
  }
  return ret_err;
}

int
coap_socket_bind_tcp(coap_socket_t *sock,
                     const coap_address_t *listen_addr,
                     coap_address_t *bound_addr) {
  int err;
  coap_address_t l_listen = *listen_addr;
  struct tcp_pcb *tcp_pcb;

  sock->tcp_pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
  if (sock->tcp_pcb == NULL)
    return 0;

#if LWIP_IPV6 && LWIP_IPV4
  if (l_listen.addr.type == IPADDR_TYPE_V6)
    l_listen.addr.type = IPADDR_TYPE_ANY;
#endif /* LWIP_IPV6 && LWIP_IPV4 */
  tcp_arg(sock->tcp_pcb, sock->endpoint);
  err = tcp_bind(sock->tcp_pcb, &l_listen.addr, l_listen.port);
  if (err != ERR_OK) {
    tcp_arg(sock->tcp_pcb, NULL);
    tcp_recv(sock->tcp_pcb, NULL);
    tcp_close(sock->tcp_pcb);
    sock->tcp_pcb = NULL;
    return 0;
  } else {
    tcp_pcb = tcp_listen(sock->tcp_pcb);
    if (tcp_pcb) {
      sock->tcp_pcb = tcp_pcb;
      tcp_accept(sock->tcp_pcb, do_tcp_accept);
    } else {
      tcp_arg(sock->tcp_pcb, NULL);
      tcp_recv(sock->tcp_pcb, NULL);
      tcp_close(sock->tcp_pcb);
      sock->tcp_pcb = NULL;
      return 0;
    }
  }
  *bound_addr = l_listen;
  return err ? 0 : 1;
}

int
coap_socket_accept_tcp(coap_socket_t *server,
                       coap_socket_t *new_client,
                       coap_address_t *local_addr,
                       coap_address_t *remote_addr,
                       void *extra) {
  struct tcp_pcb *tcp_pcb = (struct tcp_pcb *)extra;

  (void)server;

  new_client->tcp_pcb = tcp_pcb;
  local_addr->addr = tcp_pcb->local_ip;
  local_addr->port = tcp_pcb->local_port;
  remote_addr->addr = tcp_pcb->remote_ip;
  remote_addr->port = tcp_pcb->remote_port;
  return 1;
}
#endif /* COAP_SERVER_SUPPORT */

/*
 * strm
 * return +ve Number of bytes written.
 *         -1 Error error in errno).
 */
ssize_t
coap_socket_write(coap_socket_t *sock, const uint8_t *data, size_t data_len) {
  struct pbuf *pbuf;
  int err;

  pbuf = pbuf_alloc(PBUF_TRANSPORT, data_len, PBUF_RAM);
  if (pbuf == NULL)
    return -1;
  memcpy(pbuf->payload, data, data_len);

  coap_lock_invert(context,
                   LOCK_TCPIP_CORE(),
                   UNLOCK_TCPIP_CORE(); return 0);

  err = tcp_write(sock->tcp_pcb, pbuf->payload, pbuf->len, 1);

  UNLOCK_TCPIP_CORE();

  pbuf_free(pbuf);
  if (err < 0)
    return -1;
  return data_len;
}

/*
 * strm
 * return >=0 Number of bytes read.
 *         -1 Error error in errno).
 */
ssize_t
coap_socket_read(coap_socket_t *sock, uint8_t *data, size_t data_len) {
  if (sock->p) {
    if (data_len < sock->p->len) {
      uint8_t *ptr = (uint8_t *)sock->p->payload;

      /* Handle partial read of data request */
      memcpy(data, sock->p->payload, data_len);
      sock->p->payload = &ptr[data_len];
      sock->p->len -= data_len;
      return data_len;
    } else {
      data_len = sock->p->len;
      memcpy(data, sock->p->payload, sock->p->len);
      pbuf_free(sock->p);
      sock->p = NULL;
      return data_len;
    }
  }
  return 0;
}
#endif /* !COAP_DISABLE_TCP */

void
coap_socket_close(coap_socket_t *sock) {
  if (sock->udp_pcb) {
    if (sock->session) {
      coap_lock_invert(sock->session->context,
                       LOCK_TCPIP_CORE(),
                       UNLOCK_TCPIP_CORE(); return);
    } else {
      LOCK_TCPIP_CORE();
    }
    udp_remove(sock->udp_pcb);
    UNLOCK_TCPIP_CORE();
    sock->udp_pcb = NULL;
  }
#if ! COAP_DISABLE_TCP
  if (sock->tcp_pcb) {
    tcp_arg(sock->tcp_pcb, NULL);
#if COAP_SERVER_SUPPORT
    if (!sock->endpoint)
#endif /* COAP_SERVER_SUPPORT */
      tcp_recv(sock->tcp_pcb, NULL);
    if (sock->session) {
      coap_lock_invert(sock->session->context,
                       LOCK_TCPIP_CORE(),
                       UNLOCK_TCPIP_CORE(); return);
    } else {
      LOCK_TCPIP_CORE();
    }
    tcp_close(sock->tcp_pcb);
    UNLOCK_TCPIP_CORE();
    tcp_close(sock->tcp_pcb);
    sock->tcp_pcb = NULL;
  }
#endif /* !COAP_DISABLE_TCP */
  return;
}
