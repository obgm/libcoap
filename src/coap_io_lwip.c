/*
 * Copyright (C) 2012,2014 Olaf Bergmann <bergmann@tzi.org>
 *               2014 chrysn <chrysn@fsfe.org>
 *               2022-2023 Jon Shallow <supjps-libcoap@jpshallow.com>
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
}

int
coap_io_process(coap_context_t *context, uint32_t timeout_ms) {
  coap_tick_t before;
  coap_tick_t now;
  unsigned int num_sockets;
  unsigned int timeout;

  coap_ticks(&before);
  timeout = coap_io_prepare_io(context, NULL, 0, &num_sockets, before);
  if (timeout_ms != 0 && timeout_ms != COAP_IO_NO_WAIT &&
      timeout > timeout_ms) {
    timeout = timeout_ms;
  }

  LOCK_TCPIP_CORE();

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

  LOCK_TCPIP_CORE();

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
    coap_dispatch(session->context, session, pdu);
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

/** Callback from lwIP when a package was received for a server.
 *
 * The current implementation deals this to coap_dispatch immediately, but
 * other mechanisms (as storing the package in a queue and later fetching it
 * when coap_io_do_io is called) can be envisioned.
 *
 * It handles everything coap_io_do_io does on other implementations.
 */
static void
coap_recvs(void *arg, struct udp_pcb *upcb, struct pbuf *p,
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
    err = udp_sendto(sock->pcb, pbuf, &session->addr_info.remote.addr,
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

    LOCK_TCPIP_CORE();

    err = udp_sendto(sock->pcb, pbuf, &session->addr_info.remote.addr,
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

  sock->pcb = udp_new_ip_type(IPADDR_TYPE_ANY);
  if (sock->pcb == NULL)
    return 0;

#if LWIP_IPV6 && LWIP_IPV4
  if (l_listen.addr.type == IPADDR_TYPE_V6)
    l_listen.addr.type = IPADDR_TYPE_ANY;
#endif /* LWIP_IPV6 && LWIP_IPV4 */
  udp_recv(sock->pcb, coap_recvs, (void *)sock->endpoint);
  err = udp_bind(sock->pcb, &l_listen.addr, l_listen.port);
  if (err) {
    udp_remove(sock->pcb);
    sock->pcb = NULL;
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

  LOCK_TCPIP_CORE();

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

  sock->pcb = pcb;

  udp_recv(sock->pcb, coap_recvc, (void *)sock->session);

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
  return 0;
}

int
coap_socket_connect_tcp2(coap_socket_t *sock,
                         coap_address_t *local_addr,
                         coap_address_t *remote_addr) {
  (void)sock;
  (void)local_addr;
  (void)remote_addr;
  return 0;
}

int
coap_socket_bind_tcp(coap_socket_t *sock,
                     const coap_address_t *listen_addr,
                     coap_address_t *bound_addr) {
  (void)sock;
  (void)listen_addr;
  (void)bound_addr;
  return 0;
}

int
coap_socket_accept_tcp(coap_socket_t *server,
                       coap_socket_t *new_client,
                       coap_address_t *local_addr,
                       coap_address_t *remote_addr) {
  (void)server;
  (void)new_client;
  (void)local_addr;
  (void)remote_addr;
  return 0;
}
#endif /* !COAP_DISABLE_TCP */

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
coap_socket_close(coap_socket_t *sock) {
  if (sock->pcb) {
    LOCK_TCPIP_CORE();
    udp_remove(sock->pcb);
    UNLOCK_TCPIP_CORE();
  }
  sock->pcb = NULL;
  return;
}
