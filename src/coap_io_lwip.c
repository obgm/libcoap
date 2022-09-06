/*
 * Copyright (C) 2012,2014 Olaf Bergmann <bergmann@tzi.org>
 *               2014 chrysn <chrysn@fsfe.org>
 *               2022 Jon Shallow <supjps-libcoap@jpshallow.com>
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
  coap_context_t *context = (coap_context_t*)arg;
  coap_tick_t before;
  unsigned int num_sockets;
  unsigned int timeout;

  coap_ticks(&before);
  timeout = coap_io_prepare_io(context, NULL, 0, &num_sockets, before);
  if (context->timer_configured) {
    sys_untimeout(coap_io_process_timeout, (void*)context);
    context->timer_configured = 0;
  }
  if (timeout == 0) {
    /* Garbage collect 1 sec hence */
    timeout = 1000;
  }
#ifdef COAP_DEBUG_WAKEUP_TIMES
  coap_log(LOG_INFO, "****** Next wakeup msecs %u (1)\n",
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
  if (context->timer_configured) {
    sys_untimeout(coap_io_process_timeout, (void*)context);
    context->timer_configured = 0;
  }
  if (timeout == 0) {
    /* Garbage collect 1 sec hence */
    timeout = 1000;
  }
#ifdef COAP_DEBUG_WAKEUP_TIMES
  coap_log(LOG_INFO, "****** Next wakeup msecs %u (2)\n",
           timeout);
#endif /* COAP_DEBUG_WAKEUP_TIMES */
  if (context->input_wait) {
    context->input_wait(context->input_arg, timeout);
  }
  context->timer_configured = 1;
  sys_check_timeouts();
  coap_ticks(&now);
  return (int)(((now - before) * 1000) / COAP_TICKS_PER_SECOND);
}

#if 0
void coap_packet_copy_source(coap_packet_t *packet, coap_address_t *target)
{
        target->port = packet->srcport;
        memcpy(&target->addr, ip_current_src_addr(), sizeof(ip_addr_t));
}
#endif
void coap_packet_get_memmapped(coap_packet_t *packet, unsigned char **address, size_t *length)
{
        LWIP_ASSERT("Can only deal with contiguous PBUFs to read the initial details", packet->pbuf->tot_len == packet->pbuf->len);
        *address = packet->pbuf->payload;
        *length = packet->pbuf->tot_len;
}
void coap_free_packet(coap_packet_t *packet)
{
        if (packet->pbuf)
                pbuf_free(packet->pbuf);
        coap_free_type(COAP_PACKET, packet);
}

struct pbuf *coap_packet_extract_pbuf(coap_packet_t *packet)
{
        struct pbuf *ret = packet->pbuf;
        packet->pbuf = NULL;
        return ret;
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
  coap_session_t *session = (coap_session_t*)arg;
  coap_packet_t *packet;

  assert(session);

  if (p->len < 4) {
    /* Minimum size of CoAP header - ignore runt */
    return;
  }

  packet = coap_malloc_type(COAP_PACKET, sizeof(coap_packet_t));

  /* this is fatal because due to the short life of the packet, never should there be more than one coap_packet_t required */
  LWIP_ASSERT("Insufficient coap_packet_t resources.", packet != NULL);
  packet->pbuf = p;
  /* Need to do this as there may be holes in addr_info */
  memset(&packet->addr_info, 0, sizeof(packet->addr_info));
  packet->addr_info.remote.port = port;
  packet->addr_info.remote.addr = *addr;
  packet->addr_info.local.port = upcb->local_port;
  packet->addr_info.local.addr = *ip_current_dest_addr();
  packet->ifindex = netif_get_index(ip_current_netif());

  pdu = coap_pdu_from_pbuf(p);
  if (!pdu)
    goto error;

  if (!coap_pdu_parse(session->proto, p->payload, p->len, pdu)) {
    goto error;
  }

  LWIP_ASSERT("Proto not supported for LWIP", COAP_PROTO_NOT_RELIABLE(session->proto));
  coap_dispatch(session->context, session, pdu);

  coap_delete_pdu(pdu);
  packet->pbuf = NULL;
  coap_free_packet(packet);
  return;

error:
  /*
   * https://tools.ietf.org/html/rfc7252#section-4.2 MUST send RST
   * https://tools.ietf.org/html/rfc7252#section-4.3 MAY send RST
   */
  if (session)
    coap_send_rst(session, pdu);
  coap_delete_pdu(pdu);
  if (packet) {
    packet->pbuf = NULL;
    coap_free_packet(packet);
  }
  return;
}
#endif /* ! COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT
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
  coap_endpoint_t *ep = (coap_endpoint_t*)arg;
  coap_pdu_t *pdu = NULL;
  coap_session_t *session = NULL;
  coap_tick_t now;
  coap_packet_t *packet;

  if (p->len < 4) {
    /* Minimum size of CoAP header - ignore runt */
    return;
  }

  packet = coap_malloc_type(COAP_PACKET, sizeof(coap_packet_t));

  /* this is fatal because due to the short life of the packet, never should there be more than one coap_packet_t required */
  LWIP_ASSERT("Insufficient coap_packet_t resources.", packet != NULL);
  packet->pbuf = p;
  /* Need to do this as there may be holes in addr_info */
  memset(&packet->addr_info, 0, sizeof(packet->addr_info));
  packet->addr_info.remote.port = port;
  packet->addr_info.remote.addr = *addr;
  packet->addr_info.local.port = upcb->local_port;
  packet->addr_info.local.addr = *ip_current_dest_addr();
  packet->ifindex = netif_get_index(ip_current_netif());

  pdu = coap_pdu_from_pbuf(p);
  if (!pdu)
    goto error;

  if (!coap_pdu_parse(ep->proto, p->payload, p->len, pdu)) {
    goto error;
  }

  coap_ticks(&now);
  if ((upcb->local_port == COAP_DEFAULT_PORT) ||
      (upcb->local_port == COAPS_DEFAULT_PORT)) {
      /* packet for local server */
    session = coap_endpoint_get_session(ep, packet, now);
  } else {
    session = coap_session_get_by_peer(ep->context, &packet->addr_info.remote,
                                       packet->ifindex);
  }

  if (!session)
    goto error;
  LWIP_ASSERT("Proto not supported for LWIP", COAP_PROTO_NOT_RELIABLE(session->proto));
  coap_dispatch(ep->context, session, pdu);

  coap_delete_pdu(pdu);
  packet->pbuf = NULL;
  coap_free_packet(packet);
  return;

error:
  /*
   * https://tools.ietf.org/html/rfc7252#section-4.2 MUST send RST
   * https://tools.ietf.org/html/rfc7252#section-4.3 MAY send RST
   */
  if (session)
    coap_send_rst(session, pdu);
  coap_delete_pdu(pdu);
  if (packet) {
    packet->pbuf = NULL;
    coap_free_packet(packet);
  }
  return;
}

coap_endpoint_t *
coap_new_endpoint(coap_context_t *context, const coap_address_t *addr, coap_proto_t proto) {
        coap_endpoint_t *result;
        err_t err;

        LWIP_ASSERT("Proto not supported for LWIP endpoints", proto == COAP_PROTO_UDP);

        result = coap_malloc_type(COAP_ENDPOINT, sizeof(coap_endpoint_t));
        if (!result) return NULL;

        result->sock.pcb = udp_new_ip_type(IPADDR_TYPE_ANY);
        if (result->sock.pcb == NULL) goto error;

        udp_recv(result->sock.pcb, coap_recvs, (void*)result);
        err = udp_bind(result->sock.pcb, &addr->addr, addr->port);
        if (err) {
                udp_remove(result->sock.pcb);
                goto error;
        }

        result->default_mtu = COAP_DEFAULT_MTU;
        result->context = context;
        result->proto = proto;

        return result;

error:
        coap_free_type(COAP_ENDPOINT, result);
        return NULL;
}

void coap_free_endpoint(coap_endpoint_t *ep)
{
        udp_remove(ep->sock.pcb);
        coap_free_type(COAP_ENDPOINT, ep);
}
#endif /* ! COAP_SERVER_SUPPORT */

ssize_t
coap_socket_send_pdu(coap_socket_t *sock, coap_session_t *session,
                     coap_pdu_t *pdu) {
  /* FIXME: we can't check this here with the existing infrastructure, but we
  * should actually check that the pdu is not held by anyone but us. the
  * respective pbuf is already exclusively owned by the pdu. */
  struct pbuf *pbuf;

  pbuf_realloc(pdu->pbuf, pdu->used_size + coap_pdu_parse_header_size(session->proto, pdu->pbuf->payload));

  if (coap_debug_send_packet()) {
    /* Need to take a copy as we may be re-using the origin in a retransmit */
    pbuf = pbuf_clone(PBUF_TRANSPORT, PBUF_RAM, pdu->pbuf);
    if (pbuf == NULL)
      return -1;
    udp_sendto(sock->pcb, pbuf, &session->addr_info.remote.addr,
      session->addr_info.remote.port);

    pbuf_free(pbuf);
  }
  return pdu->used_size;
}

ssize_t
coap_socket_send(coap_socket_t *sock, coap_session_t *session,
  const uint8_t *data, size_t data_len ) {
  /* Not implemented, use coap_socket_send_pdu instead */
  return -1;
}

int
coap_socket_bind_udp(coap_socket_t *sock,
  const coap_address_t *listen_addr,
  coap_address_t *bound_addr) {
  return 0;
}

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

  pcb = udp_new();

  if (!pcb) {
     return 0;
  }

  err = udp_bind(pcb, &pcb->local_ip, pcb->local_port);
  if (err) {
    LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS,
                ("coap_socket_connect_udp: port bind failed\n"));
    return 0;
  }

  sock->session->addr_info.local.port = pcb->local_port;

  err = udp_connect(pcb, &server->addr, server->port);
  if (err) {
    return 0;
  }

  sock->pcb = pcb;

  udp_recv(sock->pcb, coap_recvc, (void*)sock->session);

  return 1;
}
#endif /* ! COAP_CLIENT_SUPPORT */

int
coap_socket_connect_tcp1(coap_socket_t *sock,
                         const coap_address_t *local_if,
                         const coap_address_t *server,
                         int default_port,
                         coap_address_t *local_addr,
                         coap_address_t *remote_addr) {
  return 0;
}

int
coap_socket_connect_tcp2(coap_socket_t *sock,
                         coap_address_t *local_addr,
                         coap_address_t *remote_addr) {
  return 0;
}

int
coap_socket_bind_tcp(coap_socket_t *sock,
                     const coap_address_t *listen_addr,
                     coap_address_t *bound_addr) {
  return 0;
}

int
coap_socket_accept_tcp(coap_socket_t *server,
                        coap_socket_t *new_client,
                        coap_address_t *local_addr,
                        coap_address_t *remote_addr) {
  return 0;
}

ssize_t
coap_socket_write(coap_socket_t *sock, const uint8_t *data, size_t data_len) {
  return -1;
}

ssize_t
coap_socket_read(coap_socket_t *sock, uint8_t *data, size_t data_len) {
  return -1;
}

void coap_socket_close(coap_socket_t *sock) {
  if (sock->pcb){
    udp_remove(sock->pcb);
  }
  sock->pcb = NULL;
  return;
}
