/*
 * Copyright (C) 2012,2014 Olaf Bergmann <bergmann@tzi.org>
 *               2014      chrysn <chrysn@fsfe.org>
 *               2022-2025 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file coap_dgrm_lwip.c
 * @brief LwIP Datagram (UDP) specific functions
 */

#include "coap3/coap_libcoap_build.h"

#if defined(WITH_LWIP)

#include <lwip/udp.h>
#include <lwip/timeouts.h>
#include <lwip/tcpip.h>

#if ! COAP_DISABLE_TCP
#include <lwip/tcp.h>
#endif /* !COAP_DISABLE_TCP */

#if NO_SYS == 0
extern sys_sem_t coap_io_timeout_sem;
extern uint32_t coap_lwip_in_call_back_ref;
#endif /* NO_SYS == 0 */

typedef struct {
  coap_session_t *session;
  struct udp_pcb *udp_pcb;
  struct pbuf *pbuf;
  coap_address_t addr;
} coap_lwip_udp_t;

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
 * The current implementation passes this to coap_dispatch() immediately, but
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

  assert(session);
  LWIP_ASSERT("Proto not supported for LWIP", COAP_PROTO_NOT_RELIABLE(session->proto));

  if (p->len < 4) {
    /* Minimum size of CoAP header - ignore runt */
    return;
  }
  coap_lock_lock(return);
  memcpy(&session->addr_info.remote.addr, addr, sizeof(session->addr_info.remote.addr));
  coap_address_set_port(&session->addr_info.remote, port);

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
    coap_opt_filter_t error_opts;

    pdu = coap_pdu_from_pbuf(p);
    if (!pdu)
      goto error;

    coap_option_filter_clear(&error_opts);
    if (!coap_pdu_parse2(session->proto, p->payload, p->len, pdu, &error_opts)) {
      coap_handle_event_lkd(session->context, COAP_EVENT_BAD_PACKET, session);
      coap_log_warn("discard malformed PDU\n");
      if (error_opts.mask && COAP_PDU_IS_REQUEST(pdu)) {
        coap_pdu_t *response =
            coap_new_error_response(pdu,
                                    COAP_RESPONSE_CODE(402), &error_opts);
        if (!response) {
          coap_log_warn("coap_handle_dgram: cannot create error response\n");
        } else {
          if (coap_send_internal(session, response, NULL) == COAP_INVALID_MID)
            coap_log_warn("coap_handle_dgram: error sending response\n");
        }
        coap_delete_pdu_lkd(pdu);
        coap_lock_unlock();
#if NO_SYS == 0
        sys_sem_signal(&coap_io_timeout_sem);
#endif /* NO_SYS == 0 */
        return;
      } else {
        goto error;
      }
    }
#if NO_SYS == 0
    coap_lwip_in_call_back_ref++;
#endif /* NO_SYS == 0 */
    coap_dispatch(session->context, session, pdu);
#if NO_SYS == 0
    coap_lwip_in_call_back_ref--;
#endif /* NO_SYS == 0 */
  }
#if NO_SYS == 0
  sys_sem_signal(&coap_io_timeout_sem);
#endif /* NO_SYS == 0 */
  coap_delete_pdu_lkd(pdu);
  coap_lock_unlock();
  return;

error:
  /*
   * https://rfc-editor.org/rfc/rfc7252#section-4.2 MUST send RST
   * https://rfc-editor.org/rfc/rfc7252#section-4.3 MAY send RST
   */
  if (session)
    coap_send_rst_lkd(session, pdu);
  coap_delete_pdu_lkd(pdu);
  coap_lock_unlock();
#if NO_SYS == 0
  sys_sem_signal(&coap_io_timeout_sem);
#endif /* NO_SYS == 0 */
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
 * The current implementation passes this to coap_dispatch() immediately, but
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
  coap_packet_t *packet = NULL;
  int result = -1;

  if (p->len < 4) {
    /* Minimum size of CoAP header - ignore runt */
    goto error_free_pbuf;
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

  coap_lock_lock(goto error_free_pbuf);
  session = coap_endpoint_get_session(ep, packet, now);
  if (!session)
    goto error_free_pbuf;
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
    coap_opt_filter_t error_opts;

    pdu = coap_pdu_from_pbuf(p);
    if (!pdu)
      goto error;

    coap_option_filter_clear(&error_opts);
    if (!coap_pdu_parse2(ep->proto, p->payload, p->len, pdu, &error_opts)) {
      coap_handle_event_lkd(ep->context, COAP_EVENT_BAD_PACKET, session);
      coap_log_warn("discard malformed PDU\n");
      if (error_opts.mask && COAP_PDU_IS_REQUEST(pdu)) {
        coap_pdu_t *response =
            coap_new_error_response(pdu,
                                    COAP_RESPONSE_CODE(402), &error_opts);
        if (!response) {
          coap_log_warn("coap_handle_dgram: cannot create error response\n");
        } else {
          if (coap_send_internal(session, response, NULL) == COAP_INVALID_MID)
            coap_log_warn("coap_handle_dgram: error sending response\n");
        }
        goto cleanup;
      } else {
        goto error;
      }
    }
#if NO_SYS == 0
    coap_lwip_in_call_back_ref++;
#endif /* NO_SYS == 0 */
    coap_dispatch(ep->context, session, pdu);
#if NO_SYS == 0
    coap_lwip_in_call_back_ref--;
#endif /* NO_SYS == 0 */
  }

  coap_delete_pdu_lkd(pdu);
  coap_free_packet(packet);
  coap_lock_unlock();
#if NO_SYS == 0
  sys_sem_signal(&coap_io_timeout_sem);
#endif /* NO_SYS == 0 */
  return;

error_free_pbuf:
  pbuf_free(p);

error:
  /*
   * https://rfc-editor.org/rfc/rfc7252#section-4.2 MUST send RST
   * https://rfc-editor.org/rfc/rfc7252#section-4.3 MAY send RST
   */
  if (session && pdu)
    coap_send_rst_lkd(session, pdu);
cleanup:
  coap_delete_pdu_lkd(pdu);
  coap_free_packet(packet);
  coap_lock_unlock();
#if NO_SYS == 0
  sys_sem_signal(&coap_io_timeout_sem);
#endif /* NO_SYS == 0 */
  return;
}

#endif /* ! COAP_SERVER_SUPPORT */

#if NO_SYS == 0
static void
coap_lwip_udp_sendto(void *ctx) {
  coap_lwip_udp_t *cb_ctx = (coap_lwip_udp_t *)ctx;
  int err;

  if (cb_ctx) {
    err = udp_sendto(cb_ctx->udp_pcb, cb_ctx->pbuf, &cb_ctx->addr.addr,
                     cb_ctx->addr.port);
    if (err < 0) {
      if (err == ERR_RTE) {
        coap_log_warn("** %s: udp_sendto: Packet not routable\n",
                      coap_session_str(cb_ctx->session));
      } else {
        coap_log_warn("** %s: udp_sendto: error %d\n",
                      coap_session_str(cb_ctx->session), err);
      }
    }
    pbuf_free(cb_ctx->pbuf);
    coap_free_type(COAP_STRING, cb_ctx);
  }
}
#endif /* NO_SYS == 0 */

/*
 * dgram
 * return +ve Number of bytes written.
 *         -1 Error error in errno).
 */
ssize_t
coap_socket_send(coap_socket_t *sock, coap_session_t *session,
                 const uint8_t *data, size_t data_len) {
  struct pbuf *pbuf;
  int err;

  if (coap_debug_send_packet()) {
    pbuf = pbuf_alloc(PBUF_TRANSPORT, data_len, PBUF_RAM);
    if (pbuf == NULL) {
      errno = ENOMEM;
      return -1;
    }
    memcpy(pbuf->payload, data, data_len);

#if NO_SYS == 0
    if (coap_lwip_in_call_back_ref == 0) {
      coap_lwip_udp_t *cb_ctx = coap_malloc_type(COAP_STRING, sizeof(coap_lwip_udp_t));

      if (!cb_ctx) {
        coap_log_warn("** %s: coap_socket_send: error\n",
                      coap_session_str(session));
        pbuf_free(pbuf);
        errno = ENOMEM;
        return -1;
      }
      cb_ctx->session = session;
      cb_ctx->pbuf = pbuf;
      cb_ctx->udp_pcb = sock->udp_pcb;
      cb_ctx->addr = session->addr_info.remote;
      err = tcpip_try_callback(coap_lwip_udp_sendto, cb_ctx);

      if (err < 0) {
        coap_log_warn("** %s: tcpip_try_callback: error %d\n",
                      coap_session_str(session), err);
        errno = EAGAIN;
        return -1;
      }
    } else {
#endif /* NO_SYS == 0 */
      err = udp_sendto(sock->udp_pcb, pbuf, &session->addr_info.remote.addr,
                       session->addr_info.remote.port);
      pbuf_free(pbuf);
      if (err < 0) {
        if (err == ERR_RTE) {
          coap_log_warn("** %s: udp_sendto: Packet not routable\n",
                        coap_session_str(session));
        } else {
          coap_log_warn("** %s: udp_sendto: error %d\n",
                        coap_session_str(session), err);
        }
        return -1;
      }
#if NO_SYS == 0
    }
#endif /* NO_SYS == 0 */
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
  int is_mcast = coap_is_mcast(server);
  coap_address_t connect_addr;

  coap_address_copy(&connect_addr, server);
  if (connect_addr.port == 0)
    connect_addr.port = default_port;

  coap_lock_invert(LOCK_TCPIP_CORE(),
                   goto err_unlock);

  pcb = udp_new();

  if (!pcb) {
    goto err_unlock;
  }

  if (local_if) {
    pcb->local_ip = local_if->addr;
    pcb->local_port = local_if->port;
  }
  err = udp_bind(pcb, &pcb->local_ip, pcb->local_port);
  if (err) {
    LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS,
                ("coap_socket_connect_udp: port bind failed\n"));
    goto err_udp_remove;
  }

  if (local_addr) {
    local_addr->addr = pcb->local_ip;
    local_addr->port = pcb->local_port;
  }
  sock->session->addr_info.local.port = pcb->local_port;

  if (remote_addr) {
    coap_address_copy(remote_addr, &connect_addr);
  }

  if (is_mcast) {
    coap_address_copy(&sock->mcast_addr, &connect_addr);
    sock->flags |= COAP_SOCKET_MULTICAST;
  } else {
    err = udp_connect(pcb, &connect_addr.addr, connect_addr.port);
    if (err) {
      goto err_udp_unbind;
    }
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

#if NO_SYS == 0
static void
coap_lwip_udp_remove(void *ctx) {
  struct udp_pcb *udp_pcb = (struct udp_pcb *)ctx;

  if (udp_pcb) {
    udp_remove(udp_pcb);
  }
}
#endif /* NO_SYS == 0 */

void
coap_socket_dgrm_close(coap_socket_t *sock) {
  if (!(sock->flags & COAP_SOCKET_SLAVE)) {
    struct udp_pcb *udp_pcb = sock->udp_pcb;

    sock->udp_pcb = NULL;
    if (udp_pcb) {
#if NO_SYS == 0
      err_t err;
      if (coap_lwip_in_call_back_ref == 0) {
        err = tcpip_try_callback(coap_lwip_udp_remove, udp_pcb);

        if (err < 0) {
          coap_log_warn("** %s: tcpip_try_callback: error %d\n",
                        sock->session ? coap_session_str(sock->session) : "", err);
          errno = EAGAIN;
          return;
        }
      } else {
#endif /* NO_SYS == 0 */
        udp_remove(udp_pcb);
#if NO_SYS == 0
      }
#endif /* NO_SYS == 0 */
    }
    sock->flags = COAP_SOCKET_EMPTY;
  }
  return;
}

#else /* ! WITH_LWIP */

#ifdef __clang__
/* Make compilers happy that do not like empty modules. As this function is
 * never used, we ignore -Wunused-function at the end of compiling this file
 */
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
static inline void
dummy(void) {
}

#endif /* ! WITH_LWIP */
