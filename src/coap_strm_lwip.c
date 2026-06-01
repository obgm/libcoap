/*
 * Copyright (C) 2012,2014 Olaf Bergmann <bergmann@tzi.org>
 *               2014      chrysn <chrysn@fsfe.org>
 *               2022-2026 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file coap_strm_lwip.c
 * @brief LwIP Stream (TCP) specific functions
 */

#include "coap3/coap_libcoap_build.h"

#if defined(WITH_LWIP)

#include <lwip/timeouts.h>
#include <lwip/tcpip.h>

int
coap_tcp_is_supported(void) {
  return !COAP_DISABLE_TCP;
}

#if ! COAP_DISABLE_TCP

#include <lwip/tcp.h>

#if NO_SYS == 0
extern uint32_t coap_lwip_in_call_back_ref;
#endif /* NO_SYS == 0 */

typedef struct {
  coap_session_t *session;
  struct tcp_pcb *tcp_pcb;
  struct pbuf *pbuf;
} coap_lwip_tcp_t;


static void
do_tcp_err(void *arg, err_t err) {
  coap_session_t *session = (coap_session_t *)arg;

  (void)err;

  if (!session)
    return;

  coap_lock_lock(return);
#if NO_SYS == 0
  coap_lwip_in_call_back_ref++;
#endif /* NO_SYS == 0 */
  coap_handle_event_lkd(session->context, COAP_EVENT_TCP_FAILED, session);
  /*
   * as per tcp_err() documentation, the corresponding pcb is already freed
   * when this callback is called.  So, stop a double free when
   * coap_session_disconnected_lkd() eventually calls coap_socket_close().
   */
  session->sock.tcp_pcb = NULL;
  coap_session_disconnected_lkd(session, COAP_NACK_NOT_DELIVERABLE);
#if NO_SYS == 0
  coap_lwip_in_call_back_ref--;
#endif /* NO_SYS == 0 */
  coap_lock_unlock();
#if NO_SYS == 0
  sys_sem_signal(&session->context->coap_io_timeout_sem);
#endif /* NO_SYS == 0 */
}

/** Callback from lwIP when a TCP packet is received.
 *
 * The current implementation invokes coap_read_session() to do the bulk of the
 * work.
 */
static err_t
coap_tcp_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
  coap_session_t *session = (coap_session_t *)arg;
  coap_socket_t *sock = session ? &session->sock : NULL;
  coap_tick_t now;

  (void)tpcb;
  if (!session)
    return ERR_ARG;

  if (p == NULL) {
    /* remote host closed connection */
    tcp_close(sock->tcp_pcb);
    tcp_arg(sock->tcp_pcb, NULL);
    tcp_recv(sock->tcp_pcb, NULL);
    sock->tcp_pcb = NULL;
    coap_lock_lock(return ERR_ARG);
    coap_session_disconnected_lkd(session, COAP_NACK_NOT_DELIVERABLE);
    coap_lock_unlock();
#if NO_SYS == 0
    sys_sem_signal(&session->context->coap_io_timeout_sem);
#endif /* NO_SYS == 0 */
    return ERR_OK;
  } else if (err != ERR_OK) {
    /* cleanup, for unknown reason */
    if (p != NULL) {
      pbuf_free(p);
    }
    tcp_recved(sock->tcp_pcb, p->tot_len);
#if NO_SYS == 0
    sys_sem_signal(&session->context->coap_io_timeout_sem);
#endif /* NO_SYS == 0 */
    return err;
  }

  sock->p = p;
  coap_lock_lock(return ERR_ARG);
  coap_ticks(&now);
#if NO_SYS == 0
  coap_lwip_in_call_back_ref++;
#endif /* NO_SYS == 0 */
  coap_read_session(session->context, session, now);
#if NO_SYS == 0
  coap_lwip_in_call_back_ref--;
#endif /* NO_SYS == 0 */
  coap_lock_unlock();
#if NO_SYS == 0
  sys_sem_signal(&session->context->coap_io_timeout_sem);
#endif /* NO_SYS == 0 */
  return ERR_OK;
}

#if COAP_CLIENT_SUPPORT

static err_t
do_tcp_connected(void *arg, struct tcp_pcb *tpcb, err_t err) {
  coap_session_t *session = (coap_session_t *)arg;
  coap_tick_t now;

  if (err)
    return err;
  coap_lock_lock(return ERR_ARG);
#if NO_SYS == 0
  coap_lwip_in_call_back_ref++;
#endif /* NO_SYS == 0 */
  session->sock.flags |= COAP_SOCKET_CONNECTED;
  session->addr_info.local.addr = tpcb->local_ip;
  session->addr_info.local.port = tpcb->local_port;
  tcp_recv(tpcb, coap_tcp_recv);
  coap_ticks(&now);
  coap_connect_session(session, now);
#if NO_SYS == 0
  coap_lwip_in_call_back_ref--;
#endif /* NO_SYS == 0 */
  coap_lock_unlock();
#if NO_SYS == 0
  sys_sem_signal(&session->context->coap_io_timeout_sem);
#endif /* NO_SYS == 0 */
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

  coap_lock_invert(LOCK_TCPIP_CORE(),
                   goto err_unlock);

  sock->tcp_pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
  if (sock->tcp_pcb == NULL) {
    goto err_unlock;
  }

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
      goto err_unlock;
    }
  }
  coap_address_copy(&connect_addr, server);
  if (connect_addr.port == 0)
    connect_addr.port = htons(default_port);

  err = tcp_connect(sock->tcp_pcb, &connect_addr.addr, connect_addr.port,
                    do_tcp_connected);
  if (err == ERR_OK)
    sock->flags |= COAP_SOCKET_WANT_CONNECT | COAP_SOCKET_CONNECTED;
  UNLOCK_TCPIP_CORE();
  return err ? 0 : 1;

err_unlock:
  UNLOCK_TCPIP_CORE();
  return 0;
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

  coap_lock_lock(return ERR_MEM);
#if NO_SYS == 0
  coap_lwip_in_call_back_ref++;
#endif /* NO_SYS == 0 */
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
#if NO_SYS == 0
  coap_lwip_in_call_back_ref--;
#endif /* NO_SYS == 0 */
  coap_lock_unlock();
#if NO_SYS == 0
  sys_sem_signal(&session->context->coap_io_timeout_sem);
#endif /* NO_SYS == 0 */
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

#if NO_SYS == 0
static void
coap_lwip_tcp_write(void *ctx) {
  coap_lwip_tcp_t *cb_ctx = (coap_lwip_tcp_t *)ctx;
  int err;

  if (cb_ctx && cb_ctx->pbuf) {
    err = tcp_write(cb_ctx->tcp_pcb, cb_ctx->pbuf->payload, cb_ctx->pbuf->len, 1);
    if (err < 0) {
      coap_log_warn("** %s: tcp_write: error %d\n",
                    coap_session_str(cb_ctx->session), err);
    }
    pbuf_free(cb_ctx->pbuf);
    coap_free_type(COAP_STRING, cb_ctx);
    sys_sem_signal(&cb_ctx->session->context->coap_io_timeout_sem);
  }
}
#endif /* NO_SYS == 0 */

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

#if NO_SYS == 0
  if (coap_lwip_in_call_back_ref == 0) {
    coap_lwip_tcp_t *cb_ctx = coap_malloc_type(COAP_STRING, sizeof(coap_lwip_tcp_t));

    if (!cb_ctx) {
      coap_log_warn("** %s: coap_socket_write: error\n",
                    coap_session_str(sock->session));
      pbuf_free(pbuf);
      errno = ENOMEM;
      return -1;
    }
    cb_ctx->session = sock->session;
    cb_ctx->pbuf = pbuf;
    cb_ctx->tcp_pcb = sock->tcp_pcb;
    err = tcpip_try_callback(coap_lwip_tcp_write, cb_ctx);

    if (err < 0) {
      coap_log_warn("** %s: tcpip_try_callback: error %d\n",
                    coap_session_str(sock->session), err);
      errno = EAGAIN;
      return -1;
    }
  } else {
#endif /* NO_SYS == 0 */
    err = tcp_write(sock->tcp_pcb, pbuf->payload, pbuf->len, 1);

    pbuf_free(pbuf);
    if (err < 0) {
      coap_log_warn("** %s: tcp_write: error %d\n",
                    coap_session_str(sock->session), err);
      return -1;
    }
#if NO_SYS == 0
  }
#endif /* NO_SYS == 0 */
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
      tcp_recved(sock->tcp_pcb, data_len);
      return data_len;
    } else {
      data_len = sock->p->len;
      memcpy(data, sock->p->payload, sock->p->len);
      pbuf_free(sock->p);
      sock->p = NULL;
      tcp_recved(sock->tcp_pcb, data_len);
      return data_len;
    }
  }
  return 0;
}

#if NO_SYS == 0
static void
coap_lwip_tcp_close(void *ctx) {
  struct tcp_pcb *tcp_pcb = (struct tcp_pcb *)ctx;

  if (tcp_pcb) {
    tcp_err(tcp_pcb, NULL);
    tcp_arg(tcp_pcb, NULL);
    tcp_recv(tcp_pcb, NULL);
    tcp_close(tcp_pcb);
  }
}
#if COAP_SERVER_SUPPORT
static void
coap_lwip_endpoint_tcp_close(void *ctx) {
  struct tcp_pcb *tcp_pcb = (struct tcp_pcb *)ctx;

  if (tcp_pcb) {
    tcp_accept(tcp_pcb, NULL);
    tcp_err(tcp_pcb, NULL);
    tcp_arg(tcp_pcb, NULL);
    tcp_recv(tcp_pcb, NULL);
    tcp_close(tcp_pcb);
  }
}
#endif /* COAP_SERVER_SUPPORT */
#endif /* NO_SYS == 0 */

void
coap_socket_strm_close(coap_socket_t *sock) {
  struct tcp_pcb *tcp_pcb = sock->tcp_pcb;

  sock->tcp_pcb = NULL;
  if (tcp_pcb) {
#if NO_SYS == 0
    err_t err;

    if (coap_lwip_in_call_back_ref == 0) {
#if COAP_SERVER_SUPPORT
      if (sock->endpoint)
        err = tcpip_try_callback(coap_lwip_endpoint_tcp_close, tcp_pcb);
      else
#endif /* COAP_SERVER_SUPPORT */
        err = tcpip_try_callback(coap_lwip_tcp_close, tcp_pcb);
      if (err < 0) {
        coap_log_warn("** %s: tcpip_try_callback: error %d\n",
                      sock->session ? coap_session_str(sock->session) : "", err);
        errno = EAGAIN;
        return;
      }
    } else {
#endif /* NO_SYS == 0 */
#if COAP_SERVER_SUPPORT
      if (sock->endpoint)
        tcp_accept(tcp_pcb, NULL);
#endif /* COAP_SERVER_SUPPORT */
      tcp_recv(tcp_pcb, NULL);
      tcp_arg(tcp_pcb, NULL);
      tcp_err(tcp_pcb, NULL);
      tcp_close(tcp_pcb);
#if NO_SYS == 0
    }
#endif /* NO_SYS == 0 */
  }
  return;
}
#endif /* !COAP_DISABLE_TCP */

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
