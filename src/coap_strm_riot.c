/* coap_strm_riot.c -- Default Stream (TCP) network I/O functions for libcoap on RIOT
 *
 * Copyright (C) 2019-2025 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file coap_strm_riot.c
 * @brief RIOT specific Stream (TCP) I/O functions
 */

#include "coap3/coap_libcoap_build.h"

#if defined(RIOT_VERSION)

#include "net/gnrc.h"
#include "net/gnrc/ipv6.h"
#include "net/gnrc/netreg.h"
#include "net/udp.h"
#if COAP_DISABLE_TCP
#include "net/tcp.h"
#endif /* ! COAP_DISABLE_TCP */
#include "net/sock/async.h"

#include "coap3/coap_riot.h"

#define COAP_SELECT_THREAD_FLAG (1U << 4)

int
coap_tcp_is_supported(void) {
  return !COAP_DISABLE_TCP;
}

#if ! COAP_DISABLE_TCP

/*
 * strm
 * return +ve Number of bytes written.
 *          0 No data written.
 *         -1 Error (error in errno).
 */
ssize_t
coap_socket_write(coap_socket_t *sock, const uint8_t *data, size_t data_len) {
  ssize_t ret;

  sock->flags &= ~(COAP_SOCKET_WANT_WRITE | COAP_SOCKET_CAN_WRITE);
  ret = sock_tcp_write(&sock->tcp, data, data_len);
  if (ret < 0) {
    errno = -ret;
    ret = -1;
    if (errno==EAGAIN ||
#if EAGAIN != EWOULDBLOCK
        errno == EWOULDBLOCK ||
#endif
        errno == EINTR) {
      sock->flags |= COAP_SOCKET_WANT_WRITE;
      return 0;
    }
    if (errno == EPIPE || errno == ECONNRESET) {
      coap_log_info("coap_socket_write: send: %s\n",
                    coap_socket_strerror());
    } else {
      coap_log_warn("coap_socket_write: send: %s\n",
                    coap_socket_strerror());
    }
    return -1;
  }
  if (ret < (ssize_t)data_len) {
    sock->flags |= COAP_SOCKET_WANT_WRITE;
  }
  return ret;
}

/*
 * strm
 * return >=0 Number of bytes read.
 *         -1 Error (error in errno).
 */
ssize_t
coap_socket_read(coap_socket_t *sock, uint8_t *data, size_t data_len) {
  ssize_t ret;

  ret = sock_tcp_read(&sock->tcp, data, data_len, SOCK_NO_TIMEOUT);
  if (ret == 0) {
    /* graceful shutdown */
    sock->flags &= ~COAP_SOCKET_CAN_READ;
    errno = ECONNRESET;
    return -1;
  } else if (ret < 0) {
    errno = -ret;
    ret = -1;
    sock->flags &= ~COAP_SOCKET_CAN_READ;
    if (errno==EAGAIN ||
#if EAGAIN != EWOULDBLOCK
        errno == EWOULDBLOCK ||
#endif
        errno == EINTR) {
      return 0;
    }
    if (errno != ECONNRESET) {
      coap_log_warn("coap_socket_read: recv: %s\n",
                    coap_socket_strerror());
    }
    return -1;
  }
  if (ret < (ssize_t)data_len)
    sock->flags &= ~COAP_SOCKET_CAN_READ;
  return ret;
}

#ifdef MODULE_LWIP_TCP
static void
tcp_recv_session_cb(sock_tcp_t *sock, sock_async_flags_t flags, void *arg) {
  coap_session_t *session = (coap_session_t *)arg;

  (void)sock;
  if (!(flags & (SOCK_ASYNC_MSG_RECV | SOCK_ASYNC_MSG_SENT)))
    return;

  if (flags & SOCK_ASYNC_MSG_RECV)
    session->sock.flags |= COAP_SOCKET_CAN_READ;
  if (session->context->selecting_thread) {
    thread_flags_set(session->context->selecting_thread,
                     COAP_SELECT_THREAD_FLAG);
  }
}
#endif /* MODULE_LWIP_TCP */

#if COAP_CLIENT_SUPPORT

int
coap_socket_connect_tcp1(coap_socket_t *sock,
                         const coap_address_t *local_if,
                         const coap_address_t *server,
                         int default_port,
                         coap_address_t *local_addr,
                         coap_address_t *remote_addr) {
  sock_tcp_ep_t local;
  sock_tcp_ep_t remote;
  coap_address_t connect_addr;
  int ret;

  coap_address_copy(&connect_addr, server);

  sock->flags &= ~(COAP_SOCKET_CONNECTED | COAP_SOCKET_MULTICAST);

  if (local_if && local_if->riot.family) {
    if (local_if->riot.family != connect_addr.riot.family) {
      coap_log_warn("coap_socket_connect_tcp1: local address family != "
                    "remote address family\n");
      goto error;
    }
  }

  local.netif = SOCK_ADDR_ANY_NETIF;
  remote.netif = SOCK_ADDR_ANY_NETIF;
  switch (connect_addr.riot.family) {
#if COAP_IPV4_SUPPORT
  case AF_INET:
    local.family = AF_INET;
    local.port = 0;
    if (local_if) {
      memcpy(local.addr.ipv4, &local_if->riot.addr.ipv4, sizeof(local.addr.ipv4));
      local.port = local_if->riot.port;
    } else {
      memset(local.addr.ipv4, 0, sizeof(local.addr.ipv4));
    }
    remote.family = AF_INET;
    memcpy(remote.addr.ipv4, &server->riot.addr.ipv4, sizeof(remote.addr.ipv4));
    if (connect_addr.riot.port == 0)
      connect_addr.riot.port = default_port;
    remote.port = connect_addr.riot.port;
    break;
#endif /* COAP_IPV4_SUPPORT */
#if COAP_IPV6_SUPPORT
  case AF_INET6:
    local.family = AF_INET6;
    local.port = 0;
    if (local_if) {
      memcpy(local.addr.ipv6, &local_if->riot.addr.ipv6, sizeof(local.addr.ipv6));
      local.port = local_if->riot.port;
    } else {
      memset(local.addr.ipv6, 0, sizeof(local.addr.ipv6));
    }
    remote.family = AF_INET6;
    memcpy(remote.addr.ipv6, &server->riot.addr.ipv6, sizeof(remote.addr.ipv6));
    if (connect_addr.riot.port == 0)
      connect_addr.riot.port = default_port;
    remote.port = connect_addr.riot.port;
    break;
#endif /* COAP_IPV6_SUPPORT */
  default:
    coap_log_alert("coap_socket_connect_tcp1: unsupported sa_family %d\n",
                   connect_addr.riot.family);
    goto error;
  }

  ret = sock_tcp_connect(&sock->tcp, &remote, 0, 0);
  if (ret < 0) {
    errno = -ret;
    ret = -1;
    coap_log_warn("coap_socket_connect_tcp1: sock_tcp_create: %s (%d)\n",
                  coap_socket_strerror(), connect_addr.riot.family);
    goto error;
  }
  ret = sock_tcp_get_local(&sock->tcp, &local);
  if (ret != 0) {
    errno = -ret;
    ret = -1;
    coap_log_warn("coap_socket_connect_tcp1: sock_tcp_get_local: %s\n",
                  coap_socket_strerror());
  }
  memcpy(&local_addr->riot, &local, sizeof(local_addr->riot));

  ret = sock_tcp_get_remote(&sock->tcp, &remote);
  if (ret != 0) {
    errno = -ret;
    ret = -1;
    coap_log_warn("coap_socket_connect_tcp: sock_tcp_get_remote: %s\n",
                  coap_socket_strerror());
  }
  memcpy(&remote_addr->riot, &remote, sizeof(remote_addr->riot));

#ifdef MODULE_LWIP_TCP
  sock_tcp_set_cb(&sock->tcp, tcp_recv_session_cb, sock->session);
#endif /* MODULE_LWIP_TCP */

  sock->flags |= COAP_SOCKET_CONNECTED;
  return 1;

error:
  coap_socket_close(sock);
  return 0;
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

#define SOCK_QUEUE_LEN  (1U)

static sock_tcp_t sock_queue[SOCK_QUEUE_LEN];
static sock_tcp_queue_t queue;

int
coap_socket_bind_tcp(coap_socket_t *sock,
                     const coap_address_t *listen_addr,
                     coap_address_t *bound_addr) {
  ssize_t ret;

  (void)sock;

  ret = sock_tcp_listen(&queue, &listen_addr->riot, sock_queue, SOCK_QUEUE_LEN, 0);
  if (ret < 0) {
    errno = -ret;
    return 0;
  }

  coap_address_copy(bound_addr, listen_addr);

  return 1;
}

int
coap_socket_accept_tcp(coap_socket_t *server,
                       coap_socket_t *new_client,
                       coap_address_t *local_addr,
                       coap_address_t *remote_addr,
                       void *extra) {
  sock_tcp_t *sock = NULL;
  ssize_t ret;
  sock_tcp_ep_t scratch;

  (void)extra;
  server->flags &= ~COAP_SOCKET_CAN_ACCEPT;
  ret = sock_tcp_accept(&queue, &sock, SOCK_NO_TIMEOUT);
  if (ret < 0) {
    errno = -ret;
    return 0;
  }
  if (sock == NULL || ret < 0) {
    coap_log_warn("coap_socket_accept_tcp: accept: %s\n",
                  coap_socket_strerror());
    return 0;
  }
  new_client->tcp = *sock;

  ret = sock_tcp_get_remote(&new_client->tcp, &scratch);
  if (ret < 0) {
    errno = -ret;
    return 0;
  }
  memcpy(&remote_addr->riot, &scratch, sizeof(remote_addr->riot));
  ret = sock_tcp_get_local(&new_client->tcp, &scratch);
  if (ret < 0) {
    errno = -ret;
    return 0;
  }
  memcpy(&local_addr->riot, &scratch, sizeof(local_addr->riot));

#ifdef MODULE_LWIP_TCP
  sock_tcp_set_cb(&new_client->tcp, tcp_recv_session_cb, new_client->session);
#endif /* MODULE_LWIP_TCP */
  return 1;
}
#endif /* COAP_SERVER_SUPPORT */

void
coap_socket_strm_close(coap_socket_t *sock) {
  if (sock->flags != COAP_SOCKET_EMPTY) {
    sock_tcp_disconnect(&sock->tcp);
  }
  sock->flags = COAP_SOCKET_EMPTY;
}

#endif /* ! COAP_DISABLE_TCP */

#else /* ! RIOT_VERSION */

#ifdef __clang__
/* Make compilers happy that do not like empty modules. As this function is
 * never used, we ignore -Wunused-function at the end of compiling this file
 */
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
static inline void
dummy(void) {
}

#endif /* ! RIOT_VERSION */
