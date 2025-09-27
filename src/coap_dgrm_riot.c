/* coap_dgrm_riot.c -- Default Datagram (UDP) network I/O functions for libcoap on RIOT
 *
 * Copyright (C) 2019-2025 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file coap_dgrm_riot.c
 * @brief RIOT Datagran (UDP) specific I/O functions
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

/*
 * dgram
 * return +ve Number of bytes written.
 *         -1 Error error in errno).
 */
ssize_t
coap_socket_send(coap_socket_t *sock,
                 coap_session_t *session,
                 const uint8_t *data,
                 size_t datalen) {
  ssize_t bytes_written = 0;

  if (!coap_debug_send_packet()) {
    bytes_written = (ssize_t)datalen;
  } else if (sock->flags & COAP_SOCKET_CONNECTED) {
    bytes_written = sock_udp_send(&sock->udp, data, datalen, NULL);
  } else {
    bytes_written = sock_udp_send(&sock->udp, data, datalen, &session->addr_info.remote.riot);
  }

  if (bytes_written < 0) {
    errno = -bytes_written;
    bytes_written = -1;
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
  ssize_t len = -1;

  assert(sock);
  assert(packet);

  if ((sock->flags & COAP_SOCKET_CAN_READ) == 0) {
    return -1;
  } else {
    /* clear has-data flag */
    sock->flags &= ~COAP_SOCKET_CAN_READ;
  }

  if (sock->flags & COAP_SOCKET_CONNECTED) {
    len = sock_udp_recv(&sock->udp, (char *)packet->payload, COAP_RXBUFFER_SIZE, 0, NULL);
    if (len < 0) {
      errno = -len;
      len = -1;
      if (errno == ECONNREFUSED || errno == EHOSTUNREACH || errno == ECONNRESET) {
        /* client-side ICMP destination unreachable, ignore it */
        coap_log_warn("** %s: coap_socket_recv: ICMP: %s\n",
                      sock->session ?
                      coap_session_str(sock->session) : "",
                      coap_socket_strerror());
        return -2;
      }
      if (errno != EAGAIN) {
        coap_log_warn("** %s: coap_socket_recv: %s\n",
                      sock->session ?
                      coap_session_str(sock->session) : "",
                      coap_socket_strerror());
      }
      goto error;
    } else if (len > 0) {
      packet->length = (size_t)len;
    }
  } else {
    sock_udp_aux_rx_t aux;
    sock_udp_ep_t remote;

    aux.flags = SOCK_AUX_GET_LOCAL;
    len = sock_udp_recv_aux(&sock->udp, (char *)packet->payload, COAP_RXBUFFER_SIZE, 0,
                            &remote, &aux);
    if (len < 0) {
      errno = -len;
      len = -1;
      if (errno == ECONNREFUSED || errno == EHOSTUNREACH || errno == ECONNRESET) {
        /* client-side ICMP destination unreachable, ignore it */
        coap_log_warn("** %s: coap_socket_recv: ICMP: %s\n",
                      sock->session ?
                      coap_session_str(sock->session) : "",
                      coap_socket_strerror());
        return -2;
      }
      if (errno != EAGAIN) {
        coap_log_warn("** %s: coap_socket_recv: %s\n",
                      sock->session ?
                      coap_session_str(sock->session) : "",
                      coap_socket_strerror());
      }
      goto error;
    } else if (len > 0) {
      packet->length = (size_t)len;
      memcpy(&packet->addr_info.local.riot, &aux.local, sizeof(packet->addr_info.local.riot));
      memcpy(&packet->addr_info.remote.riot, &remote, sizeof(packet->addr_info.remote.riot));
    }
  }

  if (len >= 0)
    return len;
error:
  return -1;
}

#if COAP_SERVER_SUPPORT

static void
udp_recv_endpoint_cb(sock_udp_t *sock, sock_async_flags_t flags, void *arg) {
  coap_endpoint_t *endpoint = (coap_endpoint_t *)arg;

  (void)sock;
  if (!(flags & (SOCK_ASYNC_MSG_RECV | SOCK_ASYNC_MSG_SENT)))
    return;

  if (flags & SOCK_ASYNC_MSG_RECV)
    endpoint->sock.flags |= COAP_SOCKET_CAN_READ;
  if (endpoint->context->selecting_thread) {
    thread_flags_set(endpoint->context->selecting_thread,
                     COAP_SELECT_THREAD_FLAG);
  }
}

int
coap_socket_bind_udp(coap_socket_t *sock,
                     const coap_address_t *listen_addr,
                     coap_address_t *bound_addr) {
  int ret;

  ret = sock_udp_create(&sock->udp, &listen_addr->riot, NULL, SOCK_FLAGS_REUSE_EP);
  if (ret < 0) {
    errno = -ret;
    ret = -1;
    coap_log_warn("coap_socket_bind_udp: sock_udp_create: %s (%d)\n",
                  coap_socket_strerror(), listen_addr->riot.family);
    goto error;
  }
  ret = sock_udp_get_local(&sock->udp, &bound_addr->riot);
  if (ret != 0) {
    errno = -ret;
    ret = -1;
    coap_log_warn("coap_socket_bind_udp: sock_udp_get_local: %s\n",
                  coap_socket_strerror());
  }
  sock_udp_set_cb(&sock->udp, udp_recv_endpoint_cb, sock->endpoint);

  return 1;

error:
  coap_socket_dgrm_close(sock);
  return 0;
}
#endif /* COAP_SERVER_SUPPORT */

#if COAP_CLIENT_SUPPORT

static void
udp_recv_session_cb(sock_udp_t *sock, sock_async_flags_t flags, void *arg) {
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

int
coap_socket_connect_udp(coap_socket_t *sock,
                        const coap_address_t *local_if,
                        const coap_address_t *server,
                        int default_port,
                        coap_address_t *local_addr,
                        coap_address_t *remote_addr) {
  sock_udp_ep_t local;
  sock_udp_ep_t remote;
  coap_address_t connect_addr;
  int is_mcast = coap_is_mcast(server);
  int ret;

  coap_address_copy(&connect_addr, server);

  sock->flags &= ~(COAP_SOCKET_CONNECTED | COAP_SOCKET_MULTICAST);

  if (local_if && local_if->riot.family) {
    if (local_if->riot.family != connect_addr.riot.family) {
      coap_log_warn("coap_socket_connect_udp: local address family != "
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
      connect_addr.riot.port = htons(default_port);
    remote.port = connect_addr.riot.port;
    break;
#endif /* COAP_IPV6_SUPPORT */
  default:
    coap_log_alert("coap_socket_connect_udp: unsupported sa_family %d\n",
                   connect_addr.riot.family);
    goto error;
  }

  ret = sock_udp_create(&sock->udp, &local, &remote, is_mcast ? 0 : SOCK_FLAGS_CONNECT_REMOTE);
  if (ret < 0) {
    errno = -ret;
    ret = -1;
    coap_log_warn("coap_socket_connect_udp: sock_udp_create: %s (%d)\n",
                  coap_socket_strerror(), connect_addr.riot.family);
    goto error;
  }
  ret = sock_udp_get_local(&sock->udp, &local);
  if (ret != 0) {
    errno = -ret;
    ret = -1;
    coap_log_warn("coap_socket_connect_udp: sock_udp_get_local: %s\n",
                  coap_socket_strerror());
  }
  memcpy(&local_addr->riot, &local, sizeof(local_addr->riot));

  ret = sock_udp_get_remote(&sock->udp, &remote);
  if (ret != 0) {
    errno = -ret;
    ret = -1;
    coap_log_warn("coap_socket_connect_udp: sock_udp_get_remote: %s\n",
                  coap_socket_strerror());
  }
  memcpy(&remote_addr->riot, &remote, sizeof(remote_addr->riot));

  sock_udp_set_cb(&sock->udp, udp_recv_session_cb, sock->session);

  /* special treatment for sockets that are used for multicast communication */
  if (is_mcast) {
    coap_address_copy(remote_addr, &connect_addr);
    coap_address_copy(&sock->mcast_addr, &connect_addr);
    sock->flags |= COAP_SOCKET_MULTICAST;
    return 1;
  }

  sock->flags |= COAP_SOCKET_CONNECTED;
  return 1;

error:
  coap_socket_dgrm_close(sock);
  return 0;
}
#endif /* COAP_CLIENT_SUPPORT */

void
coap_socket_dgrm_close(coap_socket_t *sock) {
  if (sock->flags != COAP_SOCKET_EMPTY) {
    sock_udp_close(&sock->udp);
  }
  sock->flags = COAP_SOCKET_EMPTY;
}

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
