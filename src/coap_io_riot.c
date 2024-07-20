/* coap_io_riot.c -- Default network I/O functions for libcoap on RIOT
 *
 * Copyright (C) 2019-2024 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file coap_io_riot.c
 * @brief RIOT specific I/O functions
 */

#include "coap3/coap_libcoap_build.h"

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
coap_io_process(coap_context_t *ctx, uint32_t timeout_ms) {
  int ret;

  coap_lock_lock(ctx, return 0);
  ret = coap_io_process_lkd(ctx, timeout_ms);
  coap_lock_unlock(ctx);
  return ret;
}

int
coap_io_process_lkd(coap_context_t *ctx, uint32_t timeout_ms) {
  coap_tick_t before, now;
  uint32_t timeout;
  coap_socket_t *sockets[1];
  unsigned int max_sockets = sizeof(sockets)/sizeof(sockets[0]);
  unsigned int num_sockets;
  ztimer64_t timeout_timer;
  thread_flags_t tflags;

  coap_lock_check_locked(ctx);

  coap_ticks(&before);
  /* Use the common logic */
  timeout = coap_io_prepare_io_lkd(ctx, sockets, max_sockets, &num_sockets, before);

  if (timeout_ms == COAP_IO_NO_WAIT) {
    timeout = 0;
  } else if (timeout == 0 && timeout_ms == COAP_IO_WAIT) {
    timeout = UINT32_MAX/1000;
  } else {
    if (timeout == 0 || (timeout_ms != COAP_IO_WAIT && timeout_ms < timeout))
      timeout = timeout_ms;
  }

  if (timeout > 0) {
    ztimer64_set_timeout_flag(ZTIMER64_USEC, &timeout_timer, timeout*1000);
    ctx->selecting_thread = thread_get_active();

    /* Unlock so that other threads can lock/update ctx */
    coap_lock_unlock(ctx);

    tflags = thread_flags_wait_any(COAP_SELECT_THREAD_FLAG |
                                   THREAD_FLAG_TIMEOUT);
    /* Take control of ctx again */
    coap_lock_lock(ctx, return -1);

    if (tflags & THREAD_FLAG_TIMEOUT) {
      errno = EINTR;
    }

    ztimer64_remove(ZTIMER64_USEC, &timeout_timer);
  }

  coap_ticks(&now);
  coap_io_do_io_lkd(ctx, now);

#if COAP_SERVER_SUPPORT
  coap_expire_cache_entries(ctx);
#endif /* COAP_SERVER_SUPPORT */
  coap_ticks(&now);
#if COAP_ASYNC_SUPPORT
  /* Check to see if we need to send off any Async requests as delay might
     have been updated */
  coap_check_async(ctx, now);
  coap_ticks(&now);
#endif /* COAP_ASYNC_SUPPORT */

  return (int)(((now - before) * 1000) / COAP_TICKS_PER_SECOND);
}

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
  coap_socket_close(sock);
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
  coap_socket_close(sock);
  return 0;
}
#endif /* COAP_CLIENT_SUPPORT */

void
coap_socket_close(coap_socket_t *sock) {
  if (sock->flags != COAP_SOCKET_EMPTY) {
    sock_udp_close(&sock->udp);
  }
#if !COAP_DISABLE_TCP
  if (sock->flags != COAP_SOCKET_EMPTY) {
    sock_tcp_disconnect(&sock->tcp);
  }
#endif /* !COAP_DISABLE_TCP */
  sock->flags = COAP_SOCKET_EMPTY;
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

#endif /* ! COAP_DISABLE_TCP */

static msg_t _msg_q[LIBCOAP_MSG_QUEUE_SIZE];

void
coap_riot_startup(void) {
  msg_init_queue(_msg_q, LIBCOAP_MSG_QUEUE_SIZE);
}
