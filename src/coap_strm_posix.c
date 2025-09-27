/*
 * coap_strm_posix.c -- Stream (TCP) functions for libcoap
 *
 * Copyright (C) 2019-2025 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_strm_posix.c
 * @brief Posix CoAP Stream (TCP) handling functions
 */

#include "coap3/coap_libcoap_build.h"

#if ! defined(WITH_LWIP) && ! defined(WITH_CONTIKI) && ! defined (RIOT_VERSION)

#if COAP_AF_UNIX_SUPPORT
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef _WIN32
#include <stdio.h>
#endif /* _WIN32 */
#endif /* COAP_AF_UNIX_SUPPORT */
#ifdef COAP_EPOLL_SUPPORT
#include <sys/epoll.h>
#include <sys/timerfd.h>
#endif /* COAP_EPOLL_SUPPORT */

int
coap_tcp_is_supported(void) {
  return !COAP_DISABLE_TCP;
}

#if !COAP_DISABLE_TCP
#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
# define OPTVAL_T(t)         (t)
# define OPTVAL_GT(t)        (t)
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
# define OPTVAL_T(t)         (const char*)(t)
# define OPTVAL_GT(t)        (char*)(t)
# undef CMSG_DATA
# define CMSG_DATA WSA_CMSG_DATA
#endif

#if defined(__ZEPHYR__)
# include <zephyr/posix/sys/ioctl.h>
# ifndef OPTVAL_T
#  define OPTVAL_T(t)         (t)
# endif
# ifndef OPTVAL_GT
#  define OPTVAL_GT(t)        (t)
# endif
# ifndef FIONBIO
#  define FIONBIO            0x5421
# endif
#endif /* __ZEPHYR__ */

int
coap_socket_connect_tcp1(coap_socket_t *sock,
                         const coap_address_t *local_if,
                         const coap_address_t *server,
                         int default_port,
                         coap_address_t *local_addr,
                         coap_address_t *remote_addr) {
  int on = 1;
#if COAP_IPV6_SUPPORT
  int off = 0;
#endif /* COAP_IPV6_SUPPORT */
#ifdef _WIN32
  u_long u_on = 1;
#endif
  coap_address_t connect_addr;
  coap_address_copy(&connect_addr, server);

  sock->flags &= ~COAP_SOCKET_CONNECTED;
  sock->fd = socket(server->addr.sa.sa_family, SOCK_STREAM, 0);

  if (sock->fd == COAP_INVALID_SOCKET) {
    coap_log_warn("coap_socket_connect_tcp1: socket: %s\n",
                  coap_socket_strerror());
    goto error;
  }

#ifdef _WIN32
  if (ioctlsocket(sock->fd, FIONBIO, &u_on) == COAP_SOCKET_ERROR) {
#else
  if (ioctl(sock->fd, FIONBIO, &on) == COAP_SOCKET_ERROR) {
#endif
    coap_log_warn("coap_socket_connect_tcp1: ioctl FIONBIO: %s\n",
                  coap_socket_strerror());
  }

  switch (server->addr.sa.sa_family) {
#if COAP_IPV4_SUPPORT
  case AF_INET:
    if (connect_addr.addr.sin.sin_port == 0)
      connect_addr.addr.sin.sin_port = htons(default_port);
    break;
#endif /* COAP_IPV4_SUPPORT */
#if COAP_IPV6_SUPPORT
  case AF_INET6:
    if (connect_addr.addr.sin6.sin6_port == 0)
      connect_addr.addr.sin6.sin6_port = htons(default_port);
    /* Configure the socket as dual-stacked */
    if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_V6ONLY, OPTVAL_T(&off),
                   sizeof(off)) == COAP_SOCKET_ERROR)
      coap_log_warn("coap_socket_connect_tcp1: setsockopt IPV6_V6ONLY: %s\n",
                    coap_socket_strerror());
    break;
#endif /* COAP_IPV6_SUPPORT */
#if COAP_AF_UNIX_SUPPORT
  case AF_UNIX:
    break;
#endif /* COAP_AF_UNIX_SUPPORT */
  default:
    coap_log_alert("coap_socket_connect_tcp1: unsupported sa_family\n");
    break;
  }

  if (local_if && local_if->addr.sa.sa_family) {
    coap_address_copy(local_addr, local_if);
    if (setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR, OPTVAL_T(&on), sizeof(on)) == COAP_SOCKET_ERROR)
      coap_log_warn("coap_socket_connect_tcp1: setsockopt SO_REUSEADDR: %s\n",
                    coap_socket_strerror());
    if (bind(sock->fd, &local_if->addr.sa,
#if COAP_IPV4_SUPPORT
             local_if->addr.sa.sa_family == AF_INET ?
             (socklen_t)sizeof(struct sockaddr_in) :
#endif /* COAP_IPV4_SUPPORT */
             (socklen_t)local_if->size) == COAP_SOCKET_ERROR) {
      coap_log_warn("coap_socket_connect_tcp1: bind: %s\n",
                    coap_socket_strerror());
      goto error;
    }
  } else {
    local_addr->addr.sa.sa_family = server->addr.sa.sa_family;
  }

  if (connect(sock->fd, &connect_addr.addr.sa, connect_addr.size) == COAP_SOCKET_ERROR) {
#ifdef _WIN32
    if (WSAGetLastError() == WSAEWOULDBLOCK) {
#else
    if (errno == EINPROGRESS) {
#endif
      /*
       * COAP_SOCKET_CONNECTED needs to be set here as there will be reads/writes
       * by underlying TLS libraries during connect() and we do not want to
       * assert() in coap_read_session() or coap_write_session() when called by coap_read()
       */
      sock->flags |= COAP_SOCKET_WANT_CONNECT | COAP_SOCKET_CONNECTED;
      return 1;
    }
    coap_log_warn("coap_socket_connect_tcp1: connect: %s\n",
                  coap_socket_strerror());
    goto error;
  }

  if (getsockname(sock->fd, &local_addr->addr.sa, &local_addr->size) == COAP_SOCKET_ERROR) {
    coap_log_warn("coap_socket_connect_tcp1: getsockname: %s\n",
                  coap_socket_strerror());
  }

  if (getpeername(sock->fd, &remote_addr->addr.sa, &remote_addr->size) == COAP_SOCKET_ERROR) {
    coap_log_warn("coap_socket_connect_tcp1: getpeername: %s\n",
                  coap_socket_strerror());
  }

  sock->flags |= COAP_SOCKET_CONNECTED;
  return 1;

error:
#if COAP_AF_UNIX_SUPPORT
  if (local_if && local_if->addr.sa.sa_family == AF_UNIX) {
#ifdef _WIN32
    _unlink(local_if->addr.cun.sun_path);
#else /* ! _WIN32 */
    unlink(local_if->addr.cun.sun_path);
#endif /* ! _WIN32 */
  }
#endif /* COAP_AF_UNIX_SUPPORT */
  coap_socket_strm_close(sock);
  return 0;
}

int
coap_socket_connect_tcp2(coap_socket_t *sock,
                         coap_address_t *local_addr,
                         coap_address_t *remote_addr) {
  int error = 0;
#ifdef _WIN32
  int optlen = (int)sizeof(error);
#else
  socklen_t optlen = (socklen_t)sizeof(error);
#endif

  sock->flags &= ~(COAP_SOCKET_WANT_CONNECT | COAP_SOCKET_CAN_CONNECT);

  if (getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, OPTVAL_GT(&error),
                 &optlen) == COAP_SOCKET_ERROR) {
    coap_log_warn("coap_socket_connect_tcp2: getsockopt: %s\n",
                  coap_socket_strerror());
  }

  if (error) {
    coap_log_warn("coap_socket_connect_tcp2: connect failed: %s\n",
                  coap_socket_format_errno(error));
    coap_socket_strm_close(sock);
    return 0;
  }

  if (getsockname(sock->fd, &local_addr->addr.sa, &local_addr->size) == COAP_SOCKET_ERROR) {
    coap_log_warn("coap_socket_connect_tcp: getsockname: %s\n",
                  coap_socket_strerror());
  }

  if (getpeername(sock->fd, &remote_addr->addr.sa, &remote_addr->size) == COAP_SOCKET_ERROR) {
    coap_log_warn("coap_socket_connect_tcp: getpeername: %s\n",
                  coap_socket_strerror());
  }

  return 1;
}

int
coap_socket_bind_tcp(coap_socket_t *sock,
                     const coap_address_t *listen_addr,
                     coap_address_t *bound_addr) {
  int on = 1;
#if COAP_IPV6_SUPPORT
  int off = 0;
#endif /* COAP_IPV6_SUPPORT */
#ifdef _WIN32
  u_long u_on = 1;
#endif

  sock->fd = socket(listen_addr->addr.sa.sa_family, SOCK_STREAM, 0);

  if (sock->fd == COAP_INVALID_SOCKET) {
    coap_log_warn("coap_socket_bind_tcp: socket: %s\n",
                  coap_socket_strerror());
    goto error;
  }

#ifdef _WIN32
  if (ioctlsocket(sock->fd, FIONBIO, &u_on) == COAP_SOCKET_ERROR) {
#else
  if (ioctl(sock->fd, FIONBIO, &on) == COAP_SOCKET_ERROR) {
#endif
    coap_log_warn("coap_socket_bind_tcp: ioctl FIONBIO: %s\n",
                  coap_socket_strerror());
  }
  if (setsockopt(sock->fd, SOL_SOCKET, SO_KEEPALIVE, OPTVAL_T(&on),
                 sizeof(on)) == COAP_SOCKET_ERROR)
    coap_log_warn("coap_socket_bind_tcp: setsockopt SO_KEEPALIVE: %s\n",
                  coap_socket_strerror());

  if (setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR, OPTVAL_T(&on),
                 sizeof(on)) == COAP_SOCKET_ERROR)
    coap_log_warn("coap_socket_bind_tcp: setsockopt SO_REUSEADDR: %s\n",
                  coap_socket_strerror());

  switch (listen_addr->addr.sa.sa_family) {
#if COAP_IPV4_SUPPORT
  case AF_INET:
    break;
#endif /* COAP_IPV4_SUPPORT */
#if COAP_IPV6_SUPPORT
  case AF_INET6:
    /* Configure the socket as dual-stacked */
    if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_V6ONLY, OPTVAL_T(&off),
                   sizeof(off)) == COAP_SOCKET_ERROR)
      coap_log_alert("coap_socket_bind_tcp: setsockopt IPV6_V6ONLY: %s\n",
                     coap_socket_strerror());
    break;
#endif /* COAP_IPV6_SUPPORT */
#if COAP_AF_UNIX_SUPPORT
  case AF_UNIX:
    break;
#endif /* COAP_AF_UNIX_SUPPORT */
  default:
    coap_log_alert("coap_socket_bind_tcp: unsupported sa_family\n");
  }

  if (bind(sock->fd, &listen_addr->addr.sa,
#if COAP_IPV4_SUPPORT
           listen_addr->addr.sa.sa_family == AF_INET ?
           (socklen_t)sizeof(struct sockaddr_in) :
#endif /* COAP_IPV4_SUPPORT */
           (socklen_t)listen_addr->size) == COAP_SOCKET_ERROR) {
    coap_log_alert("coap_socket_bind_tcp: bind: %s\n",
                   coap_socket_strerror());
    goto error;
  }

  bound_addr->size = (socklen_t)sizeof(*bound_addr);
  if (getsockname(sock->fd, &bound_addr->addr.sa, &bound_addr->size) < 0) {
    coap_log_warn("coap_socket_bind_tcp: getsockname: %s\n",
                  coap_socket_strerror());
    goto error;
  }

  if (listen(sock->fd, 5) == COAP_SOCKET_ERROR) {
    coap_log_alert("coap_socket_bind_tcp: listen: %s\n",
                   coap_socket_strerror());
    goto  error;
  }

  return 1;

error:
  coap_socket_strm_close(sock);
  return 0;
}

int
coap_socket_accept_tcp(coap_socket_t *server,
                       coap_socket_t *new_client,
                       coap_address_t *local_addr,
                       coap_address_t *remote_addr,
                       void *extra) {
#ifdef _WIN32
  u_long u_on = 1;
#else
  int on = 1;
#endif
  (void)extra;

  new_client->fd = accept(server->fd, &remote_addr->addr.sa,
                          &remote_addr->size);
  if (new_client->fd == COAP_INVALID_SOCKET) {
    if (errno != EAGAIN) {
      coap_log_warn("coap_socket_accept_tcp: accept: %s\n",
                    coap_socket_strerror());
    }
    return 0;
  }

  server->flags &= ~COAP_SOCKET_CAN_ACCEPT;

  if (getsockname(new_client->fd, &local_addr->addr.sa, &local_addr->size) < 0)
    coap_log_warn("coap_socket_accept_tcp: getsockname: %s\n",
                  coap_socket_strerror());

#ifdef _WIN32
  if (ioctlsocket(new_client->fd, FIONBIO, &u_on) == COAP_SOCKET_ERROR) {
#else
  if (ioctl(new_client->fd, FIONBIO, &on) == COAP_SOCKET_ERROR) {
#endif
    coap_log_warn("coap_socket_accept_tcp: ioctl FIONBIO: %s\n",
                  coap_socket_strerror());
  }
  return 1;
}

/*
 * strm
 * return +ve Number of bytes written.
 *          0 No data written.
 *         -1 Error (error in errno).
 */
ssize_t
coap_socket_write(coap_socket_t *sock, const uint8_t *data, size_t data_len) {
  ssize_t r;

  sock->flags &= ~(COAP_SOCKET_WANT_WRITE | COAP_SOCKET_CAN_WRITE);
#ifdef _WIN32
  r = send(sock->fd, (const char *)data, (int)data_len, 0);
#else
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif /* MSG_NOSIGNAL */
  r = send(sock->fd, data, data_len, MSG_NOSIGNAL);
#endif
  if (r == COAP_SOCKET_ERROR) {
#ifdef _WIN32
    coap_win_error_to_errno();
#endif /* _WIN32 */
    if (errno==EAGAIN ||
#if EAGAIN != EWOULDBLOCK
        errno == EWOULDBLOCK ||
#endif
        errno == EINTR) {
      sock->flags |= COAP_SOCKET_WANT_WRITE;
#ifdef COAP_EPOLL_SUPPORT
      coap_epoll_ctl_mod(sock,
                         EPOLLOUT |
                         ((sock->flags & COAP_SOCKET_WANT_READ) ?
                          EPOLLIN : 0),
                         __func__);
#endif /* COAP_EPOLL_SUPPORT */
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
  if (r < (ssize_t)data_len) {
    sock->flags |= COAP_SOCKET_WANT_WRITE;
#ifdef COAP_EPOLL_SUPPORT
    coap_epoll_ctl_mod(sock,
                       EPOLLOUT |
                       ((sock->flags & COAP_SOCKET_WANT_READ) ?
                        EPOLLIN : 0),
                       __func__);
#endif /* COAP_EPOLL_SUPPORT */
  }
  return r;
}

/*
 * strm
 * return >=0 Number of bytes read.
 *         -1 Error (error in errno).
 */
ssize_t
coap_socket_read(coap_socket_t *sock, uint8_t *data, size_t data_len) {
  ssize_t r;

#ifdef _WIN32
  r = recv(sock->fd, (char *)data, (int)data_len, 0);
#else
  r = recv(sock->fd, data, data_len, 0);
#endif
  if (r == 0) {
    /* graceful shutdown */
    sock->flags &= ~COAP_SOCKET_CAN_READ;
    errno = ECONNRESET;
    return -1;
  } else if (r == COAP_SOCKET_ERROR) {
    sock->flags &= ~COAP_SOCKET_CAN_READ;
#ifdef _WIN32
    coap_win_error_to_errno();
#endif /* _WIN32 */
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
  if (r < (ssize_t)data_len)
    sock->flags &= ~COAP_SOCKET_CAN_READ;
  return r;
}

void
coap_socket_strm_close(coap_socket_t *sock) {
  /* For POSIX, this is the same as the datagram version */
  coap_socket_dgrm_close(sock);
}

#endif /* !COAP_DISABLE_TCP */

#else /* WITH_LWIP || WITH_CONTIKI || RIOT_VERSION */

#ifdef __clang__
/* Make compilers happy that do not like empty modules. As this function is
 * never used, we ignore -Wunused-function at the end of compiling this file
 */
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
static inline void
dummy(void) {
}

#endif /* WITH_LWIP || WITH_CONTIKI || RIOT_VERSION */
