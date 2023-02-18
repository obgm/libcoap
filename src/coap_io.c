/* coap_io.c -- Default network I/O functions for libcoap
 *
 * Copyright (C) 2012,2014,2016-2023 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file coap_io.c
 * @brief Network I/O functions
 */

#include "coap3/coap_internal.h"

#ifdef HAVE_STDIO_H
#  include <stdio.h>
#endif

#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
# define OPTVAL_T(t)         (t)
# define OPTVAL_GT(t)        (t)
#endif
#ifdef HAVE_SYS_IOCTL_H
 #include <sys/ioctl.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
# define OPTVAL_T(t)         (const char*)(t)
# define OPTVAL_GT(t)        (char*)(t)
# undef CMSG_DATA
# define CMSG_DATA WSA_CMSG_DATA
#endif
#ifdef HAVE_SYS_UIO_H
# include <sys/uio.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#ifdef COAP_EPOLL_SUPPORT
#include <sys/epoll.h>
#include <sys/timerfd.h>
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#endif /* COAP_EPOLL_SUPPORT */

#if !defined(WITH_CONTIKI) && !defined(RIOT_VERSION) && !(WITH_LWIP)
 /* define generic PKTINFO for IPv4 */
#if defined(IP_PKTINFO)
#  define GEN_IP_PKTINFO IP_PKTINFO
#elif defined(IP_RECVDSTADDR)
#  define GEN_IP_PKTINFO IP_RECVDSTADDR
#else
#  error "Need IP_PKTINFO or IP_RECVDSTADDR to request ancillary data from OS."
#endif /* IP_PKTINFO */

/* define generic KTINFO for IPv6 */
#ifdef IPV6_RECVPKTINFO
#  define GEN_IPV6_PKTINFO IPV6_RECVPKTINFO
#elif defined(IPV6_PKTINFO)
#  define GEN_IPV6_PKTINFO IPV6_PKTINFO
#else
#  error "Need IPV6_PKTINFO or IPV6_RECVPKTINFO to request ancillary data from OS."
#endif /* IPV6_RECVPKTINFO */
#endif /* !(WITH_CONTIKI || RIOT_VERSION) */

/*
 * Layer index table.  A whole protocol chunk gets copied into coap_socket_t.
 * Each layer invokes the function defined at its layer to get the next layer
 * (which could be above or below) to complete.
 *
 * The stack layers are (* managed by libcoap)
 *   Application
 *   CoAP *
 *   CoAP-Session *
 *   DTLS *
 *   Netif *
 *   Sockets *
 *   Network Stack
 *
 * dgrm read currently handled separately.
 * strm read works down the layers.
 * write     works down the layers.
 * establish is done after netif accept/connect completes by invoking SESSION
 * and then works up the layers.
 * close     works down the layers
 */
coap_layer_func_t coap_layers_coap[COAP_PROTO_LAST][COAP_LAYER_LAST] = {
  { /* COAP_PROTO_NONE */
    { NULL, NULL, NULL, NULL }, /* SESSION */
    { NULL, NULL, NULL, NULL }, /* WS */
    { NULL, NULL, NULL, NULL }  /* TLS */
  },
  { /* COAP_PROTO_UDP */
    { NULL,                 coap_netif_dgrm_write, coap_session_establish, coap_netif_close }, /* SESSION */
    { NULL,                 NULL,                  NULL,                   NULL             }, /* WS */
    { NULL,                 NULL,                  NULL,                   NULL             }  /* TLS */
  },
  { /* COAP_PROTO_DTLS */
    { NULL,                 coap_dtls_send,        coap_dtls_establish,    coap_dtls_close  }, /* SESSION */
    { NULL,                 NULL,                  NULL,                   NULL             }, /* WS */
    { NULL,                 coap_netif_dgrm_write, coap_session_establish, coap_netif_close }  /* TLS */
  },
#if !COAP_DISABLE_TCP
  { /* COAP_PROTO_TCP */
    { coap_netif_strm_read, coap_netif_strm_write, coap_session_establish, coap_netif_close }, /* SESSION */
    { NULL,                 NULL,                  NULL,                   NULL             }, /* WS */
    { NULL,                 NULL,                  NULL,                   NULL             }  /* TLS */
  },
  { /* COAP_PROTO_TLS */
    { coap_tls_read,        coap_tls_write,        coap_tls_establish,     coap_tls_close   }, /* SESSION */
    { NULL,                 NULL,                  NULL,                   NULL             }, /* WS */
    { coap_netif_strm_read, coap_netif_strm_write, coap_session_establish, coap_netif_close }  /* TLS */
  },
#if COAP_WS_SUPPORT
  { /* COAP_PROTO_WS */
    { coap_ws_read,         coap_ws_write,         coap_ws_establish,      coap_ws_close    }, /* SESSION */
    { coap_netif_strm_read, coap_netif_strm_write, coap_session_establish, coap_netif_close }, /* WS */
    { NULL,                 NULL,                  NULL,                   NULL             }  /* TLS */
  },
  { /* COAP_PROTO_WSS */
    { coap_ws_read,         coap_ws_write,         coap_tls_establish,     coap_ws_close    }, /* SESSION */
    { coap_tls_read,        coap_tls_write,        coap_session_establish, coap_tls_close   }, /* WS */
    { coap_netif_strm_read, coap_netif_strm_write, coap_ws_establish,      coap_netif_close }  /* TLS */
  }
#else /* !COAP_WS_SUPPORT */
  { /* COAP_PROTO_WS */
    { NULL, NULL, NULL, NULL }, /* SESSION */
    { NULL, NULL, NULL, NULL }, /* WS */
    { NULL, NULL, NULL, NULL }  /* TLS */
  },
  { /* COAP_PROTO_WSS */
    { NULL, NULL, NULL, NULL }, /* SESSION */
    { NULL, NULL, NULL, NULL }, /* WS */
    { NULL, NULL, NULL, NULL }  /* TLS */
  }
#endif /* !COAP_WS_SUPPORT */
#else /* COAP_DISABLE_TCP */
  { /* COAP_PROTO_TCP */
    { NULL, NULL, NULL, NULL }, /* SESSION */
    { NULL, NULL, NULL, NULL }, /* WS */
    { NULL, NULL, NULL, NULL }  /* TLS */
  },
  { /* COAP_PROTO_TLS */
    { NULL, NULL, NULL, NULL }, /* SESSION */
    { NULL, NULL, NULL, NULL }, /* WS */
    { NULL, NULL, NULL, NULL }  /* TLS */
  },
  { /* COAP_PROTO_WS */
    { NULL, NULL, NULL, NULL }, /* SESSION */
    { NULL, NULL, NULL, NULL }, /* WS */
    { NULL, NULL, NULL, NULL }  /* TLS */
  },
  { /* COAP_PROTO_WSS */
    { NULL, NULL, NULL, NULL }, /* SESSION */
    { NULL, NULL, NULL, NULL }, /* WS */
    { NULL, NULL, NULL, NULL }  /* TLS */
  }
#endif /* COAP_DISABLE_TCP */
};

#if COAP_SERVER_SUPPORT
coap_endpoint_t *
  coap_malloc_endpoint(void) {
  return (coap_endpoint_t *)coap_malloc_type(COAP_ENDPOINT, sizeof(coap_endpoint_t));
}

void
coap_mfree_endpoint(coap_endpoint_t *ep) {
  coap_free_type(COAP_ENDPOINT, ep);
}
#endif /* COAP_SERVER_SUPPORT */

#if !defined(WITH_CONTIKI) && !defined(WITH_LWIP)

int
coap_socket_bind_udp(coap_socket_t *sock,
  const coap_address_t *listen_addr,
  coap_address_t *bound_addr) {
#ifndef RIOT_VERSION
  int on = 1, off = 0;
#endif /* RIOT_VERSION */
#ifdef _WIN32
  u_long u_on = 1;
#endif

  sock->fd = socket(listen_addr->addr.sa.sa_family, SOCK_DGRAM, 0);

  if (sock->fd == COAP_INVALID_SOCKET) {
    coap_log_warn(
             "coap_socket_bind_udp: socket: %s\n", coap_socket_strerror());
    goto error;
  }
#ifndef RIOT_VERSION
#ifdef _WIN32
  if (ioctlsocket(sock->fd, FIONBIO, &u_on) == COAP_SOCKET_ERROR) {
#else
  if (ioctl(sock->fd, FIONBIO, &on) == COAP_SOCKET_ERROR) {
#endif
    coap_log_warn(
         "coap_socket_bind_udp: ioctl FIONBIO: %s\n", coap_socket_strerror());
  }

  if (setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR, OPTVAL_T(&on), sizeof(on)) == COAP_SOCKET_ERROR)
    coap_log_warn(
             "coap_socket_bind_udp: setsockopt SO_REUSEADDR: %s\n",
              coap_socket_strerror());

  switch (listen_addr->addr.sa.sa_family) {
  case AF_INET:
    if (setsockopt(sock->fd, IPPROTO_IP, GEN_IP_PKTINFO, OPTVAL_T(&on), sizeof(on)) == COAP_SOCKET_ERROR)
      coap_log_alert(
               "coap_socket_bind_udp: setsockopt IP_PKTINFO: %s\n",
                coap_socket_strerror());
    break;
  case AF_INET6:
    /* Configure the socket as dual-stacked */
    if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_V6ONLY, OPTVAL_T(&off), sizeof(off)) == COAP_SOCKET_ERROR)
      coap_log_alert(
               "coap_socket_bind_udp: setsockopt IPV6_V6ONLY: %s\n",
                coap_socket_strerror());
#if !defined(ESPIDF_VERSION)
    if (setsockopt(sock->fd, IPPROTO_IPV6, GEN_IPV6_PKTINFO, OPTVAL_T(&on), sizeof(on)) == COAP_SOCKET_ERROR)
      coap_log_alert(
               "coap_socket_bind_udp: setsockopt IPV6_PKTINFO: %s\n",
                coap_socket_strerror());
#endif /* !defined(ESPIDF_VERSION) */
    setsockopt(sock->fd, IPPROTO_IP, GEN_IP_PKTINFO, OPTVAL_T(&on), sizeof(on));
    /* ignore error, because likely cause is that IPv4 is disabled at the os
       level */
    break;
  case AF_UNIX:
    break;
  default:
    coap_log_alert("coap_socket_bind_udp: unsupported sa_family\n");
    break;
  }
#endif /* RIOT_VERSION */

  if (bind(sock->fd, &listen_addr->addr.sa,
           listen_addr->addr.sa.sa_family == AF_INET ?
            (socklen_t)sizeof(struct sockaddr_in) :
            (socklen_t)listen_addr->size) == COAP_SOCKET_ERROR) {
    coap_log_warn("coap_socket_bind_udp: bind: %s\n",
             coap_socket_strerror());
    goto error;
  }

  bound_addr->size = (socklen_t)sizeof(*bound_addr);
  if (getsockname(sock->fd, &bound_addr->addr.sa, &bound_addr->size) < 0) {
    coap_log_warn(
             "coap_socket_bind_udp: getsockname: %s\n",
              coap_socket_strerror());
    goto error;
  }

  return 1;

error:
  coap_socket_close(sock);
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
#ifndef RIOT_VERSION
  int on = 1;
  int off = 0;
#endif /* RIOT_VERSION */
#ifdef _WIN32
  u_long u_on = 1;
#endif
  coap_address_t connect_addr;
  int is_mcast = coap_is_mcast(server);
  coap_address_copy(&connect_addr, server);

  sock->flags &= ~(COAP_SOCKET_CONNECTED | COAP_SOCKET_MULTICAST);
  sock->fd = socket(connect_addr.addr.sa.sa_family, SOCK_DGRAM, 0);

  if (sock->fd == COAP_INVALID_SOCKET) {
    coap_log_warn("coap_socket_connect_udp: socket: %s\n",
             coap_socket_strerror());
    goto error;
  }

#ifndef RIOT_VERSION
#ifdef _WIN32
  if (ioctlsocket(sock->fd, FIONBIO, &u_on) == COAP_SOCKET_ERROR) {
#else
  if (ioctl(sock->fd, FIONBIO, &on) == COAP_SOCKET_ERROR) {
#endif
    coap_log_warn("coap_socket_connect_udp: ioctl FIONBIO: %s\n",
             coap_socket_strerror());
  }
#endif /* RIOT_VERSION */

  switch (connect_addr.addr.sa.sa_family) {
  case AF_INET:
    if (connect_addr.addr.sin.sin_port == 0)
      connect_addr.addr.sin.sin_port = htons(default_port);
    break;
  case AF_INET6:
    if (connect_addr.addr.sin6.sin6_port == 0)
      connect_addr.addr.sin6.sin6_port = htons(default_port);
#ifndef RIOT_VERSION
    /* Configure the socket as dual-stacked */
    if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_V6ONLY, OPTVAL_T(&off), sizeof(off)) == COAP_SOCKET_ERROR)
      coap_log_warn(
               "coap_socket_connect_udp: setsockopt IPV6_V6ONLY: %s\n",
               coap_socket_strerror());
#endif /* RIOT_VERSION */
    break;
  case AF_UNIX:
    break;
  default:
    coap_log_alert("coap_socket_connect_udp: unsupported sa_family\n");
    break;
  }

  if (local_if && local_if->addr.sa.sa_family) {
    if (local_if->addr.sa.sa_family != connect_addr.addr.sa.sa_family) {
      coap_log_warn("coap_socket_connect_udp: local address family !="
                    " remote address family\n");
      goto error;
    }
#ifndef RIOT_VERSION
    if (setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR, OPTVAL_T(&on), sizeof(on)) == COAP_SOCKET_ERROR)
      coap_log_warn(
               "coap_socket_connect_udp: setsockopt SO_REUSEADDR: %s\n",
               coap_socket_strerror());
#endif /* RIOT_VERSION */
    if (bind(sock->fd, &local_if->addr.sa,
             local_if->addr.sa.sa_family == AF_INET ?
              (socklen_t)sizeof(struct sockaddr_in) :
              (socklen_t)local_if->size) == COAP_SOCKET_ERROR) {
      coap_log_warn("coap_socket_connect_udp: bind: %s\n",
               coap_socket_strerror());
      goto error;
    }
  } else if (connect_addr.addr.sa.sa_family == AF_UNIX) {
    /* Need to bind to a local address for clarity over endpoints */
    coap_log_warn("coap_socket_connect_udp: local address required\n");
    goto error;
  }

  /* special treatment for sockets that are used for multicast communication */
  if (is_mcast) {
    if (!(local_if && local_if->addr.sa.sa_family)) {
      /* Bind to a (unused) port to simplify logging */
      coap_address_t bind_addr;

      coap_address_init(&bind_addr);
      bind_addr.addr.sa.sa_family = connect_addr.addr.sa.sa_family;
      if (bind(sock->fd, &bind_addr.addr.sa,
               bind_addr.addr.sa.sa_family == AF_INET ?
                (socklen_t)sizeof(struct sockaddr_in) :
                (socklen_t)bind_addr.size) == COAP_SOCKET_ERROR) {
        coap_log_warn("coap_socket_connect_udp: bind: %s\n",
                 coap_socket_strerror());
        goto error;
      }
    }
    if (getsockname(sock->fd, &local_addr->addr.sa, &local_addr->size) == COAP_SOCKET_ERROR) {
      coap_log_warn(
              "coap_socket_connect_udp: getsockname for multicast socket: %s\n",
              coap_socket_strerror());
    }
    coap_address_copy(remote_addr, &connect_addr);
    sock->flags |= COAP_SOCKET_MULTICAST;
    return 1;
  }

  if (connect(sock->fd, &connect_addr.addr.sa, connect_addr.size) == COAP_SOCKET_ERROR) {
    if (connect_addr.addr.sa.sa_family == AF_UNIX) {
      coap_log_warn("coap_socket_connect_udp: connect: %s: %s\n",
               connect_addr.addr.cun.sun_path, coap_socket_strerror());
    }
    else {
      coap_log_warn("coap_socket_connect_udp: connect: %s\n",
               coap_socket_strerror());
    }
    goto error;
  }

  if (getsockname(sock->fd, &local_addr->addr.sa, &local_addr->size) == COAP_SOCKET_ERROR) {
    coap_log_warn("coap_socket_connect_udp: getsockname: %s\n",
             coap_socket_strerror());
  }

  if (getpeername(sock->fd, &remote_addr->addr.sa, &remote_addr->size) == COAP_SOCKET_ERROR) {
    coap_log_warn("coap_socket_connect_udp: getpeername: %s\n",
             coap_socket_strerror());
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
  if (sock->fd != COAP_INVALID_SOCKET) {
#ifdef COAP_EPOLL_SUPPORT
#if COAP_SERVER_SUPPORT
    coap_context_t *context = sock->session ? sock->session->context :
                              sock->endpoint ? sock->endpoint->context : NULL;
#else /* COAP_SERVER_SUPPORT */
    coap_context_t *context = sock->session ? sock->session->context : NULL;
#endif /* COAP_SERVER_SUPPORT */
    if (context != NULL) {
      int ret;
      struct epoll_event event;

      /* Kernels prior to 2.6.9 expect non NULL event parameter */
      ret = epoll_ctl(context->epfd, EPOLL_CTL_DEL, sock->fd, &event);
      if (ret == -1 && errno != ENOENT) {
         coap_log_err(
                  "%s: epoll_ctl DEL failed: %s (%d)\n",
                  "coap_socket_close",
                  coap_socket_strerror(), errno);
      }
    }
#if COAP_SERVER_SUPPORT
    if (sock->endpoint &&
        sock->endpoint->bind_addr.addr.sa.sa_family == AF_UNIX) {
      /* Clean up Unix endpoint */
      unlink(sock->endpoint->bind_addr.addr.cun.sun_path);
    }
    sock->endpoint = NULL;
#endif /* COAP_SERVER_SUPPORT */
#if COAP_CLIENT_SUPPORT
    if (sock->session && sock->session->type == COAP_SESSION_TYPE_CLIENT &&
        sock->session->addr_info.local.addr.sa.sa_family == AF_UNIX) {
      /* Clean up Unix endpoint */
      unlink(sock->session->addr_info.local.addr.cun.sun_path);
    }
#endif /* COAP_CLIENT_SUPPORT */
    sock->session = NULL;
#endif /* COAP_EPOLL_SUPPORT */
    coap_closesocket(sock->fd);
    sock->fd = COAP_INVALID_SOCKET;
  }
  sock->flags = COAP_SOCKET_EMPTY;
}

#ifdef COAP_EPOLL_SUPPORT
void
coap_epoll_ctl_add(coap_socket_t *sock,
                   uint32_t events,
                   const char *func) {
  int ret;
  struct epoll_event event;
  coap_context_t *context;

  if (sock == NULL)
    return;

#if COAP_SERVER_SUPPORT
  context = sock->session ? sock->session->context :
                            sock->endpoint ? sock->endpoint->context : NULL;
#else /* ! COAP_SERVER_SUPPORT */
  context = sock->session ? sock->session->context : NULL;
#endif /* ! COAP_SERVER_SUPPORT */
  if (context == NULL)
    return;

  /* Needed if running 32bit as ptr is only 32bit */
  memset(&event, 0, sizeof(event));
  event.events = events;
  event.data.ptr = sock;

  ret = epoll_ctl(context->epfd, EPOLL_CTL_ADD, sock->fd, &event);
  if (ret == -1) {
     coap_log_err(
              "%s: epoll_ctl ADD failed: %s (%d)\n",
              func,
              coap_socket_strerror(), errno);
  }
}

void
coap_epoll_ctl_mod(coap_socket_t *sock,
                   uint32_t events,
                   const char *func) {
  int ret;
  struct epoll_event event;
  coap_context_t *context;

  if (sock == NULL)
    return;

#if COAP_SERVER_SUPPORT
  context = sock->session ? sock->session->context :
                            sock->endpoint ? sock->endpoint->context : NULL;
#else /* COAP_SERVER_SUPPORT */
  context = sock->session ? sock->session->context : NULL;
#endif /* COAP_SERVER_SUPPORT */
  if (context == NULL)
    return;

  event.events = events;
  event.data.ptr = sock;

  ret = epoll_ctl(context->epfd, EPOLL_CTL_MOD, sock->fd, &event);
  if (ret == -1) {
     coap_log_err(
              "%s: epoll_ctl MOD failed: %s (%d)\n",
              func,
              coap_socket_strerror(), errno);
  }
}

void
coap_update_epoll_timer(coap_context_t *context, coap_tick_t delay)
{
  if (context->eptimerfd != -1) {
    coap_tick_t now;

    coap_ticks(&now);
    if (context->next_timeout == 0 || context->next_timeout > now + delay) {
      struct itimerspec new_value;
      int ret;

      context->next_timeout = now + delay;
      memset(&new_value, 0, sizeof(new_value));
      if (delay == 0) {
        new_value.it_value.tv_nsec = 1; /* small but not zero */
      }
      else {
        new_value.it_value.tv_sec = delay / COAP_TICKS_PER_SECOND;
        new_value.it_value.tv_nsec = (delay % COAP_TICKS_PER_SECOND) *
                                    1000000;
      }
      ret = timerfd_settime(context->eptimerfd, 0, &new_value, NULL);
      if (ret == -1) {
        coap_log_err(
                  "%s: timerfd_settime failed: %s (%d)\n",
                  "coap_resource_notify_observers",
                  coap_socket_strerror(), errno);
      }
#ifdef COAP_DEBUG_WAKEUP_TIMES
      else {
        coap_log_debug("****** Next wakeup time %3ld.%09ld\n",
                       new_value.it_value.tv_sec, new_value.it_value.tv_nsec);
      }
#endif /* COAP_DEBUG_WAKEUP_TIMES */
    }
  }
}

#endif /* COAP_EPOLL_SUPPORT */

#ifdef _WIN32
static void
coap_win_error_to_errno(void) {
  int error = WSAGetLastError();
  switch (error) {
  case WSAEWOULDBLOCK:  errno = EWOULDBLOCK; break;
  case WSAECONNRESET:   errno = ECONNRESET; break;
  case WSAECONNREFUSED: errno = ECONNREFUSED; break;
  case WSAEINVAL:       errno = EINVAL; break;
  default:
    coap_log_debug("WSAGetLastError: %d mapping to errno undefined\n", error);
    break;
  }
}
#endif /* _WIN32 */

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
    if (WSAGetLastError() == WSAEWOULDBLOCK)
#elif EAGAIN != EWOULDBLOCK
    if (errno==EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
#else
    if (errno==EAGAIN || errno == EINTR)
#endif
    {
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
    }
    else {
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
  int error;
#endif

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
    error = WSAGetLastError();
    if (error == WSAEWOULDBLOCK)
#elif EAGAIN != EWOULDBLOCK
    if (errno==EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
#else
    if (errno==EAGAIN || errno == EINTR)
#endif
    {
      return 0;
    }
#ifdef _WIN32
    if (error != WSAECONNRESET)
#else
    if (errno != ECONNRESET)
#endif
      coap_log_warn("coap_socket_read: recv: %s\n",
               coap_socket_strerror());
    return -1;
  }
  if (r < (ssize_t)data_len)
    sock->flags &= ~COAP_SOCKET_CAN_READ;
  return r;
}

#endif /* ! WITH_CONTIKI && ! WITH_LWIP */

#if !defined(WITH_LWIP)
#if (!defined(WITH_CONTIKI)) != ( defined(HAVE_NETINET_IN_H) || defined(HAVE_WS2TCPIP_H) )
/* define struct in6_pktinfo and struct in_pktinfo if not available
   FIXME: check with configure
*/
struct in6_pktinfo {
  struct in6_addr ipi6_addr;        /* src/dst IPv6 address */
  unsigned int ipi6_ifindex;        /* send/recv interface index */
};

struct in_pktinfo {
  int ipi_ifindex;
  struct in_addr ipi_spec_dst;
  struct in_addr ipi_addr;
};
#endif
#endif /* ! WITH_LWIP */

#if !defined(WITH_CONTIKI) && !defined(SOL_IP)
/* Solaris expects level IPPROTO_IP for ancillary data. */
#define SOL_IP IPPROTO_IP
#endif

#if defined(_WIN32)
#include <mswsock.h>
static __declspec(thread) LPFN_WSARECVMSG lpWSARecvMsg = NULL;
/* Map struct WSABUF fields to their posix counterpart */
#define msghdr _WSAMSG
#define msg_name name
#define msg_namelen namelen
#define msg_iov lpBuffers
#define msg_iovlen dwBufferCount
#define msg_control Control.buf
#define msg_controllen Control.len
#define iovec _WSABUF
#define iov_base buf
#define iov_len len
#define iov_len_t u_long
#undef CMSG_DATA
#define CMSG_DATA WSA_CMSG_DATA
#define ipi_spec_dst ipi_addr
#pragma warning( disable : 4116 )
#else
#define iov_len_t size_t
#endif

#if defined(_CYGWIN_ENV)
#define ipi_spec_dst ipi_addr
#endif

#if !defined(RIOT_VERSION) && !defined(WITH_LWIP) && !defined(WITH_CONTIKI)
/*
 * dgram
 * return +ve Number of bytes written.
 *         -1 Error error in errno).
 */
ssize_t
coap_socket_send(coap_socket_t *sock, const coap_session_t *session, const uint8_t *data, size_t datalen) {
  ssize_t bytes_written = 0;

  if (!coap_debug_send_packet()) {
    bytes_written = (ssize_t)datalen;
  } else if (sock->flags & COAP_SOCKET_CONNECTED) {
#ifdef _WIN32
    bytes_written = send(sock->fd, (const char *)data, (int)datalen, 0);
#else
    bytes_written = send(sock->fd, data, datalen, 0);
#endif
  } else {
#ifdef _WIN32
    DWORD dwNumberOfBytesSent = 0;
    int r;
#endif
#ifdef HAVE_STRUCT_CMSGHDR
    /* a buffer large enough to hold all packet info types, ipv6 is the largest */
    char buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
    struct msghdr mhdr;
    struct iovec iov[1];
    const void *addr = &session->addr_info.remote.addr;

    assert(session);

    memcpy (&iov[0].iov_base, &data, sizeof (iov[0].iov_base));
    iov[0].iov_len = (iov_len_t)datalen;

    memset(buf, 0, sizeof (buf));

    memset(&mhdr, 0, sizeof(struct msghdr));
    memcpy (&mhdr.msg_name, &addr, sizeof (mhdr.msg_name));
    mhdr.msg_namelen = session->addr_info.remote.size;

    mhdr.msg_iov = iov;
    mhdr.msg_iovlen = 1;

    if (!coap_address_isany(&session->addr_info.local) &&
        !coap_is_mcast(&session->addr_info.local))
    switch (session->addr_info.local.addr.sa.sa_family) {
    case AF_INET6:
    {
      struct cmsghdr *cmsg;

      if (IN6_IS_ADDR_V4MAPPED(&session->addr_info.local.addr.sin6.sin6_addr)) {
#if defined(IP_PKTINFO)
        struct in_pktinfo *pktinfo;
        mhdr.msg_control = buf;
        mhdr.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));

        cmsg = CMSG_FIRSTHDR(&mhdr);
        cmsg->cmsg_level = SOL_IP;
        cmsg->cmsg_type = IP_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

        pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);

        pktinfo->ipi_ifindex = session->ifindex;
        memcpy(&pktinfo->ipi_spec_dst,
               session->addr_info.local.addr.sin6.sin6_addr.s6_addr + 12,
               sizeof(pktinfo->ipi_spec_dst));
#elif defined(IP_SENDSRCADDR)
        mhdr.msg_control = buf;
        mhdr.msg_controllen = CMSG_SPACE(sizeof(struct in_addr));

        cmsg = CMSG_FIRSTHDR(&mhdr);
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_SENDSRCADDR;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_addr));

        memcpy(CMSG_DATA(cmsg),
               session->addr_info.local.addr.sin6.sin6_addr.s6_addr + 12,
               sizeof(struct in_addr));
#endif /* IP_PKTINFO */
      } else {
        struct in6_pktinfo *pktinfo;
        mhdr.msg_control = buf;
        mhdr.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));

        cmsg = CMSG_FIRSTHDR(&mhdr);
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

        pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);

        pktinfo->ipi6_ifindex = session->ifindex;
        memcpy(&pktinfo->ipi6_addr,
               &session->addr_info.local.addr.sin6.sin6_addr,
               sizeof(pktinfo->ipi6_addr));
      }
      break;
    }
    case AF_INET:
    {
#if defined(IP_PKTINFO)
      struct cmsghdr *cmsg;
      struct in_pktinfo *pktinfo;

      mhdr.msg_control = buf;
      mhdr.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));

      cmsg = CMSG_FIRSTHDR(&mhdr);
      cmsg->cmsg_level = SOL_IP;
      cmsg->cmsg_type = IP_PKTINFO;
      cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

      pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);

      pktinfo->ipi_ifindex = session->ifindex;
      memcpy(&pktinfo->ipi_spec_dst,
             &session->addr_info.local.addr.sin.sin_addr,
             sizeof(pktinfo->ipi_spec_dst));
#elif defined(IP_SENDSRCADDR)
      struct cmsghdr *cmsg;
      mhdr.msg_control = buf;
      mhdr.msg_controllen = CMSG_SPACE(sizeof(struct in_addr));

      cmsg = CMSG_FIRSTHDR(&mhdr);
      cmsg->cmsg_level = IPPROTO_IP;
      cmsg->cmsg_type = IP_SENDSRCADDR;
      cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_addr));

      memcpy(CMSG_DATA(cmsg),
             &session->addr_info.local.addr.sin.sin_addr,
             sizeof(struct in_addr));
#endif /* IP_PKTINFO */
      break;
    }
    case AF_UNIX:
      break;
    default:
      /* error */
      coap_log_warn("protocol not supported\n");
      bytes_written = -1;
    }
#endif /* HAVE_STRUCT_CMSGHDR */

#ifdef _WIN32
    r = WSASendMsg(sock->fd, &mhdr, 0 /*dwFlags*/, &dwNumberOfBytesSent, NULL /*lpOverlapped*/, NULL /*lpCompletionRoutine*/);
    if (r == 0)
      bytes_written = (ssize_t)dwNumberOfBytesSent;
    else
      bytes_written = -1;
#else
#ifdef HAVE_STRUCT_CMSGHDR
    bytes_written = sendmsg(sock->fd, &mhdr, 0);
#else /* ! HAVE_STRUCT_CMSGHDR */
    bytes_written = sendto(sock->fd, data, datalen, 0,
                           &session->addr_info.remote.addr.sa,
                           session->addr_info.remote.size);
#endif /* ! HAVE_STRUCT_CMSGHDR */
#endif
  }

  if (bytes_written < 0)
    coap_log_crit("coap_socket_send: %s\n", coap_socket_strerror());

  return bytes_written;
}
#endif /* ! RIOT_VERSION && ! WITH_LWIP && ! WITH_CONTIKI */

#define SIN6(A) ((struct sockaddr_in6 *)(A))

void
coap_packet_get_memmapped(coap_packet_t *packet, unsigned char **address, size_t *length) {
  *address = packet->payload;
  *length = packet->length;
}

#if !defined(RIOT_VERSION) && !defined(WITH_LWIP) && !defined(WITH_CONTIKI)
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
#ifdef _WIN32
    len = recv(sock->fd, (char *)packet->payload, COAP_RXBUFFER_SIZE, 0);
#else
    len = recv(sock->fd, packet->payload, COAP_RXBUFFER_SIZE, 0);
#endif
    if (len < 0) {
#ifdef _WIN32
      coap_win_error_to_errno();
      if (WSAGetLastError() == WSAECONNRESET ||
          WSAGetLastError() == WSAECONNREFUSED) {
#else
      if (errno == ECONNREFUSED || errno == EHOSTUNREACH) {
#endif
        /* client-side ICMP destination unreachable, ignore it */
        coap_log_warn("** %s: coap_socket_recv: ICMP: %s\n",
                 sock->session ?
                   coap_session_str(sock->session) : "",
                 coap_socket_strerror());
        return -2;
      }
      coap_log_warn("** %s: coap_socket_recv: %s\n",
                             sock->session ?
                                coap_session_str(sock->session) : "",
                             coap_socket_strerror());
      goto error;
    } else if (len > 0) {
      packet->length = (size_t)len;
    }
  } else {
#if defined(_WIN32)
    DWORD dwNumberOfBytesRecvd = 0;
    int r;
#endif
#ifdef HAVE_STRUCT_CMSGHDR
    /* a buffer large enough to hold all packet info types, ipv6 is the largest */
    char buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
    struct cmsghdr *cmsg;
    struct msghdr mhdr;
    struct iovec iov[1];

    iov[0].iov_base = packet->payload;
    iov[0].iov_len = (iov_len_t)COAP_RXBUFFER_SIZE;

    memset(&mhdr, 0, sizeof(struct msghdr));

    mhdr.msg_name = (struct sockaddr*)&packet->addr_info.remote.addr;
    mhdr.msg_namelen = sizeof(packet->addr_info.remote.addr);

    mhdr.msg_iov = iov;
    mhdr.msg_iovlen = 1;

    mhdr.msg_control = buf;
    mhdr.msg_controllen = sizeof(buf);
    /* set a big first length incase recvmsg() does not implement updating
       msg_control as well as preset the first cmsg with bad data */
    cmsg = (struct cmsghdr *)buf;
    cmsg->cmsg_len = CMSG_LEN(sizeof(buf));
    cmsg->cmsg_level = -1;
    cmsg->cmsg_type = -1;

#if defined(_WIN32)
    if (!lpWSARecvMsg) {
      GUID wsaid = WSAID_WSARECVMSG;
      DWORD cbBytesReturned = 0;
      if (WSAIoctl(sock->fd, SIO_GET_EXTENSION_FUNCTION_POINTER, &wsaid, sizeof(wsaid), &lpWSARecvMsg, sizeof(lpWSARecvMsg), &cbBytesReturned, NULL, NULL) != 0) {
        coap_log_warn("coap_socket_recv: no WSARecvMsg\n");
        return -1;
      }
    }
    r = lpWSARecvMsg(sock->fd, &mhdr, &dwNumberOfBytesRecvd, NULL /* LPWSAOVERLAPPED */, NULL /* LPWSAOVERLAPPED_COMPLETION_ROUTINE */);
    if (r == 0)
      len = (ssize_t)dwNumberOfBytesRecvd;
#else
    len = recvmsg(sock->fd, &mhdr, 0);
#endif

#else /* ! HAVE_STRUCT_CMSGHDR */
    len = recvfrom(sock->fd, packet->payload, COAP_RXBUFFER_SIZE, 0,
                   &packet->addr_info.remote.addr.sa,
                   &packet->addr_info.remote.size);
#endif /* ! HAVE_STRUCT_CMSGHDR */

    if (len < 0) {
#ifdef _WIN32
      coap_win_error_to_errno();
      if (WSAGetLastError() == WSAECONNRESET) {
#else
      if (errno == ECONNREFUSED) {
#endif
        /* server-side ICMP destination unreachable, ignore it. The destination address is in msg_name. */
        return 0;
      }
      coap_log_warn("coap_socket_recv: %s\n", coap_socket_strerror());
      goto error;
    } else {
#ifdef HAVE_STRUCT_CMSGHDR
      int dst_found = 0;

      packet->addr_info.remote.size = mhdr.msg_namelen;
      packet->length = (size_t)len;

      /* Walk through ancillary data records until the local interface
       * is found where the data was received. */
      for (cmsg = CMSG_FIRSTHDR(&mhdr); cmsg; cmsg = CMSG_NXTHDR(&mhdr, cmsg)) {

        /* get the local interface for IPv6 */
        if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
          union {
            uint8_t *c;
            struct in6_pktinfo *p;
          } u;
          u.c = CMSG_DATA(cmsg);
          packet->ifindex = (int)(u.p->ipi6_ifindex);
          memcpy(&packet->addr_info.local.addr.sin6.sin6_addr,
                 &u.p->ipi6_addr, sizeof(struct in6_addr));
          dst_found = 1;
          break;
        }

        /* local interface for IPv4 */
#if defined(IP_PKTINFO)
        if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_PKTINFO) {
          union {
            uint8_t *c;
            struct in_pktinfo *p;
          } u;
          u.c = CMSG_DATA(cmsg);
          packet->ifindex = u.p->ipi_ifindex;
          if (packet->addr_info.local.addr.sa.sa_family == AF_INET6) {
            memset(packet->addr_info.local.addr.sin6.sin6_addr.s6_addr, 0, 10);
            packet->addr_info.local.addr.sin6.sin6_addr.s6_addr[10] = 0xff;
            packet->addr_info.local.addr.sin6.sin6_addr.s6_addr[11] = 0xff;
            memcpy(packet->addr_info.local.addr.sin6.sin6_addr.s6_addr + 12,
                   &u.p->ipi_addr, sizeof(struct in_addr));
          } else {
            memcpy(&packet->addr_info.local.addr.sin.sin_addr,
                   &u.p->ipi_addr, sizeof(struct in_addr));
          }
          dst_found = 1;
          break;
        }
#elif defined(IP_RECVDSTADDR)
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_RECVDSTADDR) {
          packet->ifindex = sock->fd;
          memcpy(&packet->addr_info.local.addr.sin.sin_addr,
                 CMSG_DATA(cmsg), sizeof(struct in_addr));
          dst_found = 1;
          break;
        }
#endif /* IP_PKTINFO */
        if (!dst_found) {
          /* cmsg_level / cmsg_type combination we do not understand
             (ignore preset case for bad recvmsg() not updating cmsg) */
          if (cmsg->cmsg_level != -1 && cmsg->cmsg_type != -1) {
            coap_log_debug(
                     "cmsg_level = %d and cmsg_type = %d not supported - fix\n",
                     cmsg->cmsg_level, cmsg->cmsg_type);
          }
        }
      }
      if (!dst_found) {
        /* Not expected, but cmsg_level and cmsg_type don't match above and
           may need a new case */
        packet->ifindex = (int)sock->fd;
        if (getsockname(sock->fd, &packet->addr_info.local.addr.sa,
            &packet->addr_info.local.size) < 0) {
          coap_log_debug("Cannot determine local port\n");
        }
      }
#else /* ! HAVE_STRUCT_CMSGHDR */
      packet->length = (size_t)len;
      packet->ifindex = 0;
      if (getsockname(sock->fd, &packet->addr_info.local.addr.sa,
                      &packet->addr_info.local.size) < 0) {
         coap_log_debug("Cannot determine local port\n");
         goto error;
      }
#endif /* ! HAVE_STRUCT_CMSGHDR */
    }
  }

  if (len >= 0)
    return len;
error:
  return -1;
}
#endif /* ! RIOT_VERSION && ! WITH_LWIP && ! WITH_CONTIKI */

unsigned int
coap_io_prepare_epoll(coap_context_t *ctx, coap_tick_t now) {
#ifndef COAP_EPOLL_SUPPORT
  (void)ctx;
  (void)now;
   coap_log_emerg(
            "coap_io_prepare_epoll() requires libcoap compiled for using epoll\n");
  return 0;
#else /* COAP_EPOLL_SUPPORT */
  coap_socket_t *sockets[1];
  unsigned int max_sockets = sizeof(sockets)/sizeof(sockets[0]);
  unsigned int num_sockets;
  unsigned int timeout;

  /* Use the common logic */
  timeout = coap_io_prepare_io(ctx, sockets, max_sockets, &num_sockets, now);
  /* Save when the next expected I/O is to take place */
  ctx->next_timeout = timeout ? now + timeout : 0;
  if (ctx->eptimerfd != -1) {
    struct itimerspec new_value;
    int ret;

    memset(&new_value, 0, sizeof(new_value));
    coap_ticks(&now);
    if (ctx->next_timeout != 0 && ctx->next_timeout > now) {
      coap_tick_t rem_timeout = ctx->next_timeout - now;
      /* Need to trigger an event on ctx->eptimerfd in the future */
      new_value.it_value.tv_sec = rem_timeout / COAP_TICKS_PER_SECOND;
      new_value.it_value.tv_nsec = (rem_timeout % COAP_TICKS_PER_SECOND) *
                                   1000000;
    }
#ifdef COAP_DEBUG_WAKEUP_TIMES
    coap_log_debug("****** Next wakeup time %3ld.%09ld\n",
                   new_value.it_value.tv_sec, new_value.it_value.tv_nsec);
#endif /* COAP_DEBUG_WAKEUP_TIMES */
    /* reset, or specify a future time for eptimerfd to trigger */
    ret = timerfd_settime(ctx->eptimerfd, 0, &new_value, NULL);
    if (ret == -1) {
      coap_log_err(
                "%s: timerfd_settime failed: %s (%d)\n",
                "coap_io_prepare_epoll",
                coap_socket_strerror(), errno);
    }
  }
  return timeout;
#endif /* COAP_EPOLL_SUPPORT */
}

/*
 * return  0 No i/o pending
 *       +ve millisecs to next i/o activity
 */
unsigned int
coap_io_prepare_io(coap_context_t *ctx,
                   coap_socket_t *sockets[],
                   unsigned int max_sockets,
                   unsigned int *num_sockets,
                   coap_tick_t now) {
  coap_queue_t *nextpdu;
  coap_session_t *s, *rtmp;
  coap_tick_t timeout = 0;
  coap_tick_t s_timeout;
#if COAP_SERVER_SUPPORT
  int check_dtls_timeouts = 0;
#endif /* COAP_SERVER_SUPPORT */
#if defined(COAP_EPOLL_SUPPORT) || defined(WITH_LWIP)
  (void)sockets;
  (void)max_sockets;
#endif /* COAP_EPOLL_SUPPORT || WITH_LWIP */

  *num_sockets = 0;

#if COAP_SERVER_SUPPORT
  /* Check to see if we need to send off any Observe requests */
  coap_check_notify(ctx);
#endif /* COAP_SERVER_SUPPORT */

#ifndef WITHOUT_ASYNC
  /* Check to see if we need to send off any Async requests */
  timeout = coap_check_async(ctx, now);
#endif /* WITHOUT_ASYNC */

  /* Check to see if we need to send off any retransmit request */
  nextpdu = coap_peek_next(ctx);
  while (nextpdu && now >= ctx->sendqueue_basetime &&
         nextpdu->t <= now - ctx->sendqueue_basetime) {
    coap_retransmit(ctx, coap_pop_next(ctx));
    nextpdu = coap_peek_next(ctx);
  }
  if (nextpdu && (timeout == 0 ||
      nextpdu->t - (now - ctx->sendqueue_basetime) < timeout))
    timeout = nextpdu->t - (now - ctx->sendqueue_basetime);

  /* Check for DTLS timeouts */
  if (ctx->dtls_context) {
    if (coap_dtls_is_context_timeout()) {
      coap_tick_t tls_timeout = coap_dtls_get_context_timeout(ctx->dtls_context);
      if (tls_timeout > 0) {
        if (tls_timeout < now + COAP_TICKS_PER_SECOND / 10)
          tls_timeout = now + COAP_TICKS_PER_SECOND / 10;
        coap_log_debug("** DTLS global timeout set to %dms\n",
                 (int)((tls_timeout - now) * 1000 / COAP_TICKS_PER_SECOND));
        if (timeout == 0 || tls_timeout - now < timeout)
          timeout = tls_timeout - now;
      }
#if COAP_SERVER_SUPPORT
    } else {
      check_dtls_timeouts = 1;
#endif /* COAP_SERVER_SUPPORT */
    }
  }
#if COAP_SERVER_SUPPORT
  coap_endpoint_t *ep;
  coap_tick_t session_timeout;

  if (ctx->session_timeout > 0)
    session_timeout = ctx->session_timeout * COAP_TICKS_PER_SECOND;
  else
    session_timeout = COAP_DEFAULT_SESSION_TIMEOUT * COAP_TICKS_PER_SECOND;

  LL_FOREACH(ctx->endpoint, ep) {
#if !defined(COAP_EPOLL_SUPPORT) && !defined(WITH_LWIP)
    if (ep->sock.flags & (COAP_SOCKET_WANT_READ | COAP_SOCKET_WANT_WRITE | COAP_SOCKET_WANT_ACCEPT)) {
      if (*num_sockets < max_sockets)
        sockets[(*num_sockets)++] = &ep->sock;
    }
#endif /* ! COAP_EPOLL_SUPPORT i && ! WITH_LWIP */
    SESSIONS_ITER_SAFE(ep->sessions, s, rtmp) {
      /* Check whether any idle server sessions should be released */
      if (s->type == COAP_SESSION_TYPE_SERVER && s->ref == 0 &&
          s->delayqueue == NULL &&
          (s->last_rx_tx + session_timeout <= now ||
           s->state == COAP_SESSION_STATE_NONE)) {
        coap_handle_event(ctx, COAP_EVENT_SERVER_SESSION_DEL, s);
        coap_session_free(s);
      } else {
        if (s->type == COAP_SESSION_TYPE_SERVER && s->ref == 0 &&
            s->delayqueue == NULL) {
          s_timeout = (s->last_rx_tx + session_timeout) - now;
          if (timeout == 0 || s_timeout < timeout)
            timeout = s_timeout;
        }
        /* Make sure the session object is not deleted in any callbacks */
        coap_session_reference(s);
        /* Check any DTLS timeouts and expire if appropriate */
        if (check_dtls_timeouts && s->state == COAP_SESSION_STATE_HANDSHAKE &&
            s->proto == COAP_PROTO_DTLS && s->tls) {
          coap_tick_t tls_timeout = coap_dtls_get_timeout(s, now);
          while (tls_timeout > 0 && tls_timeout <= now) {
            coap_log_debug("** %s: DTLS retransmit timeout\n",
                     coap_session_str(s));
            if (coap_dtls_handle_timeout(s))
              goto release_1;

            if (s->tls)
              tls_timeout = coap_dtls_get_timeout(s, now);
            else {
              tls_timeout = 0;
              timeout = 1;
            }
          }
          if (tls_timeout > 0 && (timeout == 0 || tls_timeout - now < timeout))
            timeout = tls_timeout - now;
        }
        /* Check if any server large receives have timed out */
        if (s->lg_srcv) {
          if (coap_block_check_lg_srcv_timeouts(s, now, &s_timeout)) {
            if (timeout == 0 || s_timeout < timeout)
              timeout = s_timeout;
          }
        }
        /* Check if any server large sending have timed out */
        if (s->lg_xmit) {
          if (coap_block_check_lg_xmit_timeouts(s, now, &s_timeout)) {
            if (timeout == 0 || s_timeout < timeout)
              timeout = s_timeout;
          }
        }
#if !defined(COAP_EPOLL_SUPPORT) && !defined(WITH_LWIP)
        if (s->sock.flags & (COAP_SOCKET_WANT_READ|COAP_SOCKET_WANT_WRITE)) {
          if (*num_sockets < max_sockets)
            sockets[(*num_sockets)++] = &s->sock;
        }
#endif /* ! COAP_EPOLL_SUPPORT && ! WITH_LWIP */
release_1:
        coap_session_release(s);
      }
    }
  }
#endif /* COAP_SERVER_SUPPORT */
#if COAP_CLIENT_SUPPORT
  SESSIONS_ITER_SAFE(ctx->sessions, s, rtmp) {
    if (s->type == COAP_SESSION_TYPE_CLIENT &&
        s->state == COAP_SESSION_STATE_ESTABLISHED &&
        ctx->ping_timeout > 0) {
      if (s->last_rx_tx + ctx->ping_timeout * COAP_TICKS_PER_SECOND <= now) {
        if ((s->last_ping > 0 && s->last_pong < s->last_ping) ||
            ((s->last_ping_mid = coap_session_send_ping(s)) == COAP_INVALID_MID))
        {
          /* Make sure the session object is not deleted in the callback */
          coap_session_reference(s);
          coap_session_disconnected(s, COAP_NACK_NOT_DELIVERABLE);
          coap_session_release(s);
          continue;
        }
        s->last_rx_tx = now;
        s->last_ping = now;
      }
      s_timeout = (s->last_rx_tx + ctx->ping_timeout * COAP_TICKS_PER_SECOND) - now;
      if (timeout == 0 || s_timeout < timeout)
        timeout = s_timeout;
    }

#if !COAP_DISABLE_TCP
    if (s->type == COAP_SESSION_TYPE_CLIENT && COAP_PROTO_RELIABLE(s->proto) &&
        s->state == COAP_SESSION_STATE_CSM && ctx->csm_timeout > 0) {
      if (s->csm_tx == 0) {
        s->csm_tx = now;
      } else if (s->csm_tx + ctx->csm_timeout * COAP_TICKS_PER_SECOND <= now) {
        /* Make sure the session object is not deleted in the callback */
        coap_session_reference(s);
        coap_session_disconnected(s, COAP_NACK_NOT_DELIVERABLE);
        coap_session_release(s);
        continue;
      }
      s_timeout = (s->csm_tx + ctx->csm_timeout * COAP_TICKS_PER_SECOND) - now;
      if (timeout == 0 || s_timeout < timeout)
        timeout = s_timeout;
    }
#endif /* !COAP_DISABLE_TCP */

    /* Make sure the session object is not deleted in any callbacks */
    coap_session_reference(s);
    /* Check any DTLS timeouts and expire if appropriate */
    if (s->state == COAP_SESSION_STATE_HANDSHAKE &&
        s->proto == COAP_PROTO_DTLS && s->tls) {
      coap_tick_t tls_timeout = coap_dtls_get_timeout(s, now);
      while (tls_timeout > 0 && tls_timeout <= now) {
        coap_log_debug("** %s: DTLS retransmit timeout\n", coap_session_str(s));
        if (coap_dtls_handle_timeout(s))
          goto release_2;

        if (s->tls)
          tls_timeout = coap_dtls_get_timeout(s, now);
        else {
          tls_timeout = 0;
          timeout = 1;
        }
      }
      if (tls_timeout > 0 && (timeout == 0 || tls_timeout - now < timeout))
        timeout = tls_timeout - now;
    }

    /* Check if any client large receives have timed out */
    if (s->lg_crcv) {
      if (coap_block_check_lg_crcv_timeouts(s, now, &s_timeout)) {
        if (timeout == 0 || s_timeout < timeout)
          timeout = s_timeout;
      }
    }
    /* Check if any client large sending have timed out */
    if (s->lg_xmit) {
      if (coap_block_check_lg_xmit_timeouts(s, now, &s_timeout)) {
        if (timeout == 0 || s_timeout < timeout)
          timeout = s_timeout;
      }
    }

#if !defined(COAP_EPOLL_SUPPORT) && !defined(WITHLWIP)
    assert(s->ref > 1);
    if (s->sock.flags & (COAP_SOCKET_WANT_READ |
                         COAP_SOCKET_WANT_WRITE |
                         COAP_SOCKET_WANT_CONNECT)) {
      if (*num_sockets < max_sockets)
        sockets[(*num_sockets)++] = &s->sock;
    }
#endif /* ! COAP_EPOLL_SUPPORT && ! WITH_LWIP */
release_2:
    coap_session_release(s);
  }
#endif /* COAP_CLIENT_SUPPORT */

  return (unsigned int)((timeout * 1000 + COAP_TICKS_PER_SECOND - 1) / COAP_TICKS_PER_SECOND);
}

#if !defined(RIOT_VERSION) && !defined(WITH_LWIP) && !defined(CONTIKI)
int
coap_io_process(coap_context_t *ctx, uint32_t timeout_ms) {
  return coap_io_process_with_fds(ctx, timeout_ms, 0, NULL, NULL, NULL);
}

int
coap_io_process_with_fds(coap_context_t *ctx, uint32_t timeout_ms,
                         int enfds, fd_set *ereadfds, fd_set *ewritefds,
                         fd_set *eexceptfds) {
  coap_fd_t nfds = 0;
  coap_tick_t before, now;
  unsigned int timeout;
#ifndef COAP_EPOLL_SUPPORT
  struct timeval tv;
  int result;
  unsigned int i;
#endif /* ! COAP_EPOLL_SUPPORT */

  coap_ticks(&before);

#ifndef COAP_EPOLL_SUPPORT

  timeout = coap_io_prepare_io(ctx, ctx->sockets,
                            (sizeof(ctx->sockets) / sizeof(ctx->sockets[0])),
                            &ctx->num_sockets, before);
  if (timeout == 0 || timeout_ms < timeout)
    timeout = timeout_ms;

  if (ereadfds) {
    ctx->readfds = *ereadfds;
    nfds = enfds;
  }
  else {
    FD_ZERO(&ctx->readfds);
  }
  if (ewritefds) {
    ctx->writefds = *ewritefds;
    nfds = enfds;
  }
  else {
    FD_ZERO(&ctx->writefds);
  }
  if (eexceptfds) {
    ctx->exceptfds = *eexceptfds;
    nfds = enfds;
  }
  else {
    FD_ZERO(&ctx->exceptfds);
  }
  for (i = 0; i < ctx->num_sockets; i++) {
    if (ctx->sockets[i]->fd + 1 > nfds)
      nfds = ctx->sockets[i]->fd + 1;
    if (ctx->sockets[i]->flags & COAP_SOCKET_WANT_READ)
      FD_SET(ctx->sockets[i]->fd, &ctx->readfds);
    if (ctx->sockets[i]->flags & COAP_SOCKET_WANT_WRITE)
      FD_SET(ctx->sockets[i]->fd, &ctx->writefds);
#if !COAP_DISABLE_TCP
    if (ctx->sockets[i]->flags & COAP_SOCKET_WANT_ACCEPT)
      FD_SET(ctx->sockets[i]->fd, &ctx->readfds);
    if (ctx->sockets[i]->flags & COAP_SOCKET_WANT_CONNECT) {
      FD_SET(ctx->sockets[i]->fd, &ctx->writefds);
      FD_SET(ctx->sockets[i]->fd, &ctx->exceptfds);
    }
#endif /* !COAP_DISABLE_TCP */
  }

  if (timeout_ms == COAP_IO_NO_WAIT) {
    tv.tv_usec = 0;
    tv.tv_sec = 0;
    timeout = 1;
  }
  else if (timeout > 0) {
    tv.tv_usec = (timeout % 1000) * 1000;
    tv.tv_sec = (long)(timeout / 1000);
  }

  result = select((int)nfds, &ctx->readfds, &ctx->writefds, &ctx->exceptfds,
                  timeout > 0 ? &tv : NULL);

  if (result < 0) {   /* error */
#ifdef _WIN32
    coap_win_error_to_errno();
    if (WSAGetLastError() != WSAEINVAL) /* May happen because of ICMP */
#else
    if (errno != EINTR)
#endif
    {
      coap_log_debug("%s", coap_socket_strerror());
      return -1;
    }
  }
  if (ereadfds) {
    *ereadfds = ctx->readfds;
  }
  if (ewritefds) {
    *ewritefds = ctx->writefds;
  }
  if (eexceptfds) {
    *eexceptfds = ctx->exceptfds;
  }

  if (result > 0) {
    for (i = 0; i < ctx->num_sockets; i++) {
      if ((ctx->sockets[i]->flags & COAP_SOCKET_WANT_READ) &&
          FD_ISSET(ctx->sockets[i]->fd, &ctx->readfds))
        ctx->sockets[i]->flags |= COAP_SOCKET_CAN_READ;
#if !COAP_DISABLE_TCP
      if ((ctx->sockets[i]->flags & COAP_SOCKET_WANT_ACCEPT) &&
          FD_ISSET(ctx->sockets[i]->fd, &ctx->readfds))
        ctx->sockets[i]->flags |= COAP_SOCKET_CAN_ACCEPT;
      if ((ctx->sockets[i]->flags & COAP_SOCKET_WANT_WRITE) &&
          FD_ISSET(ctx->sockets[i]->fd, &ctx->writefds))
        ctx->sockets[i]->flags |= COAP_SOCKET_CAN_WRITE;
      if ((ctx->sockets[i]->flags & COAP_SOCKET_WANT_CONNECT) &&
          (FD_ISSET(ctx->sockets[i]->fd, &ctx->writefds) ||
           FD_ISSET(ctx->sockets[i]->fd, &ctx->exceptfds)))
        ctx->sockets[i]->flags |= COAP_SOCKET_CAN_CONNECT;
#endif /* !COAP_DISABLE_TCP */
    }
  }

  coap_ticks(&now);
  coap_io_do_io(ctx, now);

#else /* COAP_EPOLL_SUPPORT */
  (void)ereadfds;
  (void)ewritefds;
  (void)eexceptfds;
  (void)enfds;

  timeout = coap_io_prepare_epoll(ctx, before);

  if (timeout == 0 || timeout_ms < timeout)
    timeout = timeout_ms;

  do {
    struct epoll_event events[COAP_MAX_EPOLL_EVENTS];
    int etimeout = timeout;

    /* Potentially adjust based on what the caller wants */
    if (timeout_ms == COAP_IO_NO_WAIT) {
      etimeout = 0;
    }
    else if (timeout == COAP_IO_WAIT) {
      /* coap_io_prepare_epoll() returned 0 and timeout_ms COAP_IO_WAIT (0) */
      etimeout = -1;
    }
    else if (etimeout < 0) {
     /* epoll_wait cannot wait longer than this as int timeout parameter */
      etimeout = INT_MAX;
    }

    nfds = epoll_wait(ctx->epfd, events, COAP_MAX_EPOLL_EVENTS, etimeout);
    if (nfds < 0) {
      if (errno != EINTR) {
        coap_log (COAP_LOG_ERR, "epoll_wait: unexpected error: %s (%d)\n",
                            coap_socket_strerror(), nfds);
      }
      break;
    }

    coap_io_do_epoll(ctx, events, nfds);

    /*
     * reset to COAP_IO_NO_WAIT (which causes etimeout to become 0)
     * incase we have to do another iteration
     * (COAP_MAX_EPOLL_EVENTS insufficient)
     */
    timeout_ms = COAP_IO_NO_WAIT;

    /* Keep retrying until less than COAP_MAX_EPOLL_EVENTS are returned */
  } while (nfds == COAP_MAX_EPOLL_EVENTS);

#endif /* COAP_EPOLL_SUPPORT */
#if COAP_SERVER_SUPPORT
  coap_expire_cache_entries(ctx);
#endif /* COAP_SERVER_SUPPORT */
  coap_ticks(&now);
#ifndef WITHOUT_ASYNC
  /* Check to see if we need to send off any Async requests as delay might
     have been updated */
  coap_check_async(ctx, now);
  coap_ticks(&now);
#endif /* WITHOUT_ASYNC */

  return (int)(((now - before) * 1000) / COAP_TICKS_PER_SECOND);
}
#endif /* ! RIOT_VERSION && ! WITH_LWIP && ! WITH_CONTIKI */

/*
 * return 1  I/O pending
 *        0  No I/O pending
 */
int
coap_io_pending(coap_context_t *context) {
  coap_session_t *s, *rtmp;
#if COAP_SERVER_SUPPORT
  coap_endpoint_t *ep;
#endif /* COAP_SERVER_SUPPORT */

  if (!context)
    return 0;
  if (coap_io_process(context, COAP_IO_NO_WAIT) < 0)
    return 0;

  if (context->sendqueue)
    return 1;
#if COAP_SERVER_SUPPORT
  LL_FOREACH(context->endpoint, ep) {
    SESSIONS_ITER(ep->sessions, s, rtmp) {
      if (s->delayqueue)
        return 1;
      if (s->lg_xmit)
        return 1;
      if (s->lg_srcv)
        return 1;
    }
  }
#endif /* COAP_SERVER_SUPPORT */
#if COAP_CLIENT_SUPPORT
  SESSIONS_ITER(context->sessions, s, rtmp) {
    if (s->delayqueue)
      return 1;
    if (s->lg_xmit)
      return 1;
    if (s->lg_crcv)
      return 1;
  }
#endif /* COAP_CLIENT_SUPPORT */
  return 0;
}

#ifdef _WIN32
const char *coap_socket_format_errno(int error) {
  static char szError[256];
  if (FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, (DWORD)error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)szError, (DWORD)sizeof(szError), NULL) == 0)
    strcpy(szError, "Unknown error");
  return szError;
}

const char *coap_socket_strerror(void) {
  return coap_socket_format_errno(WSAGetLastError());
}
#else /* _WIN32 */
const char *coap_socket_format_errno(int error) {
  return strerror(error);
}
const char *coap_socket_strerror(void) {
  return coap_socket_format_errno(errno);
}
#endif /* _WIN32 */

#undef SIN6
