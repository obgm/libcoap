/*
 * coap_dgrm_posix.c -- Datagram (UDP) functions for libcoap
 *
 * Copyright (C) 2019-2025 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_dgrm_posix.c
 * @brief Posix CoAP Datagram (UDP) handling functions
 */

#include "coap3/coap_libcoap_build.h"

#if ! defined(WITH_LWIP) && ! defined(WITH_CONTIKI) && ! defined (RIOT_VERSION)

#ifdef HAVE_STDIO_H
#  include <stdio.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifndef __ZEPHYR__
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
#ifdef _WIN32
#include <stdio.h>
#endif /* _WIN32 */
#ifdef COAP_EPOLL_SUPPORT
#include <sys/epoll.h>
#include <sys/timerfd.h>
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#endif /* COAP_EPOLL_SUPPORT */
#else /* __ZEPHYR__ */
#include <sys/ioctl.h>
#include <sys/select.h>
#define OPTVAL_T(t)         (const void*)(t)
#define OPTVAL_GT(t)        (void*)(t)

#ifndef IPV6_PKTINFO
#ifdef IPV6_RECVPKTINFO
#define IPV6_PKTINFO IPV6_RECVPKTINFO
#else
#define IPV6_PKTINFO IP_PKTINFO
#endif
#ifndef IN6_IS_ADDR_V4MAPPED
#define IN6_IS_ADDR_V4MAPPED(a) \
  ((((a)->s6_addr32[0]) == 0) && (((a)->s6_addr32[1]) == 0) && \
   (((a)->s6_addr32[2]) == htonl(0xffff)))
#endif
#endif
#endif /* __ZEPHYR__ */

/* define generic PKTINFO for IPv4 */
#if defined(IP_PKTINFO)
#  define GEN_IP_PKTINFO IP_PKTINFO
#elif defined(IP_RECVDSTADDR)
#  define GEN_IP_PKTINFO IP_RECVDSTADDR
#else
#  error "Need IP_PKTINFO or IP_RECVDSTADDR to request ancillary data from OS."
#endif /* IP_PKTINFO */

/* define generic PKTINFO for IPv6 */
#ifdef IPV6_RECVPKTINFO
#  define GEN_IPV6_PKTINFO IPV6_RECVPKTINFO
#elif defined(IPV6_PKTINFO)
#  define GEN_IPV6_PKTINFO IPV6_PKTINFO
#else
#  error "Need IPV6_PKTINFO or IPV6_RECVPKTINFO to request ancillary data from OS."
#endif /* IPV6_RECVPKTINFO */

#if COAP_SERVER_SUPPORT
int
coap_socket_bind_udp(coap_socket_t *sock,
                     const coap_address_t *listen_addr,
                     coap_address_t *bound_addr) {
  int on = 1;
#if COAP_IPV6_SUPPORT
  int off = 0;
#endif /* COAP_IPV6_SUPPORT */
#ifdef _WIN32
  u_long u_on = 1;
#endif

  sock->fd = socket(listen_addr->addr.sa.sa_family, SOCK_DGRAM, 0);

  if (sock->fd == COAP_INVALID_SOCKET) {
    coap_log_warn("coap_socket_bind_udp: socket: %s\n", coap_socket_strerror());
    goto error;
  }
#ifdef _WIN32
  if (ioctlsocket(sock->fd, FIONBIO, &u_on) == COAP_SOCKET_ERROR)
#else
  if (ioctl(sock->fd, FIONBIO, &on) == COAP_SOCKET_ERROR)
#endif
  {
    coap_log_warn("coap_socket_bind_udp: ioctl FIONBIO: %s\n", coap_socket_strerror());
  }

  if (setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR, OPTVAL_T(&on), sizeof(on)) == COAP_SOCKET_ERROR)
    coap_log_warn("coap_socket_bind_udp: setsockopt SO_REUSEADDR: %s\n",
                  coap_socket_strerror());

  switch (listen_addr->addr.sa.sa_family) {
#if COAP_IPV4_SUPPORT
  case AF_INET:
    if (setsockopt(sock->fd, IPPROTO_IP, GEN_IP_PKTINFO, OPTVAL_T(&on),
                   sizeof(on)) == COAP_SOCKET_ERROR)
      coap_log_alert("coap_socket_bind_udp: setsockopt IP_PKTINFO: %s\n",
                     coap_socket_strerror());
    break;
#endif /* COAP_IPV4_SUPPORT */
#if COAP_IPV6_SUPPORT
  case AF_INET6:
    /* Configure the socket as dual-stacked */
    if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_V6ONLY, OPTVAL_T(&off),
                   sizeof(off)) == COAP_SOCKET_ERROR)
      coap_log_alert("coap_socket_bind_udp: setsockopt IPV6_V6ONLY: %s\n",
                     coap_socket_strerror());
#if !defined(ESPIDF_VERSION)
    if (setsockopt(sock->fd, IPPROTO_IPV6, GEN_IPV6_PKTINFO, OPTVAL_T(&on),
                   sizeof(on)) == COAP_SOCKET_ERROR)
      coap_log_alert("coap_socket_bind_udp: setsockopt IPV6_PKTINFO: %s\n",
                     coap_socket_strerror());
#endif /* !defined(ESPIDF_VERSION) */
#endif /* COAP_IPV6_SUPPORT */
    setsockopt(sock->fd, IPPROTO_IP, GEN_IP_PKTINFO, OPTVAL_T(&on), sizeof(on));
    /* ignore error, because likely cause is that IPv4 is disabled at the os
       level */
    break;
#if COAP_AF_UNIX_SUPPORT
  case AF_UNIX:
    break;
#endif /* COAP_AF_UNIX_SUPPORT */
  default:
    coap_log_alert("coap_socket_bind_udp: unsupported sa_family\n");
    break;
  }

  if (bind(sock->fd, &listen_addr->addr.sa,
#if COAP_IPV4_SUPPORT
           listen_addr->addr.sa.sa_family == AF_INET ?
           (socklen_t)sizeof(struct sockaddr_in) :
#endif /* COAP_IPV4_SUPPORT */
           (socklen_t)listen_addr->size) == COAP_SOCKET_ERROR) {
    coap_log_warn("coap_socket_bind_udp: bind: %s\n",
                  coap_socket_strerror());
    goto error;
  }

  bound_addr->size = (socklen_t)sizeof(*bound_addr);
  if (getsockname(sock->fd, &bound_addr->addr.sa, &bound_addr->size) < 0) {
    coap_log_warn("coap_socket_bind_udp: getsockname: %s\n",
                  coap_socket_strerror());
    goto error;
  }
  return 1;

error:
  coap_socket_dgrm_close(sock);
  return 0;
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
  int on = 1;
#if COAP_IPV6_SUPPORT
  int off = 0;
#endif /* COAP_IPV6_SUPPORT */
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

#ifdef _WIN32
  if (ioctlsocket(sock->fd, FIONBIO, &u_on) == COAP_SOCKET_ERROR)
#else
  if (ioctl(sock->fd, FIONBIO, &on) == COAP_SOCKET_ERROR)
#endif
  {
    /* Ignore Zephyr unexpected Success response */
    if (errno != 0) {
      int keep_errno = errno;

      coap_log_warn("coap_socket_connect_udp: ioctl FIONBIO: %s (%d)\n",
                    coap_socket_strerror(), keep_errno);
    }
  }

  switch (connect_addr.addr.sa.sa_family) {
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
      if (errno != ENOSYS) {
        coap_log_warn("coap_socket_connect_udp: setsockopt IPV6_V6ONLY: %s\n",
                      coap_socket_strerror());
      }
#endif /* COAP_IPV6_SUPPORT */
    break;
#if COAP_AF_UNIX_SUPPORT
  case AF_UNIX:
    break;
#endif /* COAP_AF_UNIX_SUPPORT */
  default:
    coap_log_alert("coap_socket_connect_udp: unsupported sa_family %d\n",
                   connect_addr.addr.sa.sa_family);
    goto error;;
  }

  if (local_if && local_if->addr.sa.sa_family) {
    if (local_if->addr.sa.sa_family != connect_addr.addr.sa.sa_family) {
      coap_log_warn("coap_socket_connect_udp: local address family != "
                    "remote address family\n");
      goto error;
    }
    if (setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR, OPTVAL_T(&on), sizeof(on)) == COAP_SOCKET_ERROR)
      coap_log_warn("coap_socket_connect_udp: setsockopt SO_REUSEADDR: %s\n",
                    coap_socket_strerror());
    if (bind(sock->fd, &local_if->addr.sa,
#if COAP_IPV4_SUPPORT
             local_if->addr.sa.sa_family == AF_INET ?
             (socklen_t)sizeof(struct sockaddr_in) :
#endif /* COAP_IPV4_SUPPORT */
             (socklen_t)local_if->size) == COAP_SOCKET_ERROR) {
      coap_log_warn("coap_socket_connect_udp: bind: %s\n",
                    coap_socket_strerror());
      goto error;
    }
#if COAP_AF_UNIX_SUPPORT
  } else if (connect_addr.addr.sa.sa_family == AF_UNIX) {
    /* Need to bind to a local address for clarity over endpoints */
    coap_log_warn("coap_socket_connect_udp: local address required\n");
    goto error;
#endif /* COAP_AF_UNIX_SUPPORT */
  }

  /* special treatment for sockets that are used for multicast communication */
  if (is_mcast) {
    if (!(local_if && local_if->addr.sa.sa_family)) {
      /* Bind to a (unused) port to simplify logging */
      coap_address_t bind_addr;

      coap_address_init(&bind_addr);
      bind_addr.addr.sa.sa_family = connect_addr.addr.sa.sa_family;
      if (bind(sock->fd, &bind_addr.addr.sa,
#if COAP_IPV4_SUPPORT
               bind_addr.addr.sa.sa_family == AF_INET ?
               (socklen_t)sizeof(struct sockaddr_in) :
#endif /* COAP_IPV4_SUPPORT */
               (socklen_t)bind_addr.size) == COAP_SOCKET_ERROR) {
        coap_log_warn("coap_socket_connect_udp: bind: %s\n",
                      coap_socket_strerror());
        goto error;
      }
    }
    if (getsockname(sock->fd, &local_addr->addr.sa, &local_addr->size) == COAP_SOCKET_ERROR) {
      coap_log_warn("coap_socket_connect_udp: getsockname for multicast socket: %s\n",
                    coap_socket_strerror());
    }
    coap_address_copy(remote_addr, &connect_addr);
    coap_address_copy(&sock->mcast_addr, &connect_addr);
    sock->flags |= COAP_SOCKET_MULTICAST;
    if (coap_is_bcast(server) &&
        setsockopt(sock->fd, SOL_SOCKET, SO_BROADCAST, OPTVAL_T(&on),
                   sizeof(on)) == COAP_SOCKET_ERROR)
      coap_log_warn("coap_socket_connect_udp: setsockopt SO_BROADCAST: %s\n",
                    coap_socket_strerror());
    return 1;
  }

  if (connect(sock->fd, &connect_addr.addr.sa, connect_addr.size) == COAP_SOCKET_ERROR) {
#if COAP_AF_UNIX_SUPPORT
    if (connect_addr.addr.sa.sa_family == AF_UNIX) {
      coap_log_warn("coap_socket_connect_udp: connect: %s: %s\n",
                    connect_addr.addr.cun.sun_path, coap_socket_strerror());
    } else
#endif /* COAP_AF_UNIX_SUPPORT */
    {
      coap_log_warn("coap_socket_connect_udp: connect: %s (%d)\n",
                    coap_socket_strerror(), connect_addr.addr.sa.sa_family);
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
  coap_socket_dgrm_close(sock);
  return 0;
}
#endif /* COAP_CLIENT_SUPPORT */

#if !defined(__ZEPHYR__)
#if 0 == ( defined(HAVE_NETINET_IN_H) || defined(HAVE_WS2TCPIP_H) )
/* define struct in6_pktinfo and struct in_pktinfo if not available
   FIXME: check with configure
*/
#if !defined(__MINGW32__)
struct in6_pktinfo {
  struct in6_addr ipi6_addr;        /* src/dst IPv6 address */
  unsigned int ipi6_ifindex;        /* send/recv interface index */
};

struct in_pktinfo {
  int ipi_ifindex;
  struct in_addr ipi_spec_dst;
  struct in_addr ipi_addr;
};
#endif /* ! __MINGW32__ */
#endif
#endif /* ! __ZEPHYR__ */

#if !defined(SOL_IP)
/* Solaris expects level IPPROTO_IP for ancillary data. */
#define SOL_IP IPPROTO_IP
#endif
#ifdef _WIN32
#define COAP_SOL_IP IPPROTO_IP
#else /* ! _WIN32 */
#define COAP_SOL_IP SOL_IP
#endif /* ! _WIN32 */

#if defined(_WIN32)
#include <mswsock.h>
#if defined(__MINGW32__)
static __thread LPFN_WSARECVMSG lpWSARecvMsg = NULL;
#if(_WIN32_WINNT >= 0x0600)
#define CMSG_FIRSTHDR WSA_CMSG_FIRSTHDR
#define CMSG_NXTHDR WSA_CMSG_NXTHDR
#define CMSG_LEN WSA_CMSG_LEN
#define CMSG_SPACE WSA_CMSG_SPACE
#if(_WIN32_WINNT < 0x0603 || _WIN32_WINNT == 0x0a00)
#define cmsghdr _WSACMSGHDR
#endif /* (_WIN32_WINNT<0x0603 || _WIN32_WINNT == 0x0a00) */
#endif /* (_WIN32_WINNT>=0x0600) */
#else /* ! __MINGW32__ */
static __declspec(thread) LPFN_WSARECVMSG lpWSARecvMsg = NULL;
#endif /* ! __MINGW32__ */
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
#if !defined(__MINGW32__)
#pragma warning( disable : 4116 )
#endif /* ! __MINGW32__ */
#else
#define iov_len_t size_t
#endif

#if defined(_CYGWIN_ENV) || defined(__QNXNTO__)
#define ipi_spec_dst ipi_addr
#endif

#if COAP_CLIENT_SUPPORT
static uint32_t cid_track_counter;

static void
coap_test_cid_tuple_change(coap_session_t *session) {
  if (session->type == COAP_SESSION_TYPE_CLIENT &&
      session->negotiated_cid &&
      session->state == COAP_SESSION_STATE_ESTABLISHED &&
      session->proto == COAP_PROTO_DTLS && session->context->testing_cids) {
    if ((++cid_track_counter) % session->context->testing_cids == 0) {
      coap_address_t local_if = session->addr_info.local;
      uint16_t port = coap_address_get_port(&local_if);

      port++;
      coap_address_set_port(&local_if, port);

      coap_socket_dgrm_close(&session->sock);
      session->sock.session = session;
      if (!coap_socket_connect_udp(&session->sock, &local_if, &session->addr_info.remote,
                                   port,
                                   &session->addr_info.local,
                                   &session->addr_info.remote)) {
        coap_log_err("Tuple change for CID failed\n");
        return;
#ifdef COAP_EPOLL_SUPPORT
      } else {
        coap_epoll_ctl_add(&session->sock,
                           EPOLLIN |
                           ((session->sock.flags & COAP_SOCKET_WANT_CONNECT) ?
                            EPOLLOUT : 0),
                           __func__);
#endif /* COAP_EPOLL_SUPPORT */
      }
      session->sock.flags |= COAP_SOCKET_NOT_EMPTY | COAP_SOCKET_WANT_READ | COAP_SOCKET_BOUND;
    }
  }
}
#endif /* COAP_CLIENT_SUPPORT */

/*
 * dgram
 * return +ve Number of bytes written.
 *         -1 Error error in errno).
 */
ssize_t
coap_socket_send(coap_socket_t *sock, coap_session_t *session,
                 const uint8_t *data, size_t datalen) {
  ssize_t bytes_written = 0;

#if COAP_CLIENT_SUPPORT
  coap_test_cid_tuple_change(session);
#endif /* COAP_CLIENT_SUPPORT */

  if (!coap_debug_send_packet()) {
    bytes_written = (ssize_t)datalen;
  } else if (sock->flags & COAP_SOCKET_CONNECTED) {
#ifdef _WIN32
    bytes_written = send(sock->fd, (const char *)data, (int)datalen, 0);
#else
    bytes_written = send(sock->fd, data, datalen, 0);
#endif
  } else {
#if defined(_WIN32)
    DWORD dwNumberOfBytesSent = 0;
    int r;
#endif /* _WIN32 */
#ifdef HAVE_STRUCT_CMSGHDR
    /* a buffer large enough to hold all packet info types, ipv6 is the largest */
    char buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
    struct msghdr mhdr;
    struct iovec iov[1];
    const void *addr = &session->addr_info.remote.addr;

    assert(session);

    memcpy(&iov[0].iov_base, &data, sizeof(iov[0].iov_base));
    iov[0].iov_len = (iov_len_t)datalen;

    memset(buf, 0, sizeof(buf));

    memset(&mhdr, 0, sizeof(struct msghdr));
    memcpy(&mhdr.msg_name, &addr, sizeof(mhdr.msg_name));
    mhdr.msg_namelen = session->addr_info.remote.addr.sa.sa_family == AF_INET ?
                       (socklen_t)sizeof(struct sockaddr_in) :
                       session->addr_info.remote.size;

    mhdr.msg_iov = iov;
    mhdr.msg_iovlen = 1;

    if (!coap_address_isany(&session->addr_info.local) &&
        !coap_is_mcast(&session->addr_info.local)) {
      switch (session->addr_info.local.addr.sa.sa_family) {
#if COAP_IPV6_SUPPORT
      case AF_INET6: {
        struct cmsghdr *cmsg;

#if COAP_IPV4_SUPPORT
        if (IN6_IS_ADDR_V4MAPPED(&session->addr_info.local.addr.sin6.sin6_addr)) {
#if defined(IP_PKTINFO)
          struct in_pktinfo *pktinfo;
          mhdr.msg_control = buf;
          mhdr.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));

          cmsg = CMSG_FIRSTHDR(&mhdr);
          cmsg->cmsg_level = COAP_SOL_IP;
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
#endif /* COAP_IPV4_SUPPORT */
          struct in6_pktinfo *pktinfo;
          mhdr.msg_control = buf;
          mhdr.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));

          cmsg = CMSG_FIRSTHDR(&mhdr);
          cmsg->cmsg_level = IPPROTO_IPV6;
          cmsg->cmsg_type = IPV6_PKTINFO;
          cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

          pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);

          if (coap_is_mcast(&session->addr_info.remote)) {
            pktinfo->ipi6_ifindex = session->addr_info.remote.addr.sin6.sin6_scope_id;
          } else {
            pktinfo->ipi6_ifindex = session->ifindex;
          }
          memcpy(&pktinfo->ipi6_addr,
                 &session->addr_info.local.addr.sin6.sin6_addr,
                 sizeof(pktinfo->ipi6_addr));
#if COAP_IPV4_SUPPORT
        }
#endif /* COAP_IPV4_SUPPORT */
        break;
      }
#endif /* COAP_IPV6_SUPPORT */
#if COAP_IPV4_SUPPORT
      case AF_INET: {
#if defined(IP_PKTINFO)
        struct cmsghdr *cmsg;
        struct in_pktinfo *pktinfo;

        mhdr.msg_control = buf;
        mhdr.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));

        cmsg = CMSG_FIRSTHDR(&mhdr);
        cmsg->cmsg_level = COAP_SOL_IP;
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
#endif /* COAP_IPV4_SUPPORT */
#if COAP_AF_UNIX_SUPPORT
      case AF_UNIX:
        break;
#endif /* COAP_AF_UNIX_SUPPORT */
      default:
        /* error */
        coap_log_warn("protocol not supported\n");
        return -1;
      }
    }
#endif /* HAVE_STRUCT_CMSGHDR */

#if defined(_WIN32)
    r = WSASendMsg(sock->fd, &mhdr, 0 /*dwFlags*/, &dwNumberOfBytesSent, NULL /*lpOverlapped*/,
                   NULL /*lpCompletionRoutine*/);
    if (r == 0)
      bytes_written = (ssize_t)dwNumberOfBytesSent;
    else {
      bytes_written = -1;
      coap_win_error_to_errno();
    }
#else /* !_WIN32 */
#ifdef HAVE_STRUCT_CMSGHDR
    bytes_written = sendmsg(sock->fd, &mhdr, 0);
#else /* ! HAVE_STRUCT_CMSGHDR */
    bytes_written = sendto(sock->fd, (const void *)data, datalen, 0,
                           &session->addr_info.remote.addr.sa,
                           session->addr_info.remote.size);
#endif /* ! HAVE_STRUCT_CMSGHDR */
#endif /* !_WIN32 */
  }

  if (bytes_written < 0)
    coap_log_crit("coap_socket_send: %s\n", coap_socket_strerror());

  return bytes_written;
}

#define SIN6(A) ((struct sockaddr_in6 *)(A))

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
#endif /* _WIN32 */
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
#if defined(_WIN32)
    DWORD dwNumberOfBytesRecvd = 0;
    int r;
#endif /* _WIN32 */
#ifdef HAVE_STRUCT_CMSGHDR
    /* a buffer large enough to hold all packet info types, ipv6 is the largest */
    char buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
    struct cmsghdr *cmsg;
    struct msghdr mhdr;
    struct iovec iov[1];

#if defined(__MINGW32__)
    iov[0].iov_base = (char *) packet->payload;
#else /* ! __MINGW32__ */
    iov[0].iov_base = packet->payload;
#endif /* defined(__MINGW32__) */
    iov[0].iov_len = (iov_len_t)COAP_RXBUFFER_SIZE;

    memset(&mhdr, 0, sizeof(struct msghdr));

    mhdr.msg_name = (struct sockaddr *)&packet->addr_info.remote.addr;
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
      if (WSAIoctl(sock->fd, SIO_GET_EXTENSION_FUNCTION_POINTER, &wsaid, sizeof(wsaid), &lpWSARecvMsg,
                   sizeof(lpWSARecvMsg), &cbBytesReturned, NULL, NULL) != 0) {
        coap_log_warn("coap_socket_recv: no WSARecvMsg\n");
        return -1;
      }
    }
    r = lpWSARecvMsg(sock->fd, &mhdr, &dwNumberOfBytesRecvd, NULL /* LPWSAOVERLAPPED */,
                     NULL /* LPWSAOVERLAPPED_COMPLETION_ROUTINE */);
    if (r == 0)
      len = (ssize_t)dwNumberOfBytesRecvd;
    else if (r == COAP_SOCKET_ERROR)
      coap_win_error_to_errno();
#else
    len = recvmsg(sock->fd, &mhdr, 0);
#endif

#else /* ! HAVE_STRUCT_CMSGHDR */
    len = recvfrom(sock->fd, (void *)packet->payload, COAP_RXBUFFER_SIZE, 0,
                   &packet->addr_info.remote.addr.sa,
                   &packet->addr_info.remote.size);
#endif /* ! HAVE_STRUCT_CMSGHDR */

    if (len < 0) {
#ifdef _WIN32
      coap_win_error_to_errno();
#endif /* _WIN32 */
      if (errno == ECONNREFUSED || errno == EHOSTUNREACH || errno == ECONNRESET) {
        /* server-side ICMP destination unreachable, ignore it. The destination address is in msg_name. */
        coap_log_warn("** %s: coap_socket_recv: ICMP: %s\n",
                      sock->session ?
                      coap_session_str(sock->session) : "",
                      coap_socket_strerror());
        return 0;
      }
      if (errno != EAGAIN) {
        coap_log_warn("coap_socket_recv: %s\n", coap_socket_strerror());
      }
      goto error;
    } else {
#ifdef HAVE_STRUCT_CMSGHDR
      int dst_found = 0;

      packet->addr_info.remote.size = mhdr.msg_namelen;
      packet->length = (size_t)len;

      /* Walk through ancillary data records until the local interface
       * is found where the data was received. */
      for (cmsg = CMSG_FIRSTHDR(&mhdr); cmsg; cmsg = CMSG_NXTHDR(&mhdr, cmsg)) {

#if COAP_IPV6_SUPPORT
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
#endif /* COAP_IPV6_SUPPORT */

#if COAP_IPV4_SUPPORT
        /* local interface for IPv4 */
#if defined(IP_PKTINFO)
        if (cmsg->cmsg_level == COAP_SOL_IP && cmsg->cmsg_type == IP_PKTINFO) {
          union {
            uint8_t *c;
            struct in_pktinfo *p;
          } u;
          u.c = CMSG_DATA(cmsg);
          packet->ifindex = u.p->ipi_ifindex;
#if COAP_IPV6_SUPPORT
          if (packet->addr_info.local.addr.sa.sa_family == AF_INET6) {
            memset(packet->addr_info.local.addr.sin6.sin6_addr.s6_addr, 0, 10);
            packet->addr_info.local.addr.sin6.sin6_addr.s6_addr[10] = 0xff;
            packet->addr_info.local.addr.sin6.sin6_addr.s6_addr[11] = 0xff;
            memcpy(packet->addr_info.local.addr.sin6.sin6_addr.s6_addr + 12,
                   &u.p->ipi_addr, sizeof(struct in_addr));
          } else
#endif /* COAP_IPV6_SUPPORT */
          {
            memcpy(&packet->addr_info.local.addr.sin.sin_addr,
                   &u.p->ipi_addr, sizeof(struct in_addr));
          }
          dst_found = 1;
          break;
        }
#endif /* IP_PKTINFO */
#if defined(IP_RECVDSTADDR)
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_RECVDSTADDR) {
          packet->ifindex = (int)sock->fd;
          memcpy(&packet->addr_info.local.addr.sin.sin_addr,
                 CMSG_DATA(cmsg), sizeof(struct in_addr));
          dst_found = 1;
          break;
        }
#endif /* IP_RECVDSTADDR */
#endif /* COAP_IPV4_SUPPORT */
        if (!dst_found) {
          /* cmsg_level / cmsg_type combination we do not understand
             (ignore preset case for bad recvmsg() not updating cmsg) */
          if (cmsg->cmsg_level != -1 && cmsg->cmsg_type != -1) {
            coap_log_debug("cmsg_level = %d and cmsg_type = %d not supported - fix\n",
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

void
coap_socket_dgrm_close(coap_socket_t *sock) {
  if (sock->fd != COAP_INVALID_SOCKET && !(sock->flags & COAP_SOCKET_SLAVE)) {
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
        coap_log_err("%s: epoll_ctl DEL failed: %d: %s (%d)\n",
                     "coap_socket_close",
                     sock->fd,
                     coap_socket_strerror(), errno);
      }
    }
#endif /* COAP_EPOLL_SUPPORT */
#if COAP_SERVER_SUPPORT
#if COAP_AF_UNIX_SUPPORT
    if (sock->endpoint &&
        sock->endpoint->bind_addr.addr.sa.sa_family == AF_UNIX) {
      /* Clean up Unix endpoint */
#ifdef _WIN32
      _unlink(sock->endpoint->bind_addr.addr.cun.sun_path);
#else /* ! _WIN32 */
      unlink(sock->endpoint->bind_addr.addr.cun.sun_path);
#endif /* ! _WIN32 */
    }
#endif /* COAP_AF_UNIX_SUPPORT */
    sock->endpoint = NULL;
#endif /* COAP_SERVER_SUPPORT */
#if COAP_CLIENT_SUPPORT
#if COAP_AF_UNIX_SUPPORT
    if (sock->session && sock->session->type == COAP_SESSION_TYPE_CLIENT &&
        sock->session->addr_info.local.addr.sa.sa_family == AF_UNIX) {
      /* Clean up Unix endpoint */
#ifdef _WIN32
      _unlink(sock->session->addr_info.local.addr.cun.sun_path);
#else /* ! _WIN32 */
      unlink(sock->session->addr_info.local.addr.cun.sun_path);
#endif /* ! _WIN32 */
    }
#endif /* COAP_AF_UNIX_SUPPORT */
#endif /* COAP_CLIENT_SUPPORT */
    sock->session = NULL;
    coap_closesocket(sock->fd);
    sock->fd = COAP_INVALID_SOCKET;
  }
  sock->flags = COAP_SOCKET_EMPTY;
}

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
