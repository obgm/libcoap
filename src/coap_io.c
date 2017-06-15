/* coap_io.c -- Default network I/O functions for libcoap
 *
 * Copyright (C) 2012,2014,2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#include "coap_config.h"

#ifdef HAVE_STDIO_H
#  include <stdio.h>
#endif

#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
# define OPTVAL_T(t)         (t)
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
# define OPTVAL_T(t)         (const char*)(t)
# undef CMSG_DATA
# define CMSG_DATA WSA_CMSG_DATA
#endif
#ifdef HAVE_SYS_UIO_H
# include <sys/uio.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <errno.h>

#ifdef WITH_CONTIKI
# include "uip.h"
#endif

#include "libcoap.h"
#include "debug.h"
#include "mem.h"
#include "coap_dtls.h"
#include "coap_io.h"
#include "pdu.h"
#include "utlist.h"

#if !defined(WITH_CONTIKI) && !defined(WITH_LWIP)
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

struct coap_packet_t {
  coap_address_t src;	      /**< the packet's source address */
  coap_address_t dst;	      /**< the packet's destination address */
  int ifindex;                /**< the interface index */
  size_t length;              /**< length of payload */
  unsigned char payload[];    /**< payload */
};
#endif

void coap_free_endpoint( coap_endpoint_t *ep );

#ifndef CUSTOM_COAP_NETWORK_ENDPOINT

#ifdef WITH_CONTIKI
static int ep_initialized = 0;

COAP_STATIC_INLINE struct coap_endpoint_t *
coap_malloc_contiki_endpoint() {
  static struct coap_endpoint_t ep;

  if (ep_initialized) {
    return NULL;
  } else {
    ep_initialized = 1;
    return &ep;
  }
}

COAP_STATIC_INLINE void
coap_free_contiki_endpoint(struct coap_endpoint_t *ep) {
  ep_initialized = 0;
}

coap_endpoint_t *
coap_new_endpoint( coap_context_t *context, const coap_address_t *listen_addr, coap_proto_t proto ) {

  if ( proto == COAP_PROTO_DTLS ) {
    coap_log( LOG_CRIT, "coap_new_endpoint: DTLS not supported\n" );
    return NULL;
  }

  struct coap_endpoint_t *ep = coap_malloc_contiki_endpoint();

  if (ep) {
    memset(ep, 0, sizeof(struct coap_endpoint_t));
    ep->sock.handle.conn = udp_new(NULL, 0, NULL);

    if (!ep->sock.handle.conn) {
      coap_free_endpoint(ep);
      return NULL;
    }

    coap_address_init(&ep->addr);
    uip_ipaddr_copy(&ep->addr.addr, &listen_addr->addr);
    ep->addr.port = listen_addr->port;
    udp_bind((struct uip_udp_conn *)ep->sock.handle.conn, listen_addr->port);
    LL_PREPEND( context->endpoint, endpoint );
  }
  return ep;
}

void
coap_free_endpoint(coap_endpoint_t *ep) {
  if (ep) {
    if (ep->sock.handle.conn) {
      uip_udp_remove((struct uip_udp_conn *)ep->handle.conn);
    }
    coap_free_contiki_endpoint(ep);
  }
}

#else /* WITH_CONTIKI */
COAP_STATIC_INLINE struct coap_endpoint_t *
coap_malloc_posix_endpoint(void) {
  return (struct coap_endpoint_t *)coap_malloc(sizeof(struct coap_endpoint_t));
}

COAP_STATIC_INLINE void
coap_free_posix_endpoint(struct coap_endpoint_t *ep) {
  coap_free(ep);
}

coap_endpoint_t *
coap_new_endpoint( coap_context_t *context, const coap_address_t *listen_addr, coap_proto_t proto ) {
  coap_fd_t sockfd;
  int on = 1, off = 0;
  struct coap_endpoint_t *ep = NULL;

  assert( context );
  assert( listen_addr );
  assert( proto != COAP_PROTO_NONE );

  if ( proto == COAP_PROTO_DTLS && !coap_dtls_is_supported() ) {
    coap_log(LOG_CRIT, "coap_new_endpoint: DTLS not supported\n");
    return NULL;
  }

  sockfd = socket( listen_addr->addr.sa.sa_family, SOCK_DGRAM, 0 );
  if (sockfd == COAP_INVALID_SOCKET) {
    coap_log(LOG_WARNING, "coap_new_endpoint: socket");
    return NULL;
  }

  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, OPTVAL_T(&on), sizeof(on)) == COAP_SOCKET_ERROR)
    coap_log(LOG_WARNING, "coap_new_endpoint: setsockopt SO_REUSEADDR");

  switch( listen_addr->addr.sa.sa_family ) {
  case AF_INET:
    if (setsockopt(sockfd, IPPROTO_IP, GEN_IP_PKTINFO, OPTVAL_T(&on), sizeof(on)) == COAP_SOCKET_ERROR)
      coap_log(LOG_ALERT, "coap_new_endpoint: setsockopt IP_PKTINFO\n");
    break;
  case AF_INET6:
    /* Configure the socket as dual-stacked */
    if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, OPTVAL_T(&off), sizeof(off)) == COAP_SOCKET_ERROR)
      coap_log(LOG_ALERT, "coap_new_endpoint: setsockopt IPV6_V6ONLY\n");
    if (setsockopt(sockfd, IPPROTO_IPV6, GEN_IPV6_PKTINFO, OPTVAL_T(&on), sizeof(on)) == COAP_SOCKET_ERROR)
      coap_log(LOG_ALERT, "coap_new_endpoint: setsockopt IPV6_PKTINFO\n");
    setsockopt(sockfd, IPPROTO_IP, GEN_IP_PKTINFO, OPTVAL_T(&on), sizeof(on)); /* ignore error, because the likely cause is that IPv4 is disabled at the os level */
  break;
  default:
    coap_log(LOG_ALERT, "coap_new_endpoint: unsupported sa_family\n");
  }

  if ( bind( sockfd, &listen_addr->addr.sa, listen_addr->size ) == COAP_SOCKET_ERROR) {
    coap_log(LOG_WARNING, "coap_new_endpoint: bind");
    goto error;
  }

  ep = coap_malloc_posix_endpoint();
  if (!ep) {
    coap_log(LOG_WARNING, "coap_new_endpoint: malloc");
    goto error;
  }

  memset(ep, 0, sizeof(struct coap_endpoint_t));
  ep->context = context;
  ep->proto = proto;
  ep->sock.fd = sockfd;
  ep->sock.flags = COAP_SOCKET_NOT_EMPTY | COAP_SOCKET_BOUND | COAP_SOCKET_WANT_DATA;
  ep->bind_addr.size = (socklen_t)sizeof( ep->bind_addr );
  if (getsockname(sockfd, &ep->bind_addr.addr.sa, &ep->bind_addr.size) < 0) {
    coap_log(LOG_WARNING, "coap_new_endpoint: cannot determine local address");
    goto error;
  }

#ifndef NDEBUG
  if (LOG_DEBUG <= coap_get_log_level()) {
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 40
#endif
    unsigned char addr_str[INET6_ADDRSTRLEN+8];

    if (coap_print_addr(&ep->bind_addr, addr_str, INET6_ADDRSTRLEN+8)) {
      debug("created %s endpoint %s\n",
	    ep->proto == COAP_PROTO_DTLS ? "DTLS " : "UDP",
	    addr_str);
    }
  }
#endif /* NDEBUG */

  LL_PREPEND( context->endpoint, ep );
  return ep;
 error:

  coap_closesocket(sockfd);
  coap_free_posix_endpoint(ep);
  return NULL;
}

void
coap_free_endpoint(coap_endpoint_t *ep) {
  if (ep) {
    coap_session_t *session;
    if (ep->sock.flags != COAP_SOCKET_EMPTY && ep->sock.fd != COAP_INVALID_SOCKET)
      coap_closesocket(ep->sock.fd);
    LL_FOREACH( ep->sessions, session ) {
      assert( session->ref == 0 );
      if ( session->ref == 0 ) {
	if ( session->sock.flags != COAP_SOCKET_EMPTY && session->sock.fd != COAP_INVALID_SOCKET )
	  coap_closesocket( session->sock.fd );
      }
    }
    coap_free_posix_endpoint(ep);
  }
}

static coap_session_t *
coap_make_session( coap_proto_t proto, coap_session_type_t type, const coap_address_t *local, const coap_address_t *remote, int ifindex, coap_context_t *context, coap_endpoint_t *endpoint ) {
  coap_session_t *session = (coap_session_t*)coap_malloc( sizeof( coap_session_t ) );
  if ( !session )
    return NULL;
  memset( session, 0, sizeof( *session ) );
  session->proto = proto;
  session->type = type;
  if ( local )
    coap_address_copy( &session->local_addr, local );
  else
    coap_address_init( &session->local_addr );
  if ( remote )
    coap_address_copy( &session->remote_addr, remote );
  else
    coap_address_init( &session->remote_addr );
  session->ifindex = ifindex;
  session->context = context;
  session->endpoint = endpoint;
  return session;
}

static void
coap_free_session( coap_session_t *session ) {
  if ( !session )
    return;
  assert( session->ref == 0 );
  if ( session->ref )
    return;
  if ( session->sock.flags != COAP_SOCKET_EMPTY && session->sock.fd != COAP_INVALID_SOCKET )
    coap_closesocket( session->sock.fd );
  if ( session->endpoint )
    LL_DELETE( session->endpoint->sessions, session );
  else if ( session->context )
    LL_DELETE( session->context->sessions, session );
  coap_free( session );
}

coap_session_t *
coap_session_reference( coap_session_t *session ) {
  ++session->ref;
  return session;
}

void
coap_session_release( coap_session_t *session ) {
  if ( session ) {
    assert( session->ref > 0 );
    if ( session->ref > 0 )
      --session->ref;
    if ( session->ref == 0 && session->type == COAP_SESSION_TYPE_CLIENT )
      coap_free_session( session );
  }
}

coap_session_t *
coap_endpoint_get_session( coap_endpoint_t *endpoint, const coap_packet_t *packet ) {
  coap_session_t *session = NULL;
  LL_FOREACH( endpoint->sessions, session ) {
    if ( session->ifindex == packet->ifindex && coap_address_equals( &session->local_addr, &packet->dst ) && coap_address_equals( &session->remote_addr, &packet->src ) )
      return session;
  }

  session = coap_make_session( endpoint->proto, COAP_SESSION_TYPE_SERVER, &packet->dst, &packet->src, packet->ifindex, endpoint->context, endpoint );
  
  if ( endpoint->proto == COAP_PROTO_UDP )
    session->state = COAP_SESSION_STATE_ESTABLISHED;

  LL_PREPEND( endpoint->sessions, session );

  return session;
}

coap_session_t *coap_new_client_session(
  coap_context_t *ctx,
  coap_address_t *local_if,
  coap_address_t *server,
  coap_proto_t proto
) {
  coap_session_t *session = NULL;
  int on = 1, off = 0;

  assert( server );
  assert( proto != COAP_PROTO_NONE );

  coap_fd_t sockfd = socket( server->addr.sa.sa_family, SOCK_DGRAM, 0 );

  if ( sockfd == COAP_INVALID_SOCKET ) {
    coap_log( LOG_WARNING, "coap_new_session: socket" );
    return NULL;
  }

  switch ( server->addr.sa.sa_family ) {
  case AF_INET:
    if ( server->addr.sin.sin_port == 0 )
      server->addr.sin.sin_port = htons( proto == COAP_PROTO_DTLS ? COAPS_DEFAULT_PORT : COAP_DEFAULT_PORT );
    break;
  case AF_INET6:
    if ( server->addr.sin6.sin6_port == 0 )
      server->addr.sin6.sin6_port = htons( proto == COAP_PROTO_DTLS ? COAPS_DEFAULT_PORT : COAP_DEFAULT_PORT );
    /* Configure the socket as dual-stacked */
    if ( setsockopt( sockfd, IPPROTO_IPV6, IPV6_V6ONLY, OPTVAL_T( &off ), sizeof( off ) ) == COAP_SOCKET_ERROR )
      coap_log( LOG_ALERT, "coap_new_session: setsockopt IPV6_V6ONLY\n" );
    break;
  default:
    coap_log( LOG_ALERT, "coap_new_session: unsupported sa_family\n" );
  }

  if ( local_if ) {
    if ( setsockopt( sockfd, SOL_SOCKET, SO_REUSEADDR, OPTVAL_T( &on ), sizeof( on ) ) == COAP_SOCKET_ERROR )
      coap_log( LOG_WARNING, "coap_new_session: setsockopt SO_REUSEADDR" );
    if ( bind( sockfd, &local_if->addr.sa, local_if->size ) == COAP_SOCKET_ERROR ) {
      coap_log( LOG_WARNING, "coap_new_session: bind" );
      goto error;
    }
  }

  if ( connect( sockfd, &server->addr.sa, server->size ) == COAP_SOCKET_ERROR ) {
    coap_log( LOG_WARNING, "coap_new_session: connect" );
    goto error;
  }

  session = coap_make_session( proto, COAP_SESSION_TYPE_CLIENT, local_if, server, 0, ctx, NULL );
  if ( !session )
    goto error;

  if ( getsockname( sockfd, &session->local_addr.addr.sa, &session->local_addr.size ) == COAP_SOCKET_ERROR ) {
    coap_log( LOG_WARNING, "coap_new_session: getsockname" );
  }
  
  if ( getpeername( sockfd, &session->remote_addr.addr.sa, &session->remote_addr.size ) == COAP_SOCKET_ERROR ) {
    coap_log( LOG_WARNING, "coap_new_session: getpeername" );
  }

  session->ref = 1;
  session->sock.fd = sockfd;
  session->sock.flags = COAP_SOCKET_NOT_EMPTY | COAP_SOCKET_CONNECTED | COAP_SOCKET_WANT_DATA;
  if ( local_if )
    session->sock.flags |= COAP_SOCKET_BOUND;
  if ( proto == COAP_PROTO_UDP )
    session->state = COAP_SESSION_STATE_ESTABLISHED;
  LL_PREPEND( ctx->sessions, session );
  return session;

error:
  if ( session )
    coap_free_session( session );
  else if ( sockfd != COAP_INVALID_SOCKET )
    coap_closesocket( sockfd );
  return NULL;
}

coap_session_t *coap_new_client_session_psk(
  coap_context_t *ctx,
  coap_address_t *local_if,
  coap_address_t *server,
  coap_proto_t proto,
  const uint8_t *identity,
  size_t identity_len,
  const uint8_t *key,
  size_t key_len
) {
  coap_session_t *session = coap_new_client_session( ctx, local_if, server, proto );
  return session;
}


#endif /* WITH_CONTIKI */
#endif /* CUSTOM_COAP_NETWORK_ENDPOINT */

#ifndef CUSTOM_COAP_NETWORK_SEND

#if (!defined(WITH_CONTIKI) && !defined(WITH_LWIP)) != ( defined(HAVE_NETINET_IN_H) || defined(HAVE_WS2TCPIP_H) )
/* define struct in6_pktinfo and struct in_pktinfo if not available
   FIXME: check with configure
*/
struct in6_pktinfo {
  struct in6_addr ipi6_addr;	/* src/dst IPv6 address */
  unsigned int ipi6_ifindex;	/* send/recv interface index */
};

struct in_pktinfo {
  int ipi_ifindex;
  struct in_addr ipi_spec_dst;
  struct in_addr ipi_addr;
};
#endif

#if !defined(WITH_CONTIKI) && !defined(WITH_LWIP) && !defined(SOL_IP)
/* Solaris expects level IPPROTO_IP for ancillary data. */
#define SOL_IP IPPROTO_IP
#endif

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__ ((unused))
#else /* not a GCC */
#define UNUSED_PARAM
#endif /* GCC */

#if defined(_WIN32)
#include <mswsock.h>
static __declspec( thread ) LPFN_WSARECVMSG lpWSARecvMsg = NULL;
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
#else
#define iov_len_t size_t
#endif

ssize_t
coap_network_send( coap_socket_t *sock, const coap_session_t *session, uint8_t *data, size_t datalen ) {
  ssize_t r = 0;

  if ( sock->flags & COAP_SOCKET_CONNECTED ) {
#ifdef _WIN32
    r = send( sock->fd, (const char *)data, (int)datalen, 0 );
#else
    r = send( sock->fd, data, datalen, 0 );
#endif
    return r;
  } else {
#ifndef WITH_CONTIKI
    /* a buffer large enough to hold all packet info types, ipv6 is the largest */
    char buf[CMSG_SPACE( sizeof( struct in6_pktinfo ) )];
#ifdef _WIN32
    DWORD dwNumberOfBytesSent = 0;
#endif
    struct msghdr mhdr;
    struct iovec iov[1];

    assert( session );

    iov[0].iov_base = data;
    iov[0].iov_len = (iov_len_t)datalen;

    memset( &mhdr, 0, sizeof( struct msghdr ) );
    mhdr.msg_name = (void *)&session->remote_addr.addr;
    mhdr.msg_namelen = session->remote_addr.size;

    mhdr.msg_iov = iov;
    mhdr.msg_iovlen = 1;

    if ( !coap_address_isany( &session->local_addr ) && !coap_is_mcast( &session->local_addr ) ) switch ( session->local_addr.addr.sa.sa_family ) {
    case AF_INET6:
    {
      struct cmsghdr *cmsg;

      if ( IN6_IS_ADDR_V4MAPPED( &session->local_addr.addr.sin6.sin6_addr ) ) {
	struct in_pktinfo *pktinfo;
	mhdr.msg_control = buf;
	mhdr.msg_controllen = CMSG_SPACE( sizeof( struct in_pktinfo ) );

	cmsg = CMSG_FIRSTHDR( &mhdr );
	cmsg->cmsg_level = SOL_IP;
	cmsg->cmsg_type = IP_PKTINFO;
	cmsg->cmsg_len = CMSG_LEN( sizeof( struct in_pktinfo ) );

	pktinfo = ( struct in_pktinfo * )CMSG_DATA( cmsg );
	memset( pktinfo, 0, sizeof( struct in_pktinfo ) );

	pktinfo->ipi_ifindex = session->ifindex;
	memcpy( &pktinfo->ipi_spec_dst, session->local_addr.addr.sin6.sin6_addr.s6_addr + 12, sizeof( pktinfo->ipi_spec_dst ) );
      } else {
	struct in6_pktinfo *pktinfo;
	mhdr.msg_control = buf;
	mhdr.msg_controllen = CMSG_SPACE( sizeof( struct in6_pktinfo ) );

	cmsg = CMSG_FIRSTHDR( &mhdr );
	cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type = IPV6_PKTINFO;
	cmsg->cmsg_len = CMSG_LEN( sizeof( struct in6_pktinfo ) );

	pktinfo = ( struct in6_pktinfo * )CMSG_DATA( cmsg );
	memset( pktinfo, 0, sizeof( struct in6_pktinfo ) );

	pktinfo->ipi6_ifindex = session->ifindex;
	memcpy( &pktinfo->ipi6_addr, &session->local_addr.addr.sin6.sin6_addr, sizeof( pktinfo->ipi6_addr ) );
      }
      break;
    }
    case AF_INET:
    {
#if defined(IP_PKTINFO)
      struct cmsghdr *cmsg;
      struct in_pktinfo *pktinfo;

      mhdr.msg_control = buf;
      mhdr.msg_controllen = CMSG_SPACE( sizeof( struct in_pktinfo ) );

      cmsg = CMSG_FIRSTHDR( &mhdr );
      cmsg->cmsg_level = SOL_IP;
      cmsg->cmsg_type = IP_PKTINFO;
      cmsg->cmsg_len = CMSG_LEN( sizeof( struct in_pktinfo ) );

      pktinfo = ( struct in_pktinfo * )CMSG_DATA( cmsg );
      memset( pktinfo, 0, sizeof( struct in_pktinfo ) );

      pktinfo->ipi_ifindex = session->ifindex;
      memcpy( &pktinfo->ipi_spec_dst, &session->local_addr.addr.sin.sin_addr, sizeof( pktinfo->ipi_spec_dst ) );
#endif /* IP_PKTINFO */
      break;
    }
    default:
      /* error */
      coap_log( LOG_WARNING, "protocol not supported\n" );
      return -1;
    }

#ifdef _WIN32
    r = WSASendMsg( sock->fd, &mhdr, 0 /*dwFlags*/, &dwNumberOfBytesSent, NULL /*lpOverlapped*/, NULL /*lpCompletionRoutine*/ );
    if ( r == 0 )
      return (ssize_t)dwNumberOfBytesSent;
    else
      return -1;
#else
    return sendmsg( sock->fd, &mhdr, 0 );
#endif
#else /* WITH_CONTIKI */
    /* FIXME: untested */
    /* FIXME: is there a way to check if send was successful? */
    (void)datalen;
    (void)data;
    uip_udp_packet_sendto( ( struct uip_udp_conn * )sock->handle.conn, data, datalen,
      &session->remote_addr.addr, session->remote_addr.port );
    return datalen;
#endif /* WITH_CONTIKI */
  }
}

#endif /* CUSTOM_COAP_NETWORK_SEND */

#ifndef CUSTOM_COAP_NETWORK_READ

#define SIN6(A) ((struct sockaddr_in6 *)(A))

#if !defined(WITH_CONTIKI) && !defined(WITH_LWIP)
static coap_packet_t *
coap_malloc_packet(void) {
  coap_packet_t *packet;
  const size_t need = sizeof(coap_packet_t) + COAP_MAX_PDU_SIZE;

  packet = (coap_packet_t *)coap_malloc(need);
  if (packet) {
    memset(packet, 0, need);
  }
  return packet;
}

void
coap_free_packet(coap_packet_t *packet) {
  coap_free(packet);
}
#endif /* !defined(WITH_CONTIKI) && !defined(WITH_LWIP) */
#ifdef WITH_CONTIKI
COAP_STATIC_INLINE coap_packet_t *
coap_malloc_packet(void) {
  return (coap_packet_t *)coap_malloc_type(COAP_PACKET, 0);
}

void
coap_free_packet(coap_packet_t *packet) {
  coap_free_type(COAP_PACKET, packet);
}
#endif /* WITH_CONTIKI */

COAP_STATIC_INLINE size_t
coap_get_max_packetlength(const coap_packet_t *packet) {
  (void)packet;
  return COAP_MAX_PDU_SIZE;
}

void
coap_packet_get_memmapped(coap_packet_t *packet, unsigned char **address, size_t *length) {
  *address = packet->payload;
  *length = packet->length;
}

void coap_packet_set_addr( coap_packet_t *packet, const coap_address_t *src, const coap_address_t *dst ) {
  coap_address_copy( &packet->src, src );
  coap_address_copy( &packet->dst, dst );
}

ssize_t
coap_network_read(coap_socket_t *sock, coap_packet_t **packet) {
  ssize_t len = -1;

  assert(sock);
  assert(packet);

  if ((sock->flags & COAP_SOCKET_HAS_DATA) == 0) {
    return -1;
  } else {
    /* clear has-data flag */
    sock->flags &= ~COAP_SOCKET_HAS_DATA;
  }

  *packet = coap_malloc_packet();

  if (!*packet) {
    warn("coap_network_read: insufficient memory, drop packet\n");
    return -1;
  }

  coap_address_init(&(*packet)->dst); /* the local interface address */
  coap_address_init(&(*packet)->src); /* the remote peer */

  if ( sock->flags & COAP_SOCKET_CONNECTED ) {
#ifdef _WIN32
    len = recv( sock->fd, (char *)(*packet)->payload, (int)coap_get_max_packetlength( *packet ), 0 );
#else
    len = recv( sock->fd, (*packet)->payload, coap_get_max_packetlength( *packet ), 0 );
#endif
    if ( len < 0 ) {
    } else if ( len > 0 ) {
      (*packet)->length = (size_t)len;
    }
  } else {
#if defined(_WIN32)
    DWORD dwNumberOfBytesRecvd = 0;
    int r;
#endif
#if !defined(WITH_CONTIKI) && !defined(WITH_LWIP)
    /* a buffer large enough to hold all packet info types, ipv6 is the largest */
    char buf[CMSG_SPACE( sizeof( struct in6_pktinfo ) )];
    struct msghdr mhdr;
    struct iovec iov[1];

    iov[0].iov_base = ( *packet )->payload;
    iov[0].iov_len = (iov_len_t)coap_get_max_packetlength( *packet );

    memset( &mhdr, 0, sizeof( struct msghdr ) );

    mhdr.msg_name = ( struct sockaddr* )&( *packet )->src.addr.st;
    mhdr.msg_namelen = sizeof( ( *packet )->src.addr.st );

    mhdr.msg_iov = iov;
    mhdr.msg_iovlen = 1;

    mhdr.msg_control = buf;
    mhdr.msg_controllen = sizeof( buf );

#if defined(_WIN32)
    if ( !lpWSARecvMsg ) {
      GUID wsaid = WSAID_WSARECVMSG;
      DWORD cbBytesReturned = 0;
      if ( WSAIoctl( sock->fd, SIO_GET_EXTENSION_FUNCTION_POINTER, &wsaid, sizeof( wsaid ), &lpWSARecvMsg, sizeof( lpWSARecvMsg ), &cbBytesReturned, NULL, NULL ) != 0 ) {
	coap_log( LOG_WARNING, "coap_network_read: no WSARecvMsg\n" );
	return -1;
      }
    }
    r = lpWSARecvMsg( sock->fd, &mhdr, &dwNumberOfBytesRecvd, NULL /* LPWSAOVERLAPPED */, NULL /* LPWSAOVERLAPPED_COMPLETION_ROUTINE */ );
    if ( r == 0 ) {
      len = (ssize_t)dwNumberOfBytesRecvd;
    } else {
      char *szErrorMsg = NULL;
      FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, (DWORD)WSAGetLastError(), MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT ), (LPSTR)&szErrorMsg, 0, NULL );
      coap_log( LOG_WARNING, "coap_network_read: %s\n", szErrorMsg );
      LocalFree( szErrorMsg );
      len = -1;
    }
#else
    len = recvmsg( socket->fd, &mhdr, 0 );
    if ( len < 0 )
      coap_log( LOG_WARNING, "coap_network_read: %s\n", strerror( errno ) );
#endif

    if ( len < 0 ) {
      goto error;
    } else {
      struct cmsghdr *cmsg;

      coap_log( LOG_DEBUG, "received %d bytes on fd %d\n", (int)len, (int)sock->fd );

      ( *packet )->src.size = mhdr.msg_namelen;

      /* use getsockname() to get the local port */
      ( *packet )->dst.size = sizeof( ( *packet )->dst.addr );
      if ( getsockname( sock->fd, &( *packet )->dst.addr.sa, &( *packet )->dst.size ) == COAP_SOCKET_ERROR ) {
	coap_log( LOG_DEBUG, "cannot determine local port\n" );
	goto error;
      }

      (*packet)->length = (size_t)len;

      /* Walk through ancillary data records until the local interface
       * is found where the data was received. */
      for ( cmsg = CMSG_FIRSTHDR( &mhdr ); cmsg; cmsg = CMSG_NXTHDR( &mhdr, cmsg ) ) {

	/* get the local interface for IPv6 */
	if ( cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO ) {
	  union {
	    uint8_t *c;
	    struct in6_pktinfo *p;
	  } u;
	  u.c = CMSG_DATA( cmsg );
	  ( *packet )->ifindex = (int)( u.p->ipi6_ifindex );
	  memcpy( &( *packet )->dst.addr.sin6.sin6_addr, &u.p->ipi6_addr, sizeof( struct in6_addr ) );
	  break;
	}

	/* local interface for IPv4 */
#if defined(IP_PKTINFO)
	if ( cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_PKTINFO ) {
	  union {
	    uint8_t *c;
	    struct in_pktinfo *p;
	  } u;
	  u.c = CMSG_DATA( cmsg );
	  ( *packet )->ifindex = u.p->ipi_ifindex;
	  if ( ( *packet )->dst.addr.sa.sa_family == AF_INET6 ) {
	    memset( ( *packet )->dst.addr.sin6.sin6_addr.s6_addr, 0, 10 );
	    ( *packet )->dst.addr.sin6.sin6_addr.s6_addr[10] = 0xff;
	    ( *packet )->dst.addr.sin6.sin6_addr.s6_addr[11] = 0xff;
	    memcpy( ( *packet )->dst.addr.sin6.sin6_addr.s6_addr + 12, &u.p->ipi_addr, sizeof( struct in_addr ) );
	  } else {
	    memcpy( &( *packet )->dst.addr.sin.sin_addr, &u.p->ipi_addr, sizeof( struct in_addr ) );
	  }
	  break;
	}
#elif defined(IP_RECVDSTADDR)
	if ( cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_RECVDSTADDR ) {
	  ( *packet )->ifindex = 0;
	  memcpy( &( *packet )->dst.addr.sin.sin_addr, CMSG_DATA( cmsg ), sizeof( struct in_addr ) );
	  break;
	}
#endif /* IP_PKTINFO */
      }
    }
#endif /* !defined(WITH_CONTIKI) && !defined(WITH_LWIP) */
#ifdef WITH_CONTIKI
  /* FIXME: untested, make this work */
#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_UDP_BUF  ((struct uip_udp_hdr *)&uip_buf[UIP_LLIPH_LEN])

  if(uip_newdata()) {
    uip_ipaddr_copy(&(*packet)->src.addr, &UIP_IP_BUF->srcipaddr);
    (*packet)->src.port = UIP_UDP_BUF->srcport;
    uip_ipaddr_copy(&(*packet)->dst.addr, &UIP_IP_BUF->destipaddr);
    (*packet)->dst.port = UIP_UDP_BUF->destport;

    len = uip_datalen();
    
    if (len > coap_get_max_packetlength(*packet)) {
      /* FIXME: we might want to send back a response */
      warn("discarded oversized packet\n");
      return -1;
    }

    ((char *)uip_appdata)[len] = 0;
#ifndef NDEBUG
    if (LOG_DEBUG <= coap_get_log_level()) {
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 40
#endif
      unsigned char addr_str[INET6_ADDRSTRLEN+8];
      
      if (coap_print_addr(&(*packet)->src, addr_str, INET6_ADDRSTRLEN+8)) {
	debug("received %zd bytes from %s\n", len, addr_str);
      }
    }
#endif /* NDEBUG */

    (*packet)->length = len;
    memcpy(&(*packet)->payload, uip_appdata, len);
  }

#undef UIP_IP_BUF
#undef UIP_UDP_BUF
#endif /* WITH_CONTIKI */
#ifdef WITH_LWIP
#error "coap_network_read() not implemented on this platform"
#endif
  }

  if ( len >= 0 )
    return len;
#if !defined(WITH_LWIP)
 error:
  coap_free_packet(*packet);
  *packet = NULL;
  return -1;
#endif
}

#if !defined(WITH_LWIP) && !defined(WITH_CONTIKI)
int
coap_run_once( coap_context_t *ctx, unsigned int timeout_ms ) {
  fd_set readfds;
  struct timeval tv;
  coap_queue_t *nextpdu;
  coap_tick_t now;
  unsigned long max_wait;
  int result;
  coap_endpoint_t *ep;
  coap_session_t *s;
  coap_fd_t nfds = 0;

  coap_ticks( &now );

  FD_ZERO( &readfds );
  LL_FOREACH( ctx->endpoint, ep ) {
    if ( ep->sock.flags & COAP_SOCKET_WANT_DATA ) {
      if ( ep->sock.fd + 1 > nfds )
	nfds = ep->sock.fd + 1;
      FD_SET( ep->sock.fd, &readfds );
    }
    LL_FOREACH( ctx->endpoint->sessions, s ) {
      if ( s->sock.flags & COAP_SOCKET_WANT_DATA ) {
	if ( s->sock.fd + 1 > nfds )
	  nfds = s->sock.fd + 1;
	FD_SET( s->sock.fd, &readfds );
      }
    }
  }
  LL_FOREACH( ctx->sessions, s ) {
    if ( s->sock.flags & COAP_SOCKET_WANT_DATA ) {
      if ( s->sock.fd + 1 > nfds )
	nfds = s->sock.fd + 1;
      FD_SET( s->sock.fd, &readfds );
    }
  }

  max_wait = timeout_ms * COAP_TICKS_PER_SECOND / 1000;
  while ( 1 ) {
    nextpdu = coap_peek_next( ctx );

    while ( nextpdu && nextpdu->t <= now - ctx->sendqueue_basetime ) {
      coap_retransmit( ctx, coap_pop_next( ctx ) );
      nextpdu = coap_peek_next( ctx );
    }

    if ( nextpdu && ( ( max_wait == 0 ) || nextpdu->t < max_wait ) ) {
      /* set timeout if there is a pdu to send */
      tv.tv_usec = ( ( nextpdu->t ) % COAP_TICKS_PER_SECOND ) * 1000000 / COAP_TICKS_PER_SECOND;
      tv.tv_sec = (long)( nextpdu->t ) / COAP_TICKS_PER_SECOND;
    } else {
      tv.tv_usec = ( max_wait % COAP_TICKS_PER_SECOND ) * 1000000 / COAP_TICKS_PER_SECOND;
      tv.tv_sec = (long)max_wait / COAP_TICKS_PER_SECOND;
    }

    result = select( nfds, &readfds, 0, 0, ( nextpdu || ( max_wait > 0 ) ) ? &tv : NULL );

    if ( result < 0 ) {   /* error */
#ifdef _WIN32
      char *szErrorMsg = NULL;
      int err = WSAGetLastError();
      if ( err == WSAEINVAL ) { /* May happen because of ICMP */
	coap_tick_t past = now;
	coap_ticks( &now );
	return (int)( ( ( now - past ) * 1000 ) / COAP_TICKS_PER_SECOND );
      }
      FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, (DWORD)err, MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT ), (LPSTR)&szErrorMsg, 0, NULL );
      coap_log( LOG_DEBUG, szErrorMsg );
      LocalFree( szErrorMsg );
#else
      if ( errno != EINTR ) {
	coap_log( LOG_DEBUG, strerror( errno ) );
      }
#endif
      return -1;
    } else if ( result > 0 ) {  /* read from socket */
      coap_tick_t past = now;
      LL_FOREACH( ctx->endpoint, ep ) {
	if ( FD_ISSET( ep->sock.fd, &readfds ) )
	  ep->sock.flags |= COAP_SOCKET_HAS_DATA;
	LL_FOREACH( ctx->endpoint->sessions, s ) {
	  if ( FD_ISSET( s->sock.fd, &readfds ) )
	    s->sock.flags |= COAP_SOCKET_HAS_DATA;
	}
      }
      LL_FOREACH( ctx->sessions, s ) {
	if ( FD_ISSET( s->sock.fd, &readfds ) )
	  s->sock.flags |= COAP_SOCKET_HAS_DATA;
      }
      coap_read( ctx );           /* read received data */
      coap_ticks( &now );
      return (int)( ( ( now - past ) * 1000 ) / COAP_TICKS_PER_SECOND );
    } else { /* timeout */
      coap_tick_t past = now;
      coap_ticks( &now );
      if ( past + max_wait <= now ) {
	return (int)( now - past );
      } else {
	max_wait -= (unsigned long)( now - past );
      }
    }
  }

  /* never reached */
}

#else
int coap_run_once( coap_context_t *ctx, unsigned int timeout_ms ) {
  return -1;
}
#endif


#undef SIN6

#endif /*  CUSTOM_COAP_NETWORK_READ */
