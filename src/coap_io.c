/* coap_io.h -- Default network I/O functions for libcoap
 *
 * Copyright (C) 2012,2014 Olaf Bergmann <bergmann@tzi.org>
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
# define CLOSE_SOCKET(fd)    close(fd)
# define COAP_SOCKET_ERROR   (-1)
# define COAP_INVALID_SOCKET (-1)
typedef int coap_socket_t;
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_WS2TCPIP_H
# include <ws2tcpip.h>
# define OPTVAL_T(t)         (const char*)(t)
# define CLOSE_SOCKET(fd)    { closesocket(fd); WSACleanup(); }
# define COAP_SOCKET_ERROR   SOCKET_ERROR
# define COAP_INVALID_SOCKET INVALID_SOCKET
# undef CMSG_DATA
# define CMSG_DATA           WSA_CMSG_DATA
# define CMSG_FIRSTHDR       WSA_CMSG_FIRSTHDR
# define CMSG_LEN            WSA_CMSG_LEN
# define CMSG_SPACE          WSA_CMSG_SPACE
typedef SOCKET coap_socket_t;
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

#include "debug.h"
#include "mem.h"
#include "coap_io.h"
#include "pdu.h"

#if !defined(WITH_LWIP) && !defined(WITH_CONTIKI)
struct coap_packet_t {
  coap_if_handle_t hnd;	      /**< the interface handle */
  coap_address_t src;	      /**< the packet's source address */
  coap_address_t dst;	      /**< the packet's destination address */
  const coap_endpoint_t *endpoint;

  int ifindex;
  void *session;		/**< opaque session data */

  size_t length;		/**< length of payload */
  unsigned char payload[];	/**< payload */
};
#endif

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
coap_new_endpoint(const coap_address_t *addr, int flags) {
  struct coap_endpoint_t *ep = coap_malloc_contiki_endpoint();

  if (ep) {
    memset(ep, 0, sizeof(struct coap_endpoint_t));
    ep->handle.conn = udp_new(NULL, 0, NULL);

    if (!ep->handle.conn) {
      coap_free_endpoint(ep);
      return NULL;
    }

    coap_address_init(&ep->addr);
    uip_ipaddr_copy(&ep->addr.addr, &addr->addr);
    ep->addr.port = addr->port;
    udp_bind((struct uip_udp_conn *)ep->handle.conn, addr->port);
  }
  return ep;
}

void
coap_free_endpoint(coap_endpoint_t *ep) {
  if (ep) {
    if (ep->handle.conn) {
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
coap_new_endpoint(const coap_address_t *addr, int flags) {
#ifdef HAVE_WS2TCPIP_H
  WSADATA Data;
  if (WSAStartup(MAKEWORD(2, 2), &Data) != NO_ERROR) {
    coap_log(LOG_WARNING, "coap_new_endpoint: WSAStartup failed");
    return NULL;
  }
#endif
  coap_socket_t sockfd = socket(addr->addr.sa.sa_family, SOCK_DGRAM, 0);
  int on = 1;
  struct coap_endpoint_t *ep;

  if (sockfd == COAP_INVALID_SOCKET) {
#ifdef HAVE_WS2TCPIP_H
    WSACleanup();
#endif
    coap_log(LOG_WARNING, "coap_new_endpoint: socket");
    return NULL;
  }

  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, OPTVAL_T(&on), sizeof(on)) == COAP_SOCKET_ERROR)
    coap_log(LOG_WARNING, "coap_new_endpoint: setsockopt SO_REUSEADDR");

  on = 1;
  switch(addr->addr.sa.sa_family) {
  case AF_INET:
    if (setsockopt(sockfd, IPPROTO_IP, IP_PKTINFO, OPTVAL_T(&on), sizeof(on)) == COAP_SOCKET_ERROR)
      coap_log(LOG_ALERT, "coap_new_endpoint: setsockopt IP_PKTINFO\n");
    break;
  case AF_INET6:
#ifdef IPV6_RECVPKTINFO
  if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVPKTINFO, OPTVAL_T(&on), sizeof(on)) == COAP_SOCKET_ERROR)
    coap_log(LOG_ALERT, "coap_new_endpoint: setsockopt IPV6_RECVPKTINFO\n");
#else /* IPV6_RECVPKTINFO */
  if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_PKTINFO, OPTVAL_T(&on), sizeof(on)) == COAP_SOCKET_ERROR)
    coap_log(LOG_ALERT, "coap_new_endpoint: setsockopt IPV6_PKTINFO\n");
#endif /* IPV6_RECVPKTINFO */      
  break;
  default:
    coap_log(LOG_ALERT, "coap_new_endpoint: unsupported sa_family\n");
  }

  if (bind(sockfd, &addr->addr.sa, addr->size) == COAP_SOCKET_ERROR) {
    coap_log(LOG_WARNING, "coap_new_endpoint: bind");
    CLOSE_SOCKET(sockfd);
    return NULL;
  }

  ep = coap_malloc_posix_endpoint();
  if (!ep) {
    coap_log(LOG_WARNING, "coap_new_endpoint: malloc");
    CLOSE_SOCKET(sockfd);
    return NULL;
  }

  memset(ep, 0, sizeof(struct coap_endpoint_t));
  ep->handle.fd = sockfd;
  ep->flags = flags;

  ep->addr.size = addr->size;
  if (getsockname(sockfd, &ep->addr.addr.sa, &ep->addr.size) == COAP_SOCKET_ERROR) {
    coap_log(LOG_WARNING, "coap_new_endpoint: cannot determine local address");
    CLOSE_SOCKET(sockfd);
    return NULL;
  }

#ifndef NDEBUG
  if (LOG_DEBUG <= coap_get_log_level()) {
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 40
#endif
    unsigned char addr_str[INET6_ADDRSTRLEN+8];

    if (coap_print_addr(&ep->addr, addr_str, INET6_ADDRSTRLEN+8)) {
      debug("created %sendpoint %s\n", 
	    ep->flags & COAP_ENDPOINT_DTLS ? "DTLS " : "",
	    addr_str);
    }
  }
#endif /* NDEBUG */

  return (coap_endpoint_t *)ep;
}

void
coap_free_endpoint(coap_endpoint_t *ep) {
  if (ep) {
    if (ep->handle.fd != COAP_INVALID_SOCKET)
      CLOSE_SOCKET(ep->handle.fd);
    coap_free_posix_endpoint((struct coap_endpoint_t *)ep);
  }
}

#endif /* WITH_CONTIKI */
#endif /* CUSTOM_COAP_NETWORK_ENDPOINT */

#ifndef CUSTOM_COAP_NETWORK_SEND

#if defined(WITH_POSIX) != defined(HAVE_NETINET_IN_H)
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

#if !defined(WITH_LWIP) && !defined(WITH_CONTIKI) && !defined(SOL_IP)
/* Solaris and Windows expect level IPPROTO_IP for ancillary data. */
#define SOL_IP IPPROTO_IP
#endif

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__ ((unused))
#else /* not a GCC */
#define UNUSED_PARAM
#endif /* GCC */

ssize_t
coap_network_send(struct coap_context_t *context UNUSED_PARAM,
		  const coap_endpoint_t *local_interface,
		  const coap_address_t *dst,
		  unsigned char *data,
		  size_t datalen) {

  struct coap_endpoint_t *ep = 
    (struct coap_endpoint_t *)local_interface;

#ifndef WITH_CONTIKI
  /* a buffer large enough to hold all protocol address types */
  char buf[CMSG_LEN(sizeof(struct sockaddr_storage))];
  assert(local_interface);

#ifdef WSA_CMSG_SPACE
  WSAMSG mhdr;
  WSABUF dataBuf;

  memset(&mhdr, 0, sizeof(mhdr));

  mhdr.name = (PSOCKADDR)&dst->addr.sa;
  mhdr.lpBuffers = &dataBuf;
  mhdr.dwBufferCount = 1;
#else
  struct msghdr mhdr;
  struct iovec iov[1];

  iov[0].iov_base = data;
  iov[0].iov_len = datalen;

  memset(&mhdr, 0, sizeof(mhdr));
  mhdr.msg_name = (void *)&dst->addr;
  mhdr.msg_namelen = dst->size;

  mhdr.msg_iov = iov;
  mhdr.msg_iovlen = 1;
  mhdr.msg_control = buf;
#endif

  switch (dst->addr.sa.sa_family) {
  case AF_INET6: {
    struct cmsghdr *cmsg;
    struct in6_pktinfo *pktinfo;

#ifdef WSA_CMSG_SPACE
    mhdr.Control.len = CMSG_SPACE(sizeof(struct in6_pktinfo));
#else
    mhdr.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
#endif

    cmsg = CMSG_FIRSTHDR(&mhdr);
    cmsg->cmsg_level = IPPROTO_IPV6;
    cmsg->cmsg_type = IPV6_PKTINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
  
    pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);
    memset(pktinfo, 0, sizeof(struct in6_pktinfo));
  
    pktinfo->ipi6_ifindex = ep->ifindex;
    if (coap_is_mcast(&local_interface->addr)) {
      /* We cannot send with multicast address as source address
       * and hence let the kernel pick the outgoing interface. */
      pktinfo->ipi6_ifindex = 0;
      memset(&pktinfo->ipi6_addr, 0, sizeof(pktinfo->ipi6_addr));
    } else {
      pktinfo->ipi6_ifindex = ep->ifindex;
      memcpy(&pktinfo->ipi6_addr,
	     &local_interface->addr.addr.sin6.sin6_addr,
	     local_interface->addr.size);
    }
    break;
  }
  case AF_INET: {
    struct cmsghdr *cmsg;
    struct in_pktinfo *pktinfo;

#ifdef WSA_CMSG_SPACE
    mhdr.Control.len = CMSG_SPACE(sizeof(struct in_pktinfo));
#else
    mhdr.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));
#endif

    cmsg = CMSG_FIRSTHDR(&mhdr);
    cmsg->cmsg_level = SOL_IP;
    cmsg->cmsg_type = IP_PKTINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

    pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
    memset(pktinfo, 0, sizeof(struct in_pktinfo));

    if (coap_is_mcast(&local_interface->addr)) {
      /* We cannot send with multicast address as source address
       * and hence let the kernel pick the outgoing interface. */
      pktinfo->ipi_ifindex = 0;

#ifdef WSA_CMSG_SPACE
      /* OS's without ipi_spec_dst put the source address in ipi_addr. */
      memset(&pktinfo->ipi_addr, 0, sizeof(pktinfo->ipi_addr));
#else
      /* OS's with ipi_spec_dst seem to put the source address in ipi_spec_dst
       * which is apparently a misnomer. */
      memset(&pktinfo->ipi_spec_dst, 0, sizeof(pktinfo->ipi_spec_dst));
#endif
    } else {
      pktinfo->ipi_ifindex = ep->ifindex;

#ifdef WSA_CMSG_SPACE
      /* OS's without ipi_spec_dst put the source address in ipi_addr. */
      memcpy(&pktinfo->ipi_addr,
	     &local_interface->addr.addr.sin.sin_addr,
	     local_interface->addr.size);
#else
      /* OS's with ipi_spec_dst seem to put the source address in ipi_spec_dst
       * which is apparently a misnomer. */
      memcpy(&pktinfo->ipi_spec_dst,
	     &local_interface->addr.addr.sin.sin_addr,
	     local_interface->addr.size);
#endif
    }
    break;
  }
  default:
    /* error */
    coap_log(LOG_WARNING, "protocol not supported\n");
    return -1;
  }

#ifdef WSA_CMSG_SPACE
  {
    int sent = 0;
    WSASendMsg(ep->handle.fd, &mhdr, 0, &sent, NULL, NULL);
    return sent;
  }
#else
  return sendmsg(ep->handle.fd, &mhdr, 0);
#endif
#else /* WITH_CONTIKI */
  /* FIXME: untested */
  /* FIXME: is there a way to check if send was successful? */
  uip_udp_packet_sendto((struct uip_udp_conn *)ep->handle.conn, data, datalen, 
			&dst->addr, dst->port);
  return datalen;
#endif /* WITH_CONTIKI */
}

#endif /* CUSTOM_COAP_NETWORK_SEND */

#ifndef CUSTOM_COAP_NETWORK_READ

#define SIN6(A) ((struct sockaddr_in6 *)(A))
#if !defined(WITH_LWIP) && !defined(WITH_CONTIKI)
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
#endif /* WITH_POSIX */
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
coap_get_max_packetlength(const coap_packet_t *packet UNUSED_PARAM) {
  return COAP_MAX_PDU_SIZE;
}

void
coap_packet_populate_endpoint(coap_packet_t *packet, coap_endpoint_t *target)
{
  target->handle = packet->endpoint->handle;
  memcpy(&target->addr, &packet->dst, sizeof(target->addr));
  target->ifindex = packet->ifindex;
  target->flags = 0; /* FIXME */
}
void
coap_packet_copy_source(coap_packet_t *packet, coap_address_t *target)
{
  memcpy(target, &packet->src, sizeof(coap_address_t));
}
void
coap_packet_get_memmapped(coap_packet_t *packet, unsigned char **address, size_t *length)
{
	*address = packet->payload;
	*length = packet->length;
}

/**
 * Checks if a message with destination address @p dst matches the
 * local interface with address @p local. This function returns @c 1
 * if @p dst is a valid match, and @c 0 otherwise.
 */
COAP_STATIC_INLINE int
is_local_if(const coap_address_t *local, const coap_address_t *dst) {
  return coap_address_isany(local) || coap_address_equals(dst, local) ||
    coap_is_mcast(dst);
}

ssize_t
coap_network_read(coap_endpoint_t *ep, coap_packet_t **packet) {
  ssize_t len = -1;

#ifdef WITH_POSIX
  char msg_control[CMSG_LEN(sizeof(struct sockaddr_storage))]; 
  struct msghdr mhdr;
  struct iovec iov[1];
#endif /* WITH_POSIX */

  assert(ep);
  assert(packet);

  *packet = coap_malloc_packet();
  
  if (!*packet) {
    warn("coap_network_read: insufficient memory, drop packet\n");
    return -1;
  }

  coap_address_init(&(*packet)->dst); /* the local interface address */
  coap_address_init(&(*packet)->src); /* the remote peer */

#ifdef WITH_POSIX
  iov[0].iov_base = (*packet)->payload;
  iov[0].iov_len = coap_get_max_packetlength(*packet);

  memset(&mhdr, 0, sizeof(struct msghdr));

  mhdr.msg_name = &(*packet)->src.addr.st;
  mhdr.msg_namelen = sizeof((*packet)->src.addr.st);

  mhdr.msg_iov = iov;
  mhdr.msg_iovlen = 1;
  
  mhdr.msg_control = msg_control;
  mhdr.msg_controllen = sizeof(msg_control);
  assert(sizeof(msg_control) == CMSG_LEN(sizeof(struct sockaddr_storage)));

  len = recvmsg(ep->handle.fd, &mhdr, 0);

  if (len < 0) {
    coap_log(LOG_WARNING, "coap_network_read: %s\n", strerror(errno));
    goto error;
  } else {
    struct cmsghdr *cmsg;

    coap_log(LOG_DEBUG, "received %d bytes on fd %d\n", (int)len, ep->handle.fd);

    /* use getsockname() to get the local port */
    (*packet)->dst.size = sizeof((*packet)->dst.addr);
    if (getsockname(ep->handle.fd, &(*packet)->dst.addr.sa, &(*packet)->dst.size) == COAP_SOCKET_ERROR) {
      coap_log(LOG_DEBUG, "cannot determine local port\n");
      goto error;
    }

    (*packet)->length = len;

    /* Walk through ancillary data records until the local interface
     * is found where the data was received. */
    for (cmsg = CMSG_FIRSTHDR(&mhdr); cmsg; cmsg = CMSG_NXTHDR(&mhdr, cmsg)) {
      
      /* get the local interface for IPv6 */
      if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
	union {
	  unsigned char *c;
	  struct in6_pktinfo *p;
	} u;
	u.c = CMSG_DATA(cmsg);
	(*packet)->ifindex = (int)(u.p->ipi6_ifindex);

	memcpy(&(*packet)->dst.addr.sin6.sin6_addr, 
	       &u.p->ipi6_addr, sizeof(struct in6_addr));

	(*packet)->src.size = mhdr.msg_namelen;
	assert((*packet)->src.size == sizeof(struct sockaddr_in6));

	(*packet)->src.addr.sin6.sin6_family = SIN6(mhdr.msg_name)->sin6_family;
	(*packet)->src.addr.sin6.sin6_addr = SIN6(mhdr.msg_name)->sin6_addr;
	(*packet)->src.addr.sin6.sin6_port = SIN6(mhdr.msg_name)->sin6_port;

	break;
      }

      /* local interface for IPv4 */
      if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_PKTINFO) {
	union {
	  unsigned char *c;
	  struct in_pktinfo *p;
	} u;

	u.c = CMSG_DATA(cmsg);
	(*packet)->ifindex = u.p->ipi_ifindex;

	memcpy(&(*packet)->dst.addr.sin.sin_addr, 
	       &u.p->ipi_addr, sizeof(struct in_addr));

	(*packet)->src.size = mhdr.msg_namelen;
	memcpy(&(*packet)->src.addr.st, mhdr.msg_name, (*packet)->src.size);

	break;
      }
    }

    if (!is_local_if(&ep->addr, &(*packet)->dst)) {
      coap_log(LOG_DEBUG, "packet received on wrong interface, dropped\n");
      goto error;
    }
  }
#endif /* WITH_POSIX */
#ifdef WITH_CONTIKI
  /* FIXME: untested, make this work */
#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_UDP_BUF  ((struct uip_udp_hdr *)&uip_buf[UIP_LLIPH_LEN])

  if(uip_newdata()) {
    uip_ipaddr_copy(&(*packet)->src.addr, &UIP_IP_BUF->srcipaddr);
    (*packet)->src.port = UIP_UDP_BUF->srcport;
    uip_ipaddr_copy(&(*packet)->dst.addr, &UIP_IP_BUF->destipaddr);
    (*packet)->dst.port = UIP_UDP_BUF->destport;

    if (!is_local_if(&ep->addr, &(*packet)->dst)) {
      coap_log(LOG_DEBUG, "packet received on wrong interface, dropped\n");
      goto error;
    }

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

  (*packet)->endpoint = ep;

  return len;
 error:
  coap_free_packet(*packet);
  *packet = NULL;
  return -1;
}

#undef SIN6

#endif /*  CUSTOM_COAP_NETWORK_READ */
