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
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_SYS_UIO_H
# include <sys/uio.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <errno.h>
#include <fcntl.h>

#include "debug.h"
#include "mem.h"
#include "coap_dtls.h"
#include "coap_io.h"

struct coap_packet_t {
  coap_if_handle_t hnd;	      /**< the interface handle */
  coap_address_t src;	      /**< the packet's source address */
  coap_address_t dst;	      /**< the packet's destination address */
  const coap_endpoint_t *interface;

  int ifindex;
  void *session;		/**< opaque session data */

  size_t length;		/**< length of payload */
  unsigned char payload[];	/**< payload */
};

#ifndef CUSTOM_COAP_NETWORK_ENDPOINT

static inline struct coap_endpoint_t *
coap_malloc_posix_endpoint(void) {
  return (struct coap_endpoint_t *)coap_malloc(sizeof(struct coap_endpoint_t));
}

static inline void
coap_free_posix_endpoint(struct coap_endpoint_t *ep) {
  coap_free(ep);
}

coap_endpoint_t *
coap_new_endpoint(const coap_address_t *addr, int flags) {
  int sockfd;
  int on = 1;
  struct coap_endpoint_t *ep = NULL;

  if (((flags & COAP_ENDPOINT_DTLS) != 0) && !coap_dtls_is_supported()) {
    coap_log(LOG_CRIT, "coap_new_endpoint: DTLS not supported\n");
    return NULL;
  }

  sockfd = socket(addr->addr.sa.sa_family, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    coap_log(LOG_WARNING, "coap_new_endpoint: socket");
    return NULL;
  }

  if (fcntl(sockfd, F_SETFL, O_NONBLOCK) < 0) {
    coap_log(LOG_WARNING, "coap_new_endpoint: %s\n", strerror(errno));
    goto error;
  }

  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
    coap_log(LOG_WARNING, "coap_new_endpoint: setsockopt SO_REUSEADDR");

  on = 1;
  switch(addr->addr.sa.sa_family) {
  case AF_INET:
    if (setsockopt(sockfd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) < 0)
      coap_log(LOG_ALERT, "coap_new_endpoint: setsockopt IP_PKTINFO\n");
    break;
  case AF_INET6:
#ifdef IPV6_RECVPKTINFO
    if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0)
      coap_log(LOG_ALERT, "coap_new_endpoint: setsockopt IPV6_RECVPKTINFO\n");
#else /* IPV6_RECVPKTINFO */
    if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_PKTINFO, &on, sizeof(on)) < 0)
      coap_log(LOG_ALERT, "coap_new_endpoint: setsockopt IPV6_PKTINFO\n");
#endif /* IPV6_RECVPKTINFO */
    break;
  default:
    coap_log(LOG_ALERT, "coap_new_endpoint: unsupported sa_family\n");
  }

  if (bind(sockfd, &addr->addr.sa, addr->size) < 0) {
    coap_log(LOG_WARNING, "coap_new_endpoint: bind");
    goto error;
  }

  ep = coap_malloc_posix_endpoint();
  if (!ep) {
    coap_log(LOG_WARNING, "coap_new_endpoint: malloc");
    goto error;
  }

  memset(ep, 0, sizeof(struct coap_endpoint_t));
  ep->handle.fd = sockfd;
  ep->flags = flags;

  ep->addr.size = addr->size;
  if (getsockname(sockfd, &ep->addr.addr.sa, &ep->addr.size) < 0) {
    coap_log(LOG_WARNING, "coap_new_endpoint: cannot determine local address");
    goto error;
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
 error:

  close (sockfd);
  coap_free_posix_endpoint(ep);
  return NULL;
}

void
coap_free_endpoint(coap_endpoint_t *ep) {
  if(ep) {
    if (ep->handle.fd >= 0)
      close(ep->handle.fd);
    coap_free_posix_endpoint((struct coap_endpoint_t *)ep);
  }
}

#endif /* CUSTOM_COAP_NETWORK_ENDPOINT */

#ifndef CUSTOM_COAP_NETWORK_SEND

#ifndef HAVE_NETINET_IN_H
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
#endif /* HAVE_NETINET_IN_H */

#if defined(WITH_POSIX) && !defined(SOL_IP)
/* Solaris expects level IPPROTO_IP for ancillary data. */
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

  /* a buffer large enough to hold all protocol address types */
  char buf[CMSG_LEN(sizeof(struct sockaddr_storage))];
  struct msghdr mhdr;
  struct iovec iov[1];

  assert(local_interface);

  iov[0].iov_base = data;
  iov[0].iov_len = datalen;

  memset(&mhdr, 0, sizeof(struct msghdr));
  mhdr.msg_name = (void *)&dst->addr;
  mhdr.msg_namelen = dst->size;

  mhdr.msg_iov = iov;
  mhdr.msg_iovlen = 1;

  switch (dst->addr.sa.sa_family) {
  case AF_INET6: {
    struct cmsghdr *cmsg;
    struct in6_pktinfo *pktinfo;

    mhdr.msg_control = buf;
    mhdr.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));

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

    mhdr.msg_control = buf;
    mhdr.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));

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
      memset(&pktinfo->ipi_spec_dst, 0, sizeof(pktinfo->ipi_spec_dst));
    } else {
      pktinfo->ipi_ifindex = ep->ifindex;
      memcpy(&pktinfo->ipi_spec_dst,
	     &local_interface->addr.addr.sin.sin_addr,
	     local_interface->addr.size);
    }
    break;
  }
  default:
    /* error */
    coap_log(LOG_WARNING, "protocol not supported\n");
    return -1;
  }

  return sendmsg(ep->handle.fd, &mhdr, 0);
}

#endif /* CUSTOM_COAP_NETWORK_SEND */

#ifndef CUSTOM_COAP_NETWORK_READ

#define SIN6(A) ((struct sockaddr_in6 *)(A))

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

static inline size_t
coap_get_max_packetlength(const coap_packet_t *packet UNUSED_PARAM) {
  return COAP_MAX_PDU_SIZE;
}

void
coap_packet_populate_endpoint(coap_packet_t *packet, coap_endpoint_t *target) {
  target->handle = packet->interface->handle;
  memcpy(&target->addr, &packet->dst, sizeof(target->addr));
  target->ifindex = packet->ifindex;
  target->flags = 0; /* FIXME */
}
void
coap_packet_copy_source(coap_packet_t *packet, coap_address_t *target) {
  memcpy(target, &packet->src, sizeof(coap_address_t));
}
void
coap_packet_get_memmapped(coap_packet_t *packet, unsigned char **address, size_t *length) {
  *address = packet->payload;
  *length = packet->length;
}

/**
 * Checks if a message with destination address @p dst matches the
 * local interface with address @p local. This function returns @c 1
 * if @p dst is a valid match, and @c 0 otherwise.
 */
static inline int
is_local_if(const coap_address_t *local, const coap_address_t *dst) {
  return coap_address_isany(local) || coap_address_equals(dst, local) ||
    coap_is_mcast(dst);
}

ssize_t
coap_network_read(coap_endpoint_t *ep, coap_packet_t **packet) {
  ssize_t len = -1;

  char msg_control[CMSG_LEN(sizeof(struct sockaddr_storage))];
  struct msghdr mhdr;
  struct iovec iov[1];

  assert(ep);
  assert(packet);

  if ((ep->flags & COAP_ENDPOINT_HAS_DATA) == 0) {
    return -1;
  } else {
    /* clear has-data flag */
    ep->flags &= ~COAP_ENDPOINT_HAS_DATA;
  }

  *packet = coap_malloc_packet();

  if (!*packet) {
    warn("coap_network_read: insufficient memory, drop packet\n");
    return -1;
  }

  coap_address_init(&(*packet)->dst); /* the local interface address */
  coap_address_init(&(*packet)->src); /* the remote peer */

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
    if (getsockname(ep->handle.fd, &(*packet)->dst.addr.sa, &(*packet)->dst.size) < 0) {
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

  (*packet)->interface = ep;

  return len;
 error:
  coap_free_packet(*packet);
  *packet = NULL;
  return -1;
}

#undef SIN6

#endif /*  CUSTOM_COAP_NETWORK_READ */
