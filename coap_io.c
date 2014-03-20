/* coap_io.h -- Default network I/O functions for libcoap
 *
 * Copyright (C) 2012 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

#include "config.h"

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

#ifdef WITH_CONTIKI
# include "uip.h"
#endif

#include "debug.h"
#include "mem.h"
#include "coap_io.h"

#ifndef CUSTOM_COAP_NETWORK_ENDPOINT

#ifdef WITH_CONTIKI
struct coap_contiki_endpoint_t {
  int handle;
  coap_address_t addr;
  struct uip_udp_conn *conn;	/**< uIP connection object */
};

static inline coap_contiki_endpoint_t *
coap_malloc_contiki_endpoint() {
  /* FIXME */
  return NULL;
}

static inline void
coap_free_contiki_endpoint(coap_endpoint_t *ep) {
  /* FIXME */
}

coap_endpoint_t *
coap_new_endpoint(const coap_address_t *addr, int flags) {
  static initialized = 0;
  struct coap_contiki_endpoint_t ep;

  if (initialized)
    return NULL;

  memset(&ep, 0, sizeof(struct coap_contiki_endpoint_t));
  ep.conn = udp_new(NULL, 0, NULL);

  if (!ep.conn)
    return NULL;

  memcpy(ep.addr, addr, sizeof(coap_address_t));
  udp_bind(ep.conn, addr->port);
  return &ep;
}

void
coap_free_endpoint(coap_endpoint_t *ep) {
  /* FIXME */
}

#else /* WITH_CONTIKI */
static inline struct coap_endpoint_t *
coap_malloc_posix_endpoint() {
  return (struct coap_endpoint_t *)coap_malloc(sizeof(struct coap_endpoint_t));
}

static inline void
coap_free_posix_endpoint(struct coap_endpoint_t *ep) {
  coap_free(ep);
}

coap_endpoint_t *
coap_new_endpoint(const coap_address_t *addr, int flags) {
  int sockfd = socket(addr->addr.sa.sa_family, SOCK_DGRAM, 0);
  int on = 1;
  struct coap_endpoint_t *ep;

  if (sockfd < 0) {
    coap_log(LOG_WARNING, "coap_new_endpoint: socket");
    return NULL;
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
    close (sockfd);
    return NULL;
  }

  ep = coap_malloc_posix_endpoint();
  if (!ep) {
    coap_log(LOG_WARNING, "coap_new_endpoint: malloc");
    close(sockfd);
    return NULL;
  }

  memset(ep, 0, sizeof(struct coap_endpoint_t));
  ep->handle = sockfd;
  ep->flags = flags;
  memcpy(&ep->addr, addr, sizeof(coap_address_t));
  
#ifndef NDEBUG
  if (LOG_DEBUG <= coap_get_log_level()) {
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 40
#endif
    unsigned char addr_str[INET6_ADDRSTRLEN+8];

    if (coap_print_addr(addr, addr_str, INET6_ADDRSTRLEN+8)) {
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
  if(ep) {
    if (ep->handle >= 0)
      close(ep->handle);
    coap_free_posix_endpoint((struct coap_endpoint_t *)ep);
  }
}

#endif /* WITH_CONTIKI */
#endif /* CUSTOM_COAP_NETWORK_ENDPOINT */

#ifndef CUSTOM_COAP_NETWORK_SEND

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
#ifndef WITH_CONTIKI
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
    memcpy(&pktinfo->ipi6_addr, 
	   &local_interface->addr.addr.sin6.sin6_addr, 
	   local_interface->addr.size);
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

    pktinfo->ipi_ifindex = ep->ifindex;
    memcpy(&pktinfo->ipi_spec_dst, 
	   &local_interface->addr.addr.sin.sin_addr, 
	   local_interface->addr.size);
    break;
  }
  default:
    /* error */
    coap_log(LOG_WARNING, "protocol not supported\n");
    return -1;
  }

  return sendmsg(ep->handle, &mhdr, 0);
#else /* WITH_CONTIKI */
  /* FIXME: untested */
  /* FIXME: is there a way to check if send was successful? */
  uip_udp_packet_sendto((uip_udp_conn *)interface, data, datalen, 
			&dst->addr, dst->port);
  return datalen;
#endif /* WITH_CONTIKI */
}

#endif /* CUSTOM_COAP_NETWORK_SEND */

#ifndef CUSTOM_COAP_NETWORK_READ

#define SIN6(A) ((struct sockaddr_in6 *)(A))

ssize_t
coap_network_read(coap_endpoint_t *local_interface,
		  coap_address_t *remote, 
		  unsigned char *buf, size_t buflen) {
  ssize_t len = -1;

#ifndef WITH_CONTIKI
  char msg_control[CMSG_LEN(sizeof(struct sockaddr_storage))]; 
  struct msghdr mhdr;
  struct iovec iov[1];
  struct coap_endpoint_t *ep = local_interface;
  coap_address_t local;
#endif /* WITH_CONTIKI */

  assert(local_interface);
  assert(remote);
  assert(buf);

  coap_address_init(&local);
  coap_address_init(remote);
  ep->ifindex = 0;

#ifndef WITH_CONTIKI
  iov[0].iov_base = buf;
  iov[0].iov_len = buflen;

  memset(&mhdr, 0, sizeof(struct msghdr));

  mhdr.msg_name = &remote->addr.st;
  mhdr.msg_namelen = sizeof(remote->addr.st);

  mhdr.msg_iov = iov;
  mhdr.msg_iovlen = 1;
  
  mhdr.msg_control = msg_control;
  mhdr.msg_controllen = sizeof(msg_control);
  assert(sizeof(msg_control) == CMSG_LEN(sizeof(struct sockaddr_storage)));

  len = recvmsg(ep->handle, &mhdr, 0);
  coap_log(LOG_DEBUG, "read %d bytes on fd %d\n", (int)len, ep->handle);

  buflen = 0;
  if (len >= 0) {
    struct cmsghdr *cmsg;

    /* use getsockname() to get the local port */
    local.size = sizeof(local.addr);
    if (getsockname(ep->handle, &local.addr.sa, &local.size) < 0) {
      coap_log(LOG_DEBUG, "cannot determine local port\n");
      return -1;
    }

    buflen = len;

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
	ep->ifindex = (int)(u.p->ipi6_ifindex);

	memcpy(&local.addr.sin6.sin6_addr, 
	       &u.p->ipi6_addr, sizeof(struct in6_addr));

	remote->size = mhdr.msg_namelen;
	remote->addr.sin6.sin6_family = SIN6(mhdr.msg_name)->sin6_family;
	remote->addr.sin6.sin6_addr = SIN6(mhdr.msg_name)->sin6_addr;
	remote->addr.sin6.sin6_port = SIN6(mhdr.msg_name)->sin6_port;

	break;
      }

      /* local interface for IPv4 */
      if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_PKTINFO) {
	union {
	  unsigned char *c;
	  struct in_pktinfo *p;
	} u;

	u.c = CMSG_DATA(cmsg);
	ep->ifindex = u.p->ipi_ifindex;
	memcpy(&local.addr.sin.sin_addr, 
	       &u.p->ipi_addr, sizeof(struct in_addr));

	remote->size = mhdr.msg_namelen;
	memcpy(&remote->addr.st, mhdr.msg_name, remote->size);

	break;
      }
    }
  }
#else /* WITH_CONTIKI */
  /* FIXME: untested, make this work */
#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_UDP_BUF  ((struct uip_udp_hdr *)&uip_buf[UIP_LLIPH_LEN])

  if(uip_newdata()) {
    uip_ipaddr_copy(&remote->addr, &UIP_IP_BUF->srcipaddr);
    remote->port = UIP_UDP_BUF->srcport;
    uip_ipaddr_copy(&local->addr, &UIP_IP_BUF->destipaddr);
    local->port = UIP_UDP_BUF->destport;

    len = uip_datalen();

    if (len > buflen) {
      return -1;
    }
    
    memcpy(buf, uip_appdata, len);
    /* PRINTF("Server received %d bytes from [", (int)len); */
    /* PRINT6ADDR(&local->addr); */
    /* PRINTF("]:%d\n", uip_ntohs(local->port)); */
  }
#undef UIP_IP_BUF
#undef UIP_UDP_BUF
#endif /* WITH_CONTIKI */

  return len;
}

#undef SIN6

#endif /*  CUSTOM_COAP_NETWORK_READ */
