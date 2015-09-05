#include "coap_io.h"

#include "debug.h"
#include "mem.h"
#include "coap_io.h"

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
  ep->handle.fd = sockfd;
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
    if (ep->handle.fd >= 0)
      close(ep->handle.fd);
    coap_free_posix_endpoint((struct coap_endpoint_t *)ep);
  }
}



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


