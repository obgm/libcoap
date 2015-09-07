#include "coap_io.h"

#include <lwip/pbuf.h>
#include <lwip/udp.h>

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
coap_network_read(coap_endpoint_t *ep, coap_packet_t **packet) {
  // TODO not implemented
  return -1;
}

ssize_t
coap_network_send(struct coap_context_t *context UNUSED_PARAM,
                  const coap_endpoint_t *local_interface,
                  const coap_address_t *dst,
                  unsigned char *data,
                  size_t datalen) {
  struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, datalen, PBUF_REF);
  pbuf->payload = data;
  udp_sendto(context->endpoint->pcb, pdu->pbuf,
             &dst->addr, dst->port);
  pbuf_free(p);
}


