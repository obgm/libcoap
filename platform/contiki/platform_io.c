#include "coap_io.h"

#include "debug.h"
#include "mem.h"
#include "coap_io.h"

static int ep_initialized = 0;

static inline struct coap_endpoint_t *
coap_malloc_contiki_endpoint() {
  static struct coap_endpoint_t ep;

  if (ep_initialized) {
    return NULL;
  } else {
    ep_initialized = 1;
    return &ep;
  }
}

static inline void
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
coap_packet_copy_source(coap_packet_t *packet, coap_address_t *target)
{
  memcpy(target, &packet->src, sizeof(coap_address_t));
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

ssize_t
coap_network_send(struct coap_context_t *context UNUSED_PARAM,
		  const coap_endpoint_t *local_interface,
		  const coap_address_t *dst,
		  unsigned char *data,
		  size_t datalen) {

  struct coap_endpoint_t *ep = 
    (struct coap_endpoint_t *)local_interface;

  /* FIXME: untested */
  /* FIXME: is there a way to check if send was successful? */
  uip_udp_packet_sendto((struct uip_udp_conn *)ep->handle.conn, data, datalen, 
			&dst->addr, dst->port);
  return datalen;
}

coap_packet_t *
coap_malloc_packet(void) {
  return (coap_packet_t *)coap_malloc_type(COAP_PACKET, 0);
}

/* FIXME: untested, make this work */
#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_UDP_BUF  ((struct uip_udp_hdr *)&uip_buf[UIP_LLIPH_LEN])

ssize_t
coap_network_read(coap_endpoint_t *ep, coap_packet_t **packet) {
  ssize_t len = -1;

  assert(ep);
  assert(packet);

  *packet = coap_malloc_packet();
  
  if (!*packet) {
    warn("coap_network_read: insufficient memory, drop packet\n");
    return -1;
  }

  coap_address_init(&(*packet)->dst); /* the local interface address */
  coap_address_init(&(*packet)->src); /* the remote peer */

  if(uip_newdata()) {
    uip_ipaddr_copy(&(*packet)->src.addr, &UIP_IP_BUF->srcipaddr);
    (*packet)->src.port = UIP_UDP_BUF->srcport;
    uip_ipaddr_copy(&(*packet)->dst.addr, &UIP_IP_BUF->destipaddr);
    (*packet)->dst.port = UIP_UDP_BUF->destport;

    if (!coap_is_local_if(&ep->addr, &(*packet)->dst)) {
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

  (*packet)->interface = ep;

  return len;
 error:
  coap_free_packet(*packet);
  *packet = NULL;
  return -1;
}

