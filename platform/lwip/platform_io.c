#include "coap_io.h"

#include <lwip/pbuf.h>
#include <lwip/udp.h>

#include "debug.h"
#include "mem.h"
#include "coap_io.h"

/*
void coap_packet_populate_endpoint(coap_packet_t *packet, coap_endpoint_t *target)
{
  printf("FIXME no endpoint populated\n");
}
*/

void coap_packet_copy_source(coap_packet_t *packet, coap_address_t *target)
{
  target->port = packet->srcport;
  memcpy(&target->addr, ip_current_src_addr(), sizeof(ip_addr_t));
}

/** Callback from lwIP when a package was received.
 *
 * The current implementation deals this to coap_handle_message immedately, but
 * other mechanisms (as storing the package in a queue and later fetching it
 * when coap_read is called) can be envisioned.
 *
 * It handles everything coap_read does on other implementations.
 */
static void coap_recv(void *arg, struct udp_pcb *upcb, struct pbuf *p, ip_addr_t *addr, u16_t port)
{
  coap_endpoint_t *ep = (coap_endpoint_t*)arg;

  LWIP_ASSERT("Can only deal with contiguous PBUFs to read the initial details",
      p->tot_len == p->len);

  coap_packet_t *packet = coap_malloc_type(COAP_PACKET, sizeof(coap_packet_t));
  /* this is fatal because due to the short life of the packet, never should there be more than one coap_packet_t required */
  LWIP_ASSERT("Insufficient coap_packet_t resources.", packet != NULL);

  packet->data = p->payload;
  packet->data_len = p->tot_len;
  packet->srcport = port;

  /** FIXME derive the context without changing endopint definition */
  coap_handle_message(ep->context, packet);

  coap_free_packet(packet);
  // Free the pbuf that the data comes from
  if (p) {
      pbuf_free(p);
  }
}


coap_endpoint_t *
coap_new_endpoint(const coap_address_t *addr, int flags) {
  coap_endpoint_t *result;
  err_t err;

  LWIP_ASSERT("Flags not supported for LWIP endpoints", flags == COAP_ENDPOINT_NOSEC);

  result = coap_malloc_type(COAP_ENDPOINT, sizeof(coap_endpoint_t));
  if (!result) return NULL;

  result->pcb = udp_new();
  if (result->pcb == NULL) goto error;

  udp_recv(result->pcb, coap_recv, (void*)result);
  err = udp_bind(result->pcb, &addr->addr, addr->port);
  if (err) {
    udp_remove(result->pcb);
    goto error;
  }

  return result;

error:
  coap_free_type(COAP_ENDPOINT, result);
  return NULL;
}

void
coap_free_endpoint(coap_endpoint_t *ep) {
  udp_remove(ep->pcb);
  coap_free_type(COAP_ENDPOINT, ep);
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


