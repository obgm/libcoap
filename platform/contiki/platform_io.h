#include "uip.h"

/*
 * This is only included in coap_io.h instead of .c in order to be available for
 * sizeof in mem.c.
 */
struct coap_packet_t {
  coap_if_handle_t hnd;         /**< the interface handle */
  coap_address_t src;           /**< the packet's source address */
  coap_address_t dst;           /**< the packet's destination address */
  const coap_endpoint_t *interface;
  int ifindex;
  void *session;                /**< opaque session data */
  size_t length;                /**< length of payload */
  unsigned char payload[];      /**< payload */
};

