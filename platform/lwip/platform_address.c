#include <lwip/ip_addr.h>

#include "address.h"

struct coap_address_t {
  uint16_t port;
  ip_addr_t addr;
};

/* FIXME oversimplification: just assuming it's an ipv4 address instead of
 * looking up the appropraite lwip function */
int coap_address_equals(const coap_address_t *a, const coap_address_t *b) {
  return a->addr.addr == b->addr.addr && a->port == b->port;
}

int coap_address_isany(const coap_address_t *a) {
  /** @todo implementation of _coap_address_isany_impl() for lwIP */
  return 0; 
}

int coap_is_mcast(const coap_address_t *a) {
  /* FIXME sure there is something in lwip */
  return 0;

}

void coap_address_init(coap_address_t *addr) {
  assert(addr);
  memset(addr, 0, sizeof(coap_address_t));
}

