#include "uip.h"

#include "address.h"

int coap_address_equals(const coap_address_t *a, const coap_address_t *b) {
  return a->port == b->port && uip_ipaddr_cmp(&a->addr,&b->addr);
}

int coap_address_isany(const coap_address_t *a) {
  /** @todo implementation of _coap_address_isany_impl() for Contiki */
  return 0; 
}

int coap_is_mcast(const coap_address_t *a) {
  return uip_is_addr_mcast(&a->addr);
}

void coap_address_init(coap_address_t *addr) {
  assert(addr);
  memset(addr, 0, sizeof(coap_address_t));
}

