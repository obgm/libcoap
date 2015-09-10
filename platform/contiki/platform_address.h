#ifndef _PLATFORM_ADDRESS_H_
#define _PLATFORM_ADDRESS_H_

struct coap_address_t {
  uip_ipaddr_t addr;
  unsigned short port;
};

#endif /* _PLATFORM_ADDRESS_H_ */

