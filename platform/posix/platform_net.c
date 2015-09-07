#include "net.h"

#include <limits.h>

void coap_transaction_id(const coap_address_t *peer,
                         const coap_pdu_t *pdu,
                         coap_tid_t *id) {
  coap_key_t h;

  memset(h, 0, sizeof(coap_key_t));

  /* Compare the transport address. */
  switch (peer->addr.sa.sa_family) {
  case AF_INET:
    coap_hash((const unsigned char *)&peer->addr.sin.sin_port,
        sizeof(peer->addr.sin.sin_port), h);
    coap_hash((const unsigned char *)&peer->addr.sin.sin_addr,
        sizeof(peer->addr.sin.sin_addr), h);
    break;
  case AF_INET6:
    coap_hash((const unsigned char *)&peer->addr.sin6.sin6_port,
        sizeof(peer->addr.sin6.sin6_port), h);
    coap_hash((const unsigned char *)&peer->addr.sin6.sin6_addr,
        sizeof(peer->addr.sin6.sin6_addr), h);
    break;
  default:
    return;
  }

  coap_hash((const unsigned char *)&pdu->hdr->id, sizeof(unsigned short), h);

  *id = (((h[0] << 8) | h[1]) ^ ((h[2] << 8) | h[3])) & INT_MAX;
}
