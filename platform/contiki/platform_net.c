#include "net.h"

// FIXME
#include <limits.h>

void
coap_transaction_id(const coap_address_t *peer,
                    const coap_pdu_t *pdu, 
                    coap_tid_t *id) {
  coap_key_t h;
  memset(h, 0, sizeof(coap_key_t));

  /* Compare the transport address. */
  coap_hash((const unsigned char *)&peer->port, sizeof(peer->port), h);
  coap_hash((const unsigned char *)&peer->addr, sizeof(peer->addr), h);  
  coap_hash((const unsigned char *)&pdu->hdr->id, sizeof(unsigned short), h);

  *id = (((h[0] << 8) | h[1]) ^ ((h[2] << 8) | h[3])) & INT_MAX;
}


