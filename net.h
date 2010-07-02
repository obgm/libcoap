/* net.h -- CoAP network interface
 *
 * (c) 2010 Olaf Bergmann <bergmann@tzi.org>
 */

#ifndef _COAP_NET_H_
#define _COAP_NET_H_

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>

#include "pdu.h"

struct coap_listnode {
  struct coap_listnode *next;

  time_t t;			/* when to send PDU for the next time */
  unsigned char retransmit_cnt;	/* retransmission counter, will be removed when zero */
  
  struct sockaddr_in6 remote;	/* remote address */

  coap_pdu_t *pdu;		/* the CoAP PDU to send */
};

typedef struct coap_listnode coap_sendqueue_t;

/* adds node to given queue, ordered by timestamp */
int coap_insert_node(coap_sendqueue_t **queue, coap_sendqueue_t *node);

/* removes all items from given queue and frees the allocated storage */
void coap_delete_all(coap_sendqueue_t *queue);

/* creates a new node suitable for adding to the CoAP sendqueue */
coap_sendqueue_t *coap_new_node();

#endif /* _COAP_NET_H_ */
