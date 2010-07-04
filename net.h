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

/* destroys specified node */
int coap_delete_node(coap_sendqueue_t *node);

/* removes all items from given queue and frees the allocated storage */
void coap_delete_all(coap_sendqueue_t *queue);

/* creates a new node suitable for adding to the CoAP sendqueue */
coap_sendqueue_t *coap_new_node();


/* The CoAP stack's global state is stored in a coap_context_t object */
typedef struct {
  coap_sendqueue_t *sendqueue;
  int sockfd;			/* send/receive socket */
} coap_context_t;

/* Returns the next pdu to send without removing from sendqeue. */
coap_sendqueue_t *coap_peek_next( coap_context_t *context );

/* Returns the next pdu to send and removes it from the sendqeue. */
coap_sendqueue_t *coap_pop_next( coap_context_t *context );

/* Creates a new coap_context_t object that will hold the CoAP stack status */
coap_context_t *coap_new_context();

/* CoAP stack context must be released with coap_free_context() */
void coap_free_context( coap_context_t *context );


/**
 * Sends a confirmed CoAP message to given destination. The memory that is allocated by pdu will
 * be released by coap_send_confirmed(). The caller must not make any assumption on the lifetime
 * of pdu.
 */
coap_tid_t coap_send_confirmed( coap_context_t *context, const struct sockaddr_in6 *dst, coap_pdu_t *pdu );

/**
 * Sends a non-confirmed CoAP message to given destination. The memory that is allocated by pdu will
 * be released by coap_send(). The caller must not make any assumption on the lifetime of pdu.
 */
coap_tid_t coap_send( coap_context_t *context, const struct sockaddr_in6 *dst, coap_pdu_t *pdu );

/* handles retransmissions of confirmable messages */
coap_tid_t coap_retransmit( coap_context_t *context, coap_sendqueue_t *node );

#endif /* _COAP_NET_H_ */
