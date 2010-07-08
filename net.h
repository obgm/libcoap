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

typedef struct coap_listnode coap_queue_t;

/* adds node to given queue, ordered by specified order function */
int coap_insert_node(coap_queue_t **queue, coap_queue_t *node, 
		     int (*order)(coap_queue_t *, coap_queue_t *node) );

/* destroys specified node */
int coap_delete_node(coap_queue_t *node);

/* removes all items from given queue and frees the allocated storage */
void coap_delete_all(coap_queue_t *queue);

/* creates a new node suitable for adding to the CoAP sendqueue */
coap_queue_t *coap_new_node();

/* The CoAP stack's global state is stored in a coap_context_t object */
typedef struct {
  coap_queue_t *sendqueue, *recvqueue;
  int sockfd;			/* send/receive socket */

  void ( *msg_handler )( void *, coap_queue_t *, void *);
} coap_context_t;

typedef void (*coap_message_handler_t)( coap_context_t  *, coap_queue_t *, void *);

/** 
 * Registers a new message handler that is called whenever a new PDU
 * was received. Note that the transactions are handled on the lower
 * layer previously to stop retransmissions, e.g. */
void coap_register_message_handler( coap_context_t *context, coap_message_handler_t handler);

/* Returns the next pdu to send without removing from sendqeue. */
coap_queue_t *coap_peek_next( coap_context_t *context );

/* Returns the next pdu to send and removes it from the sendqeue. */
coap_queue_t *coap_pop_next( coap_context_t *context );

/* Creates a new coap_context_t object that will hold the CoAP stack status. If port is
 * set to zero, the next free port will be used as server port, starting with COAP_DEFAULT_PORT.  */
coap_context_t *coap_new_context(in_port_t port);

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

/** Handles retransmissions of confirmable messages */
coap_tid_t coap_retransmit( coap_context_t *context, coap_queue_t *node );

/**
 * Reads data from the network and tries to parse as CoAP PDU. On success, 0 is returned
 * and a new node with the parsed PDU is added to the receive queue in the specified context
 * object.
 */
int coap_read( coap_context_t *context );

/** Removes transaction with specified id from given queue. Returns 0 if not found, 1 otherwise. */
int coap_remove_transaction( coap_queue_t **queue, coap_tid_t id );

/** Dispatches the PDUs from the receive queue in given context. */
void coap_dispatch( coap_context_t *context );

#endif /* _COAP_NET_H_ */
