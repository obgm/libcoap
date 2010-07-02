/* net.c -- CoAP network interface
 *
 * (c) 2010 Olaf Bergmann <bergmann@tzi.org>
 */

#include "net.h"

int
coap_insert_node(coap_sendqueue_t **queue, coap_sendqueue_t *node) {
  coap_sendqueue_t *p, *q;
  if ( !queue || !node )
    return 0;
    
  /* set queue head if empty */
  if ( !*queue ) {
    *queue = node;
    return 1;
  }

  /* replace queue head if PDU's time is less than head's time */
  q = *queue;
  if ( node->t < q->t ) {
    node->next = q;
    *queue = node;
    return 1;
  }

  /* search for right place to insert */
  do {
    p = q;
    q = q->next;
  } while ( q && ! (node->t < q->t) );
  
  /* insert new item */
  node->next = q;
  p->next = node;
  return 1;
}

void
coap_delete_all(coap_sendqueue_t *queue) {
  if ( !queue ) 
    return;

  coap_delete_all( queue->next );

  free( queue->pdu );
  free( queue );
}


coap_sendqueue_t *
coap_new_node() {
  coap_sendqueue_t *node = malloc ( sizeof *node );
  if ( ! node ) {
    perror ("coap_new_node: malloc");
    return NULL;
  }

  memset(node, 0, sizeof *node );
  node->retransmit_cnt = COAP_DEFAULT_MAX_RETRANSMIT;
  return node;
}
