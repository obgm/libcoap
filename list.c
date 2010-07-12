/* list.c -- CoAP list structures
 *
 * (c) 2010 Olaf Bergmann <bergmann@tzi.org>
 */

#include <stdio.h>
#include <string.h>

#include "mem.h"
#include "list.h"

int
coap_insert(coap_list_t **queue, coap_list_t *node,
	    int (*order)(void *, void *node) ) {
  coap_list_t *p, *q;
  if ( !queue || !node )
    return 0;
    
  /* set queue head if empty */
  if ( !*queue ) {
    *queue = node;
    return 1;
  }

  /* replace queue head if new node has to be added before the existing queue head */
  q = *queue;
  if ( order( node->data, q->data ) ) {
    node->next = q;
    *queue = node;
    return 1;
  }

  /* search for right place to insert */
  do {
    p = q;
    q = q->next;
  } while ( q && ! order( node->data, q->data ) );
  
  /* insert new item */
  node->next = q;
  p->next = node;
  return 1;
}

int 
coap_delete(coap_list_t *node) {
  if ( !node ) 
    return 0;

  coap_free( node->data );
  coap_free( node );  

  return 1;
}

void
coap_delete_list(coap_list_t *queue) {
  if ( !queue ) 
    return;

  coap_delete_list( queue->next );
  coap_delete( queue );
}

coap_list_t *
coap_new_listnode(void *data) {
  coap_list_t *node = coap_malloc( sizeof(coap_list_t) );
  if ( ! node ) {
    perror ("coap_new_listnode: malloc");
    return NULL;
  }

  memset(node, 0, sizeof(coap_list_t));
  node->data = data;
  return node;
}

