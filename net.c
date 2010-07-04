/* net.c -- CoAP network interface
 *
 * (c) 2010 Olaf Bergmann <bergmann@tzi.org>
 */

#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "net.h"

/************************************************************************
 ** some functions for debugging
 ************************************************************************/

#define options_start(p) ((coap_opt_t *) ( (unsigned char *)p->hdr + sizeof ( coap_hdr_t ) ))

void 
for_each_option(coap_pdu_t *pdu, 
		void (*f)(coap_opt_t *, unsigned char, unsigned int, const unsigned char *) ) {
  unsigned char cnt;
  coap_opt_t *opt;
  unsigned char opt_code = 0;
  
  if (! pdu )
    return;

  opt = options_start( pdu );
  for ( cnt = pdu->hdr->optcnt; cnt; --cnt ) {
    opt_code += opt->delta;

    if ( opt->length < 15 ) {
      f ( opt, opt_code, opt->length, opt->shortopt.value );
      opt = (coap_opt_t *)( (unsigned char *)opt + opt->length + 1 );
    } else {
      f ( opt, opt_code, opt->longopt.length + 15, opt->longopt.value );
      opt = (coap_opt_t *)( (unsigned char *)opt + opt->longopt.length + 17 );
    }
  }
}

void 
show( coap_opt_t *opt, unsigned char type, unsigned int len, const unsigned char *data ) {
  char buf[64];
  memset(buf, 0, 64);
  snprintf(buf, len + 1, "%s", data);
  printf( " %d:'%s'", type, buf );
}

void 
show_data( coap_pdu_t *pdu ) {
  char buf[64];
  memset(buf, 0, 64);
  snprintf(buf, (int)( (unsigned char *)pdu->hdr + pdu->length - pdu->data ) + 1, "%s", pdu->data);
  printf("'%s'", buf);
}

void
show_pdu( coap_pdu_t *pdu ) {

  printf("pdu (%d bytes)", pdu->length);
  printf(" v:%d t:%d oc:%d c:%d id:%d", pdu->hdr->version, pdu->hdr->type,
	 pdu->hdr->optcnt, pdu->hdr->code, pdu->hdr->id);
  if ( pdu->hdr->optcnt ) {
    printf(" o:");
    for_each_option ( pdu, show );
  }

  if ( pdu->data < (unsigned char *)pdu->hdr + pdu->length ) {
    printf("\n  data:");
    show_data ( pdu );
  }
  printf("\n");
}

/************************************************************************/

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

int 
coap_delete_node(coap_sendqueue_t *node) {
  if ( node ) {
    free( node->pdu );
    free( node );  
  }
}

void
coap_delete_all(coap_sendqueue_t *queue) {
  if ( !queue ) 
    return;

  coap_delete_all( queue->next );
  coap_delete_node( queue );
}


coap_sendqueue_t *
coap_new_node() {
  coap_sendqueue_t *node = malloc ( sizeof *node );
  if ( ! node ) {
    perror ("coap_new_node: malloc");
    return NULL;
  }

  memset(node, 0, sizeof *node );
  return node;
}

coap_sendqueue_t *
coap_peek_next( coap_context_t *context ) {
  if ( !context || !context->sendqueue )
    return NULL;

  return context->sendqueue;
}

coap_sendqueue_t *
coap_pop_next( coap_context_t *context ) {
  coap_sendqueue_t *next; 

  if ( !context || !context->sendqueue )
    return NULL;

  next = context->sendqueue;
  context->sendqueue = context->sendqueue->next;
  next->next = NULL;
  return next;
}

coap_context_t *
coap_new_context() {
  coap_context_t *c = malloc( sizeof( coap_context_t ) );
  struct sockaddr_in6 addr;
  time_t now;

  srand( getpid() ^ time(&now) );

  if ( !c ) {
    perror("coap_init: malloc:");
    return NULL;
  }

  memset(c, 0, sizeof( coap_context_t ) );

  c->sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
  if ( c->sockfd < 0 ) {
    perror("coap_new_context: socket");
    goto onerror;
  }

  memset(&addr, 0, sizeof addr );
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons( COAP_DEFAULT_PORT );
  memcpy( &addr.sin6_addr, &in6addr_any, sizeof addr.sin6_addr );

  if ( bind (c->sockfd, (struct sockaddr *)&addr, sizeof addr) < 0 ) {
    perror("coap_new_context: bind");
    goto onerror;
  }

  return c;

 onerror:
  if ( c->sockfd >= 0 ) 
    close ( c->sockfd );
  free( c );
  return NULL;
}

void
coap_free_context( coap_context_t *context ) {
  if ( !context )
    return;

  coap_delete_all(context->sendqueue);
  close( context->sockfd );
  free( context );
}

/* releases space allocated by PDU if free_pdu is set */
coap_tid_t
coap_send_impl( coap_context_t *context, const struct sockaddr_in6 *dst, coap_pdu_t *pdu,
		int free_pdu ) {
  ssize_t bytes_written;
#ifndef NDEBUG
  char addr[INET6_ADDRSTRLEN];/* buffer space for textual represenation of destination address  */
#endif

  if ( !context || !dst || !pdu )
    return COAP_INVALID_TID;

#ifndef NDEBUG
  if ( inet_ntop(dst->sin6_family, &dst->sin6_addr, addr, INET6_ADDRSTRLEN) == 0 ) {
    perror("coap_send_impl: inet_ntop");
  } else {
    printf("send to [%s]:%d:\n  ",addr,ntohs(dst->sin6_port));
  }
  show_pdu( pdu );
#endif

#if 0
  bytes_written = sendto( context->sockfd, pdu->hdr, pdu->length, 0, 
			  (const struct sockaddr *)dst, sizeof( *dst ));
#else
  bytes_written = 0;
#endif
  
  if ( free_pdu )
    coap_delete_pdu( pdu );

  if ( bytes_written < 0 ) {
    perror("coap_send: sendto");
    return COAP_INVALID_TID;
  }

  return pdu->hdr->id;;
}

#define create_transaction_id(T) do { T = (unsigned short)rand(); } while ( T == COAP_INVALID_TID );

coap_tid_t
coap_send( coap_context_t *context, const struct sockaddr_in6 *dst, coap_pdu_t *pdu ) {
  create_transaction_id( pdu->hdr->id );
  return coap_send_impl( context, dst, pdu, 1 );
}

coap_tid_t
coap_send_confirmed( coap_context_t *context, const struct sockaddr_in6 *dst, coap_pdu_t *pdu ) {
  coap_sendqueue_t *node;

  create_transaction_id( pdu->hdr->id );

  /* send once, and enter into message queue for retransmission unless
   * retransmission counter is reached */

  node = coap_new_node();
  time(&node->t);
  node->t += 1;		      /* 1 == 1 << 0 == 1 << retransmit_cnt */

  memcpy( &node->remote, dst, sizeof( struct sockaddr_in6 ) );
  node->pdu = pdu;

  if ( !coap_insert_node( &context->sendqueue, node ) ) {
    fprintf(stderr, "coap_send_confirmed: cannot ibsert node:into sendqueue\n");
    coap_delete_node ( node );
    return COAP_INVALID_TID;
  }

  return coap_send_impl( context, dst, pdu, 0 );
}

coap_tid_t
coap_retransmit( coap_context_t *context, coap_sendqueue_t *node ) {
  time_t now;

  if ( !context || !node )
    return COAP_INVALID_TID;

  /* re-initialize timeout when maximum number of retransmissions are not reached yet */
  if ( node->retransmit_cnt < COAP_DEFAULT_MAX_RETRANSMIT ) {
    node->retransmit_cnt++;
    node->t += ( 1 << node->retransmit_cnt );
    coap_insert_node( &context->sendqueue, node );

#ifndef NDEBUG
    printf("** retransmission #%d of transaction %d\n",
	   node->retransmit_cnt, node->pdu->hdr->id);
#endif
    return coap_send_impl( context, &node->remote, node->pdu, 0 );
  } 

  /* no more retransmissions, remove node from system */

#ifndef NDEBUG
    printf("** removed transaction %d\n", node->pdu->hdr->id);
#endif

  coap_delete_node( node );
  return COAP_INVALID_TID;
}
