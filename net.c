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
#include <arpa/inet.h>

#include "debug.h"
#include "net.h"

#define options_start(p) ((coap_opt_t *) ( (unsigned char *)p->hdr + sizeof ( coap_hdr_t ) ))

#define options_end(p, opt) {			\
  unsigned char opt_code = 0, cnt;		\
  *opt = options_start( node->pdu );            \
  for ( cnt = (p)->hdr->optcnt; cnt; --cnt ) {  \
    opt_code += (*opt)->delta;			\
    *opt = (coap_opt_t *)( (unsigned char *)(*opt) + ((*opt)->length < 15 ? (*opt)->length + 1 : (*opt)->optval.longopt.length + 17) ); \
  } \
}

/************************************************************************
 ** some functions for debugging
 ************************************************************************/

#define LONGOPT(opt) (opt).optval.longopt
#define SHORTOPT(opt) (opt).optval.shortopt

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
      f ( opt, opt_code, opt->length, SHORTOPT(*opt).value );
      opt = (coap_opt_t *)( (unsigned char *)opt + opt->length + 1 );
    } else {
      f ( opt, opt_code, LONGOPT(*opt).length + 15, LONGOPT(*opt).value );
      opt = (coap_opt_t *)( (unsigned char *)opt + LONGOPT(*opt).length + 17 );
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
coap_show_pdu( coap_pdu_t *pdu ) {

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
coap_insert_node(coap_queue_t **queue, coap_queue_t *node,
		 int (*order)(coap_queue_t *, coap_queue_t *node) ) {
  coap_queue_t *p, *q;
  if ( !queue || !node )
    return 0;
    
  /* set queue head if empty */
  if ( !*queue ) {
    *queue = node;
    return 1;
  }

  /* replace queue head if PDU's time is less than head's time */
  q = *queue;
  if ( order( node, q ) ) {
    node->next = q;
    *queue = node;
    return 1;
  }

  /* search for right place to insert */
  do {
    p = q;
    q = q->next;
  } while ( q && ! order( node, q ) );
  
  /* insert new item */
  node->next = q;
  p->next = node;
  return 1;
}

int 
coap_delete_node(coap_queue_t *node) {
  if ( !node ) 
    return 0;

  free( node->pdu );
  free( node );  

  return 1;
}

void
coap_delete_all(coap_queue_t *queue) {
  if ( !queue ) 
    return;

  coap_delete_all( queue->next );
  coap_delete_node( queue );
}


coap_queue_t *
coap_new_node() {
  coap_queue_t *node = malloc ( sizeof *node );
  if ( ! node ) {
    perror ("coap_new_node: malloc");
    return NULL;
  }

  memset(node, 0, sizeof *node );
  return node;
}

coap_queue_t *
coap_peek_next( coap_context_t *context ) {
  if ( !context || !context->sendqueue )
    return NULL;

  return context->sendqueue;
}

coap_queue_t *
coap_pop_next( coap_context_t *context ) {
  coap_queue_t *next; 

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
    debug("send to [%s]:%d:\n  ",addr,ntohs(dst->sin6_port));
  }
  coap_show_pdu( pdu );
#endif

  bytes_written = sendto( context->sockfd, pdu->hdr, pdu->length, 0, 
			  (const struct sockaddr *)dst, sizeof( *dst ));
  
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

int
_order_timestamp( coap_queue_t *lhs, coap_queue_t *rhs ) {
  return lhs && rhs && ( lhs->t < rhs->t );
}
  
coap_tid_t
coap_send_confirmed( coap_context_t *context, const struct sockaddr_in6 *dst, coap_pdu_t *pdu ) {
  coap_queue_t *node;

  create_transaction_id( pdu->hdr->id );

  /* send once, and enter into message queue for retransmission unless
   * retransmission counter is reached */

  node = coap_new_node();
  time(&node->t);
  node->t += 1;		      /* 1 == 1 << 0 == 1 << retransmit_cnt */

  memcpy( &node->remote, dst, sizeof( struct sockaddr_in6 ) );
  node->pdu = pdu;

  if ( !coap_insert_node( &context->sendqueue, node, _order_timestamp ) ) {
#ifndef NDEBUG
    fprintf(stderr, "coap_send_confirmed: cannot insert node:into sendqueue\n");
#endif
    coap_delete_node ( node );
    return COAP_INVALID_TID;
  }

  return coap_send_impl( context, dst, pdu, 0 );
}

coap_tid_t
coap_retransmit( coap_context_t *context, coap_queue_t *node ) {
  if ( !context || !node )
    return COAP_INVALID_TID;

  /* re-initialize timeout when maximum number of retransmissions are not reached yet */
  if ( node->retransmit_cnt < COAP_DEFAULT_MAX_RETRANSMIT ) {
    node->retransmit_cnt++;
    node->t += ( 1 << node->retransmit_cnt );
    coap_insert_node( &context->sendqueue, node, _order_timestamp );

    debug("** retransmission #%d of transaction %d\n",
	   node->retransmit_cnt, node->pdu->hdr->id);

    return coap_send_impl( context, &node->remote, node->pdu, 0 );
  } 

  /* no more retransmissions, remove node from system */

  debug("** removed transaction %d\n", node->pdu->hdr->id);

  coap_delete_node( node );
  return COAP_INVALID_TID;
}

int
_order_transaction_id( coap_queue_t *lhs, coap_queue_t *rhs ) {
  return lhs && rhs && lhs->pdu && rhs->pdu &&
    ( lhs->pdu->hdr->id < lhs->pdu->hdr->id );
}  

int
coap_read( coap_context_t *ctx ) {
  static char buf[COAP_MAX_PDU_SIZE];
  ssize_t bytes_read;
  static struct sockaddr_in6 src;
  socklen_t addrsize = sizeof src;
  coap_queue_t *node;
  coap_opt_t *opt;

#ifndef NDEBUG
  static char addr[INET6_ADDRSTRLEN];
#endif

  bytes_read = recvfrom( ctx->sockfd, buf, COAP_MAX_PDU_SIZE, 0,
			 (struct sockaddr *)&src, &addrsize );

  if ( bytes_read < 0 ) {
    perror("coap_read: recvfrom");
    return -1;
  }

  if ( bytes_read < sizeof(coap_hdr_t) || ((coap_hdr_t *)buf)->version != COAP_DEFAULT_VERSION ) {
#ifndef NDEBUG
    fprintf(stderr, "coap_read: discarded invalid frame\n" ); 
#endif
    return -1;
  }

  node = coap_new_node();
  if ( !node ) 
    return -1;

  node->pdu = coap_new_pdu();
  if ( !node->pdu ) {
    coap_delete_node( node );
    return -1;
  }

  time( &node->t );
  memcpy( &node->remote, &src, sizeof( src ) );

  /* "parse" received PDU by filling pdu structure */
  memcpy( node->pdu->hdr, buf, bytes_read );
  node->pdu->length = bytes_read;
  
  /* finally calculate beginning of data block */
  options_end( node->pdu, &opt );

  if ( (unsigned char *)node->pdu->hdr + node->pdu->length < (unsigned char *)opt )
    node->pdu->data = (unsigned char *)node->pdu->hdr + node->pdu->length;
  else
    node->pdu->data = (unsigned char *)opt;

  /* and add new node to receive queue */
  coap_insert_node( &ctx->recvqueue, node, _order_transaction_id );
  
#ifndef NDEBUG
  if ( inet_ntop(src.sin6_family, &src.sin6_addr, addr, INET6_ADDRSTRLEN) == 0 ) {
    perror("coap_read: inet_ntop");
  } else {
    debug("** received from [%s]:%d:\n  ",addr,ntohs(src.sin6_port));
  }
  coap_show_pdu( node->pdu );
#endif

  return 0;
}

int
coap_remove_transaction( coap_queue_t **queue, coap_tid_t id ) {
  coap_queue_t *p, *q;

  if ( !queue )
    return 0;

  /* replace queue head if PDU's time is less than head's time */
    
  q = *queue;
  if ( id == q->pdu->hdr->id ) { /* found transaction */
    *queue = q->next;
    coap_delete_node( q );
    debug("*** removed transaction %u\n", id);
    return 1;
  }

  /* search transaction to remove (only first occurence will be removed) */
  do {
    p = q;
    q = q->next;
  } while ( q && id == q->pdu->hdr->id );
  
  if ( q ) {			/* found transaction */
    p->next = q->next;
    coap_delete_node( q );
    debug("*** removed transaction %u\n", id);
    return 1;    
  }

  return 0;
  
}

void 
coap_dispatch( coap_context_t *context ) {
  coap_queue_t *node;

  if ( !context ) 
    return;

  while ( context->recvqueue ) {
    node = context->recvqueue;

    switch ( node->pdu->hdr->type ) {
    case COAP_MESSAGE_ACK :
    case COAP_MESSAGE_RST :
      /* find transaction in sendqueue to stop retransmission */
      coap_remove_transaction( &context->sendqueue, node->pdu->hdr->id );
    }
    
    /* remove node from recvqueue */
    context->recvqueue = context->recvqueue->next;
    node->next = NULL;

    /* pass message to upper layer if a specific handler was registered */
    if ( context->msg_handler ) 
      context->msg_handler( context, node, NULL );

    coap_delete_node( node );
  }
  
}

void 
coap_register_message_handler( coap_context_t *context, coap_message_handler_t handler) {
  context->msg_handler = (void (*)( void *, coap_queue_t *, void *)) handler;
}


