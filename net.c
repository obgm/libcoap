/* net.c -- CoAP network interface
 *
 * (c) 2010 Olaf Bergmann <bergmann@tzi.org>
 */

#include <ctype.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "debug.h"
#include "mem.h"
#include "net.h"

#define options_start(p) ((coap_opt_t *) ( (unsigned char *)p->hdr + sizeof ( coap_hdr_t ) ))

#define options_end(p, opt) {			\
  unsigned char opt_code = 0, cnt;		\
  *opt = options_start( node->pdu );            \
  for ( cnt = (p)->hdr->optcnt; cnt; --cnt ) {  \
    opt_code += COAP_OPT_DELTA(**opt);			\
    *opt = (coap_opt_t *)( (unsigned char *)(*opt) + COAP_OPT_SIZE(**opt)); \
  } \
}

/************************************************************************
 ** some functions for debugging
 ************************************************************************/

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
    opt_code += COAP_OPT_DELTA(*opt);

    f ( opt, opt_code, COAP_OPT_LENGTH(*opt), COAP_OPT_VALUE(*opt) );
    opt = (coap_opt_t *)( (unsigned char *)opt + COAP_OPT_SIZE(*opt) );
  }
}


unsigned int
print_readable( const unsigned char *data, unsigned int len, 
		unsigned char *result, unsigned int buflen ) {
  static unsigned char hex[] = "0123456789ABCDEF";
  unsigned int cnt = 0;
  while ( len && (cnt < buflen-1) ) {
    if ( isprint( *data ) ) {
      *result++ = *data;
      ++cnt;
    } else {
      if ( cnt+4 < buflen-1 ) {
	*result++ = '\\';
	*result++ = 'x';
	*result++ = hex[(*data & 0xf0) >> 4];
	*result++ = hex[*data & 0x0f ];	
	cnt += 4;
      } else 
	break;
    }

    ++data; --len;
  }
  
  *result = '\0';
  return cnt;
}

void 
show( coap_opt_t *opt, unsigned char type, unsigned int len, const unsigned char *data ) {
  static unsigned char buf[COAP_MAX_PDU_SIZE];
  print_readable( data, len, buf, COAP_MAX_PDU_SIZE );
  printf( " %d:'%s'", type, buf );
}

void 
show_data( coap_pdu_t *pdu ) {
  static unsigned char buf[COAP_MAX_PDU_SIZE];
  unsigned int len = (int)( (unsigned char *)pdu->hdr + pdu->length - pdu->data );
  print_readable( pdu->data, len, buf, COAP_MAX_PDU_SIZE );
  printf("'%s'", buf);
}

void
coap_show_pdu( coap_pdu_t *pdu ) {

  printf("pdu (%d bytes)", pdu->length);
  printf(" v:%d t:%d oc:%d c:%d id:%u", pdu->hdr->version, pdu->hdr->type,
	 pdu->hdr->optcnt, pdu->hdr->code, ntohs(pdu->hdr->id));
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

  coap_free( node->pdu );
  coap_free( node );  

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
  coap_queue_t *node = coap_malloc ( sizeof *node );
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
coap_new_context(in_port_t port) {
  coap_context_t *c = coap_malloc( sizeof( coap_context_t ) );
  struct sockaddr_in6 addr;
  time_t now;
  int reuse = 1, need_port = 1;

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
  
  if ( setsockopt( c->sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse) ) < 0 )
    perror("setsockopt SO_REUSEADDR");

  if ( port == 0 ) {
    port = COAP_DEFAULT_PORT;
    need_port = 0;
  }

  memset(&addr, 0, sizeof addr );
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons( port );
  memcpy( &addr.sin6_addr, &in6addr_any, sizeof addr.sin6_addr );

  if ( bind (c->sockfd, (struct sockaddr *)&addr, sizeof addr) < 0 ) {
    if (need_port) {
      perror("coap_new_context: bind");
      goto onerror;
    }
    
    do {
      addr.sin6_port = htons( ++port );
    } while (bind (c->sockfd, (struct sockaddr *)&addr, sizeof addr) < 0);
  } 
  
  return c;

 onerror:
  if ( c->sockfd >= 0 ) 
    close ( c->sockfd );
  coap_free( c );
  return NULL;
}

void
coap_free_context( coap_context_t *context ) {
  if ( !context )
    return;

  coap_delete_all(context->sendqueue);
  close( context->sockfd );
  coap_free( context );
}

#ifdef __STRICT_ANSI__
#include <stdarg.h>
void debug(char *format, ...) {
  va_list ap;
  
  va_start(ap, format);	/* bf being the last argument before '...' */
  vprintf(format, ap);
  va_end(ap);
}
#endif

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

  return ntohs(pdu->hdr->id);
}

#define create_transaction_id(T) do { T = (unsigned short)rand(); } while ( T == COAP_INVALID_TID );

coap_tid_t
coap_send( coap_context_t *context, const struct sockaddr_in6 *dst, coap_pdu_t *pdu ) {
  if ( ntohs(pdu->hdr->id) == COAP_INVALID_TID )
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

  if ( ntohs(pdu->hdr->id) == COAP_INVALID_TID )
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
	  node->retransmit_cnt, ntohs(node->pdu->hdr->id));

    return coap_send_impl( context, &node->remote, node->pdu, 0 );
  } 

  /* no more retransmissions, remove node from system */

  debug("** removed transaction %d\n", ntohs(node->pdu->hdr->id));

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
    debug("*** removed transaction %u\n", ntohs(id));
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
    debug("*** removed transaction %u\n", ntohs(id));
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


