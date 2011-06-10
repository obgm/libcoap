/* net.c -- CoAP network interface
 *
 * Copyright (C) 2010,2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

#include <ctype.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "debug.h"
#include "mem.h"
#include "str.h"
#include "resource.h"
#include "subscribe.h"
#include "option.h"
#include "net.h"

extern int snprintf(char *str, size_t size, const char *format, ...);

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

#ifndef NDEBUG
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
		unsigned char *result, unsigned int buflen, int encode_always ) {
  static unsigned char hex[] = "0123456789ABCDEF";
  unsigned int cnt = 0;
  while ( len && (cnt < buflen-1) ) {
    if ( !encode_always && isprint( *data ) ) {
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
  print_readable( data, len, buf, COAP_MAX_PDU_SIZE, 0 );
  printf(" %d:'%s'", type, buf );
}

void
show_data( coap_pdu_t *pdu ) {
  static unsigned char buf[COAP_MAX_PDU_SIZE];
  unsigned int len = (int)( (unsigned char *)pdu->hdr + pdu->length - pdu->data );
  print_readable( pdu->data, len, buf, COAP_MAX_PDU_SIZE, 0 );
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
  fflush(stdout);
}
#endif /* NDEBUG */

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
  if ( order( node, q ) < 0) {
    node->next = q;
    *queue = node;
    return 1;
  }

  /* search for right place to insert */
  do {
    p = q;
    q = q->next;
  } while ( q && order( node, q ) >= 0 );

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
#ifndef NDEBUG
    perror ("coap_new_node: malloc");
#endif
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
coap_new_context(const struct sockaddr *listen_addr, size_t addr_size) {
  coap_context_t *c = coap_malloc( sizeof( coap_context_t ) );
  time_t now;
  int reuse = 1;

  if (!listen_addr) {
    fprintf(stderr, "no listen address specified\n");
    return NULL;
  }

  srand( getpid() ^ time(&now) );

  if ( !c ) {
#ifndef NDEBUG
    perror("coap_init: malloc:");
#endif
    return NULL;
  }

  memset(c, 0, sizeof( coap_context_t ) );

  /* register the critical options that we know */
  coap_register_option(c, COAP_OPTION_CONTENT_TYPE);
  coap_register_option(c, COAP_OPTION_PROXY_URI);
  coap_register_option(c, COAP_OPTION_URI_HOST);
  coap_register_option(c, COAP_OPTION_URI_PORT);
  coap_register_option(c, COAP_OPTION_URI_PATH);
  coap_register_option(c, COAP_OPTION_TOKEN);
  coap_register_option(c, COAP_OPTION_URI_QUERY);

  c->sockfd = socket(listen_addr->sa_family, SOCK_DGRAM, 0);
  if ( c->sockfd < 0 ) {
#ifndef NDEBUG
    perror("coap_new_context: socket");
#endif
    goto onerror;
  }

  if ( setsockopt( c->sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse) ) < 0 ) {
#ifndef NDEBUG
    perror("setsockopt SO_REUSEADDR");
#endif
  }

  if ( bind (c->sockfd, listen_addr, addr_size) < 0 ) {
#ifndef NDEBUG
    perror("coap_new_context: bind");
#endif
    goto onerror;
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
  coap_resource_t *res, *rtmp;
  if ( !context )
    return;

  coap_delete_all(context->recvqueue);
  coap_delete_all(context->sendqueue);

  HASH_ITER(hh, context->resources, res, rtmp) {
    free(res);
  }

  coap_delete_list(context->subscriptions);
  close( context->sockfd );
  coap_free( context );
}

int
coap_option_check_critical(coap_context_t *ctx, 
			   coap_pdu_t *pdu,
			   coap_opt_filter_t unknown) {

  coap_opt_iterator_t opt_iter;
  int ok = 1;
  
  coap_option_iterator_init(pdu, &opt_iter, COAP_OPT_ALL);

  while (coap_option_next(&opt_iter)) {

    /* The following condition makes use of the fact that
     * coap_option_getb() returns -1 if type exceeds the bit-vector
     * filter. As the vector is supposed to be large enough to hold
     * the largest known option, we know that everything beyond is
     * bad.
     */
    if (opt_iter.type & 0x01 && 
	coap_option_getb(ctx->known_options, opt_iter.type) < 1) {
      debug("unknown critical option %d\n", opt_iter.type);
      
      ok = 0;

      /* When opt_iter.type is beyond our known option range,
       * coap_option_setb() will return -1 and we are safe to leave
       * this loop. */
      if (coap_option_setb(unknown, opt_iter.type) == -1)
	break;
    }
  }

  return ok;
}

/* releases space allocated by PDU if free_pdu is set */
coap_tid_t
coap_send_impl( coap_context_t *context, 
		const struct sockaddr *dst, socklen_t dstlen,
		coap_pdu_t *pdu, int free_pdu ) {
  ssize_t bytes_written;

  if ( !context || !dst || !pdu )
    return COAP_INVALID_TID;

  bytes_written = sendto( context->sockfd, pdu->hdr, pdu->length, 0,
			  dst, dstlen);

  if ( free_pdu )
    coap_delete_pdu( pdu );

  if ( bytes_written < 0 ) {
#ifndef NDEBUG
    perror("coap_send: sendto");
#endif
    return COAP_INVALID_TID;
  }

  return ntohs(pdu->hdr->id);
}

coap_tid_t
coap_send( coap_context_t *context, 
	   const struct sockaddr *dst, socklen_t dstlen, 
	   coap_pdu_t *pdu ) {
  return coap_send_impl( context, dst, dstlen, pdu, 1 );
}

int
_order_timestamp( coap_queue_t *lhs, coap_queue_t *rhs ) {
  return lhs && rhs && ( lhs->t < rhs->t ) ? -1 : 1;
}

void
coap_ticks(coap_tick_t *t) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  *t = tv.tv_sec * COAP_TICKS_PER_SECOND 
    + (tv.tv_usec >> 10) % COAP_TICKS_PER_SECOND;
}

coap_tid_t
coap_send_confirmed( coap_context_t *context, 
		     const struct sockaddr *dst, socklen_t addrlen, 
		     coap_pdu_t *pdu ) {
  coap_queue_t *node;
  int r;

  if (addrlen > sizeof(struct sockaddr_in6))
    return COAP_INVALID_TID;

  node = coap_new_node();

  r = rand();
  coap_ticks(&node->t);

  /* add randomized RESPONSE_TIMEOUT to determine retransmission timeout */
  node->timeout = COAP_DEFAULT_RESPONSE_TIMEOUT * COAP_TICKS_PER_SECOND +
    (COAP_DEFAULT_RESPONSE_TIMEOUT >> 1) *
    ((COAP_TICKS_PER_SECOND * (r & 0xFF)) >> 8);
  node->t += node->timeout;

  node->remote.size = addrlen;
  memcpy( &node->remote.addr.sa, dst, addrlen );
  node->pdu = pdu;

  if ( !coap_insert_node( &context->sendqueue, node, _order_timestamp ) ) {
#ifndef NDEBUG
    fprintf(stderr, "coap_send_confirmed: cannot insert node:into sendqueue\n");
#endif
    coap_delete_node ( node );
    return COAP_INVALID_TID;
  }

  return coap_send_impl( context, dst, addrlen, pdu, 0 );
}

coap_tid_t
coap_retransmit( coap_context_t *context, coap_queue_t *node ) {
  if ( !context || !node )
    return COAP_INVALID_TID;

  /* re-initialize timeout when maximum number of retransmissions are not reached yet */
  if ( node->retransmit_cnt < COAP_DEFAULT_MAX_RETRANSMIT ) {
    node->retransmit_cnt++;
    node->t += ( node->timeout << node->retransmit_cnt );
    coap_insert_node( &context->sendqueue, node, _order_timestamp );

    debug("** retransmission #%d of transaction %d\n",
	  node->retransmit_cnt, ntohs(node->pdu->hdr->id));

    return coap_send_impl( context, &node->remote.addr.sa, node->remote.size, 
			   node->pdu, 0 );
  }

  /* no more retransmissions, remove node from system */

  debug("** removed transaction %d\n", ntohs(node->pdu->hdr->id));

  coap_delete_node( node );
  return COAP_INVALID_TID;
}

int
_order_transaction_id( coap_queue_t *lhs, coap_queue_t *rhs ) {
  return ( lhs && rhs && lhs->pdu && rhs->pdu &&
	   ( lhs->pdu->hdr->id < lhs->pdu->hdr->id ) )
    ? -1
    : 1;
}

int
coap_read( coap_context_t *ctx ) {
  static char buf[COAP_MAX_PDU_SIZE];
  static coap_hdr_t *pdu = (coap_hdr_t *)buf;
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

  if ( bytes_read < sizeof(coap_hdr_t) ) {
    debug("coap_read: discarded invalid frame\n" );
    return -1;
  }

  if ( pdu->version != COAP_DEFAULT_VERSION ) {
    debug("coap_read: unknown protocol version\n" );
    return -1;
  }

  if (addrsize > sizeof(struct sockaddr_in6)) {
    debug("coap_read: cannote store remote address\n" );
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

  coap_ticks( &node->t );
  node->remote.size = addrsize;
  memcpy( &node->remote.addr.sa, &src, addrsize );

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

  if ( !queue || !*queue)
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

coap_queue_t *
coap_find_transaction(coap_queue_t *queue, coap_tid_t id) {
  if ( !queue )
    return 0;

  for (; queue; queue = queue->next) {
    if (queue->pdu && queue->pdu->hdr && queue->pdu->hdr->id == id)
      return queue;
  }
  return NULL;
}

void
coap_dispatch( coap_context_t *context ) {
  coap_queue_t *node, *sent;
  coap_uri_t uri;
  coap_pdu_t *response;
  coap_opt_filter_t unknown;

  if ( !context )
    return;

  memset(unknown, 0, sizeof(coap_opt_filter_t));

  while ( context->recvqueue ) {
    node = context->recvqueue;

    /* remove node from recvqueue */
    context->recvqueue = context->recvqueue->next;
    node->next = NULL;

    switch ( node->pdu->hdr->type ) {
    case COAP_MESSAGE_ACK :
      /* find transaction in sendqueue to stop retransmission */
      coap_remove_transaction( &context->sendqueue, node->pdu->hdr->id );
      break;
    case COAP_MESSAGE_RST :
      /* We have sent something the receiver disliked, so we remove
       * not only the transaction but also the subscriptions we might
       * have. */

      fprintf(stderr, "* got RST for transaction %u\n", ntohs(node->pdu->hdr->id) );
      sent = coap_find_transaction(context->sendqueue, node->pdu->hdr->id);
      if (sent && coap_get_request_uri(sent->pdu, &uri)) {
	/* The easy way: we still have the transaction that has caused
	* the trouble.*/

	coap_delete_subscription(context, coap_uri_hash(&uri), &node->remote.addr.sa);
      } else {
	/* ?? */
      }

      /* find transaction in sendqueue to stop retransmission */
      coap_remove_transaction( &context->sendqueue, node->pdu->hdr->id );
      break;
    case COAP_MESSAGE_NON :	/* check for unknown critical options */
      if (coap_option_check_critical(context, node->pdu, unknown) == 0)
	goto cleanup;
      break;
    case COAP_MESSAGE_CON :	/* check for unknown critical options */
      if (coap_option_check_critical(context, node->pdu, unknown) == 0) {
	coap_opt_iterator_t opt_iter;

	response = coap_new_pdu();
	if (response) {
	  response->hdr->type = COAP_MESSAGE_RST;
	  response->hdr->code = COAP_RESPONSE_CODE(402);
	  response->hdr->id = node->pdu->hdr->id;

	  coap_option_iterator_init(node->pdu, &opt_iter, unknown);
	
	  while (coap_option_next(&opt_iter)) {
	    if (opt_iter.type & 0x01) {
	      
	      coap_add_option(response, opt_iter.type, 
			      COAP_OPT_LENGTH(*opt_iter.option),
			      COAP_OPT_VALUE(*opt_iter.option));
	    }
	  }

	  if ( coap_send( context, &node->remote.addr.sa, node->remote.size, 
			  response ) 
	       == COAP_INVALID_TID ) {
	    debug("coap_dispatch: error sending reponse");
	    coap_delete_pdu(response);
	  }
	}	 

	goto cleanup;
      }
      break;
    }
   
    /* pass message to upper layer if a specific handler was registered */
    if ( context->msg_handler )
      context->msg_handler( context, node, NULL );
   
  cleanup:
    coap_delete_node( node );
  }
}

void
coap_register_message_handler( coap_context_t *context, coap_message_handler_t handler) {
  context->msg_handler = (void (*)( void *, coap_queue_t *, void *)) handler;
}

int
coap_can_exit( coap_context_t *context ) {
  return !context || (context->recvqueue == NULL && context->sendqueue == NULL);
}

