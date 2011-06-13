/* net.c -- CoAP network interface
 *
 * Copyright (C) 2010,2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

#include "config.h"

#include <ctype.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "debug.h"
#include "mem.h"
#include "str.h"
#include "async.h"
#include "resource.h"
#include "option.h"
#include "encode.h"
#include "net.h"

time_t clock_offset;

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

#ifdef COAP_DEFAULT_WKC_HASHKEY
/** Checks if @p Key is equal to the pre-defined hash key for.well-known/core. */
#define is_wkc(Key)							\
  (memcmp((Key), COAP_DEFAULT_WKC_HASHKEY, sizeof(coap_key_t)) == 0)
#else
/* Implements a singleton to store a hash key for the .wellknown/core
 * resources. */
int
is_wkc(coap_key_t k) {
  static coap_key_t wkc;
  static unsigned char initialized = 0;
  if (!initialized) {
    initialized = coap_hash_path((unsigned char *)COAP_DEFAULT_URI_WELLKNOWN, 
				 sizeof(COAP_DEFAULT_URI_WELLKNOWN) - 1, wkc);
  return memcmp(k, wkc, sizeof(coap_key_t)) == 0;
}
#endif

coap_context_t *
coap_new_context(const struct sockaddr *listen_addr, size_t addr_size) {
  coap_context_t *c = coap_malloc( sizeof( coap_context_t ) );
  int reuse = 1;

  if (!listen_addr) {
    fprintf(stderr, "no listen address specified\n");
    return NULL;
  }

  coap_clock_init();
  prng_init((unsigned long)listen_addr ^ clock_offset);

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

  /* coap_delete_list(context->subscriptions); */
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
coap_send_impl(coap_context_t *context, 
	       const coap_address_t *dst,
	       coap_pdu_t *pdu, int free_pdu) {
  ssize_t bytes_written;

  if ( !context || !dst || !pdu )
    return COAP_INVALID_TID;

  bytes_written = sendto( context->sockfd, pdu->hdr, pdu->length, 0,
			  &dst->addr.sa, dst->size);

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
	   const coap_address_t *dst,
	   coap_pdu_t *pdu ) {
  return coap_send_impl(context, dst, pdu, 1);
}

int
_order_timestamp( coap_queue_t *lhs, coap_queue_t *rhs ) {
  return lhs && rhs && ( lhs->t < rhs->t ) ? -1 : 1;
}

coap_tid_t
coap_send_confirmed(coap_context_t *context, 
		    const coap_address_t *dst,
		    coap_pdu_t *pdu) {
  coap_queue_t *node;
  int r;

  node = coap_new_node();

  r = rand();
  coap_ticks(&node->t);

  /* add randomized RESPONSE_TIMEOUT to determine retransmission timeout */
  node->timeout = COAP_DEFAULT_RESPONSE_TIMEOUT * COAP_TICKS_PER_SECOND +
    (COAP_DEFAULT_RESPONSE_TIMEOUT >> 1) *
    ((COAP_TICKS_PER_SECOND * (r & 0xFF)) >> 8);
  node->t += node->timeout;

  memcpy(&node->remote, dst, sizeof(coap_address_t));
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
    node->t += ( node->timeout << node->retransmit_cnt );
    coap_insert_node( &context->sendqueue, node, _order_timestamp );

    debug("** retransmission #%d of transaction %d\n",
	  node->retransmit_cnt, ntohs(node->pdu->hdr->id));

    return coap_send_impl(context, &node->remote, node->pdu, 0);
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
  static coap_address_t src;
  coap_queue_t *node;

  coap_address_init(&src);
  bytes_read = recvfrom(ctx->sockfd, buf, sizeof(buf), 0,
			&src.addr.sa, &src.size);

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

  node = coap_new_node();
  if ( !node )
    return -1;

  node->pdu = coap_new_pdu();
  if ( !node->pdu ) {
    coap_delete_node( node );
    return -1;
  }

  coap_ticks( &node->t );
  memcpy(&node->remote, &src, sizeof(coap_address_t));

  /* "parse" received PDU by filling pdu structure */
  memcpy( node->pdu->hdr, buf, bytes_read );
  node->pdu->length = bytes_read;

  /* finally calculate beginning of data block */
  node->pdu->data = (unsigned char *)node->pdu->hdr + sizeof(coap_hdr_t);
  {
    coap_opt_iterator_t oi;
    coap_option_iterator_init(node->pdu, &oi, COAP_OPT_ALL);
    while(coap_option_next(&oi))
      node->pdu->data += COAP_OPT_SIZE(oi.option);
  }

  /* and add new node to receive queue */
  coap_insert_node( &ctx->recvqueue, node, _order_transaction_id );

#ifndef NDEBUG
  {
    static unsigned char addr[INET6_ADDRSTRLEN+8];

    if (coap_print_addr(&src, addr, sizeof(addr)))
      debug("** received %d bytes from %s:\n", bytes_read, addr);

    coap_show_pdu( node->pdu );
  }
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

#ifndef SHORT_ERROR_RESPONSE
typedef struct {
  unsigned char code;
  char *phrase;
} error_desc_t;

error_desc_t coap_error[] = {
  { COAP_RESPONSE_CODE(400), "Bad Request" },
  { COAP_RESPONSE_CODE(401), "Unauthorized" },
  { COAP_RESPONSE_CODE(402), "Bad Option" },
  { COAP_RESPONSE_CODE(403), "Forbidden" },
  { COAP_RESPONSE_CODE(404), "Not Found" },
  { COAP_RESPONSE_CODE(405), "Method Not Allowed" },
  { COAP_RESPONSE_CODE(408), "Request Entity Incomplete" },
  { COAP_RESPONSE_CODE(413), "Request Entity Too Large" },
  { COAP_RESPONSE_CODE(415), "Unsupported Media Type" },
  { COAP_RESPONSE_CODE(500), "Internal Server Error" },
  { COAP_RESPONSE_CODE(501), "Not Implemented" },
  { COAP_RESPONSE_CODE(502), "Bad Gateway" },
  { COAP_RESPONSE_CODE(503), "Service Unavailable" },
  { COAP_RESPONSE_CODE(504), "Gateway Timeout" },
  { COAP_RESPONSE_CODE(505), "Proxying Not Supported" },
  { 0, NULL }			/* end marker */
};

#define COAP_ERROR_PHRASE_LENGTH 32 /* maximum length of error phrase */
#endif

coap_pdu_t *
coap_new_error_response(coap_queue_t *node, unsigned char code, 
			coap_opt_filter_t opts) {
  coap_opt_iterator_t opt_iter;
  coap_pdu_t *response;
  size_t size = sizeof(coap_hdr_t);
  unsigned char buf[2];

#ifndef SHORT_ERROR_RESPONSE
  /* Need some more space for the error phrase and the Content-Type option */
  size += COAP_ERROR_PHRASE_LENGTH + 2;
#endif

  /* Estimate how much space we need for options to copy from
   * request. We always need the Token, for 4.02 the unknown critical
   * options must be included as well. */
  coap_option_clrb(opts, COAP_OPTION_CONTENT_TYPE); /* we do not want this */
  coap_option_setb(opts, COAP_OPTION_TOKEN);

  coap_option_iterator_init(node->pdu, &opt_iter, opts);

  while(coap_option_next(&opt_iter))
    size += COAP_OPT_SIZE(opt_iter.option);

  /* Now create the response and fill with options and payload data. */
  response = coap_pdu_init(COAP_MESSAGE_ACK, code, node->pdu->hdr->id, size);
  if (response) {
#ifndef SHORT_ERROR_RESPONSE
    coap_add_option(response, COAP_OPTION_CONTENT_TYPE, 
	    coap_encode_var_bytes(buf, COAP_MEDIATYPE_TEXT_PLAIN), buf);
#endif

    /* copy all options */
    coap_option_iterator_init(node->pdu, &opt_iter, opts);
    while(coap_option_next(&opt_iter))
      coap_add_option(response, opt_iter.type, 
		      COAP_OPT_LENGTH(opt_iter.option),
		      COAP_OPT_VALUE(opt_iter.option));
    
#ifndef SHORT_ERROR_RESPONSE
    {
      int i = 0;
      while (coap_error[i].code) {
	if (coap_error[i].code == code) {
	  coap_add_data(response, strlen(coap_error[i].phrase), 
			(unsigned char *)coap_error[i].phrase);
	  break;
	}
	++i;
      }
    }
#endif
  }

  return response;
}

/** 
 * Prints the names of all known resources to @p buf. This function
 * sets @p buflen to the number of bytes actually written and returns
 * @c 1 on succes. On error, the value in @p buflen is undefined and
 * the return value will be @c 0.
 * 
 * @param context The context with the resource map.
 * @param buf     The buffer to write the result.
 * @param buflen  Must be initialized to the maximum length of @p buf and will be
 *                set to the number of bytes written on return.
 * 
 * @return @c 0 on error or @c 1 on success.
 */
int
print_wellknown(coap_context_t *context, unsigned char *buf, size_t *buflen) {
  coap_resource_t *r, *tmp;
  unsigned char *p = buf;
  size_t left, written = 0;
  HASH_ITER(hh, context->resources, r, tmp) {
    left = *buflen - written;

    if (left < *buflen) {	/* this is not the first resource  */
      *p++ = ',';
      --left;
    }

    if (!coap_print_link(r, p, &left))
      return 0;
    
    p += left;
    written += left;
  }
  *buflen = p - buf;
  return 1;
}

coap_pdu_t *
wellknown_response(coap_context_t *context, coap_pdu_t *request) {
  coap_pdu_t *resp;
  coap_opt_iterator_t opt_iter;
  coap_opt_t *token;
  size_t len;
  unsigned char buf[2];

  resp = coap_pdu_init(COAP_MESSAGE_ACK, COAP_RESPONSE_CODE(205),
		       request->hdr->id, COAP_MAX_PDU_SIZE);
  if (!resp)
    return NULL;

  /* add Content-Type */
  coap_add_option(resp, COAP_OPTION_CONTENT_TYPE,
     coap_encode_var_bytes(buf, COAP_MEDIATYPE_APPLICATION_LINK_FORMAT), buf);
  
  token = coap_check_option(request, COAP_OPTION_TOKEN, &opt_iter);
  if (token)
    coap_add_option(resp, COAP_OPTION_TOKEN, 
		    COAP_OPT_LENGTH(token), COAP_OPT_VALUE(token));
  
  /* set payload of response */
  len = resp->max_size - resp->length;
  
  if (!print_wellknown(context, resp->data, &len)) {
    debug("print_wellknown failed\n");
    coap_delete_pdu(resp);
    return NULL;
  } 
  
  resp->length += len;
  return resp;
}

#define WANT_WKC(Pdu,Key)					\
  (((Pdu)->hdr->code == COAP_REQUEST_GET) && is_wkc(Key))

void
handle_request(coap_context_t *context, coap_queue_t *node) {      
  coap_method_handler_t h = NULL;
  coap_pdu_t *response = NULL;
  coap_opt_filter_t opt_filter;
  coap_resource_t *resource;
  coap_key_t key;

  coap_option_filter_clear(opt_filter);
  coap_option_setb(opt_filter, COAP_OPTION_TOKEN); /* we always need the token */
  
  /* try to find the resource from the request URI */
  coap_hash_request_uri(node->pdu, key);
  resource = coap_get_resource_from_key(context, key);

  if (!resource) {
    /* The resource was not found. Check if the request URI happens to
     * be the well-known URI. In that case, we generate a default
     * response, otherwise, we return 4.04 */
    
    if (WANT_WKC(node->pdu, key)) { /* GET request for .well-known/core */
      debug("create default response for %s\n", COAP_DEFAULT_URI_WELLKNOWN);
      response = wellknown_response(context, node->pdu);
    } else { /* return 4.04 */
      debug("resource 0x%02x%02x%02x%02x not found, return 4.04\n", 
	    key[0], key[1], key[2], key[3]);
      response = 
	coap_new_error_response(node, COAP_RESPONSE_CODE(404), opt_filter);
    }

    if (!response || (coap_send(context, &node->remote, response)
		      == COAP_INVALID_TID)) {
      debug("cannot send response for message %d\n", node->pdu->hdr->id);
      coap_delete_pdu(response);
    }

    return;
  }

  
  /* the resource was found, check if there is a registered handler */
  
  /* check if there is a */
  if (node->pdu->hdr->code < sizeof(resource->handler))
    h = resource->handler[node->pdu->hdr->code - 1];
  
  if (h) {
    debug("call custom handler for resource 0x%02x%02x%02x%02x\n", 
	  key[0], key[1], key[2], key[3]);
    h(context, resource, &node->remote, node->pdu);
  } else {
    if (WANT_WKC(node->pdu, key)) {
      debug("create default response for %s\n", COAP_DEFAULT_URI_WELLKNOWN);
      response = wellknown_response(context, node->pdu);
    } else
      response = coap_new_error_response(node, COAP_RESPONSE_CODE(405), 
					 opt_filter);

    if (!response || (coap_send(context, &node->remote, response)
		      == COAP_INVALID_TID)) {
      debug("cannot send response for message %d\n", node->pdu->hdr->id);
      coap_delete_pdu(response);
    }
  }  
}

static inline int
handle_locally(coap_context_t *context, coap_queue_t *node) {
  /* this function can be used to check if node->pdu is really for us */
  return 1;
}

void
coap_dispatch( coap_context_t *context ) {
  coap_queue_t *node;
  coap_pdu_t *response;
  coap_opt_filter_t opt_filter;

  if (!context)
    return;

  memset(opt_filter, 0, sizeof(coap_opt_filter_t));

  while ( context->recvqueue ) {
    node = context->recvqueue;

    /* remove node from recvqueue */
    context->recvqueue = context->recvqueue->next;
    node->next = NULL;

    if ( node->pdu->hdr->version != COAP_DEFAULT_VERSION ) {
      debug("dropped packet with unknown version %u\n", node->pdu->hdr->version);
      goto cleanup;
    }

    switch ( node->pdu->hdr->type ) {
    case COAP_MESSAGE_ACK :
      /* find transaction in sendqueue to stop retransmission */
      coap_remove_transaction( &context->sendqueue, node->pdu->hdr->id );
      goto cleanup;

    case COAP_MESSAGE_RST :
      /* We have sent something the receiver disliked, so we remove
       * not only the transaction but also the subscriptions we might
       * have. */

      fprintf(stderr, "* got RST for transaction %u\n", ntohs(node->pdu->hdr->id) );

      /* Must call error handler before we remove the transaction from
       * the sendqueue as this would destroy the node. As long as we
       * are single-threaded, this is still deterministic. */
      if (context->error_handler) 
	context->error_handler(context, 
			       coap_find_transaction(context->sendqueue, 
						     node->pdu->hdr->id),
			       node, NULL);

      /* find transaction in sendqueue to stop retransmission */
      coap_remove_transaction( &context->sendqueue, node->pdu->hdr->id );
      goto cleanup;

    case COAP_MESSAGE_NON :	/* check for unknown critical options */
      if (coap_option_check_critical(context, node->pdu, opt_filter) == 0)
	goto cleanup;
      break;

    case COAP_MESSAGE_CON :	/* check for unknown critical options */
      if (coap_option_check_critical(context, node->pdu, opt_filter) == 0) {

	response = 
	  coap_new_error_response(node, COAP_RESPONSE_CODE(402), opt_filter);

	if (!response)
	  debug("coap_dispatch: cannot create error reponse");
	else {
	  if (coap_send(context, &node->remote, response) 
	      == COAP_INVALID_TID) {
	    debug("coap_dispatch: error sending reponse");
	    coap_delete_pdu(response);
	  }
	}	 
	
	goto cleanup;
      }
      break;
    }
   
    /* Pass message to upper layer if a specific handler was
     * registered for a request that should be handled locally. */
    if (COAP_MESSAGE_IS_REQUEST(node->pdu->hdr) && 
	handle_locally(context, node)) {
      handle_request(context, node);
    }
    
  cleanup:
    coap_delete_node( node );
  }
}

int
coap_can_exit( coap_context_t *context ) {
  return !context || (context->recvqueue == NULL && context->sendqueue == NULL);
}

