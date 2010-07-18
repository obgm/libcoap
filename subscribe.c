/* subscribe.c -- subscription handling for CoAP 
 *                see draft-hartke-coap-observe-01
 *
 * (c) 2010 Olaf Bergmann <bergmann@tzi.org>
 */

#include <stdio.h>
#include <limits.h>
#include <arpa/inet.h>

#include "mem.h"
#include "encode.h"
#include "debug.h"
#include "subscribe.h"

#define HMASK (ULONG_MAX >> 1)

void
notify(coap_context_t *context, coap_resource_t *res, 
       coap_subscription_t *sub, unsigned int duration, int code) {
  coap_pdu_t *pdu;
  int ls;
  unsigned char d;
#ifndef NDEBUG
  char addr[INET6_ADDRSTRLEN];
#endif

  if ( !context || !res || !sub || !(pdu = coap_new_pdu()) )
    return;

  pdu->hdr->type = COAP_MESSAGE_CON;
  pdu->hdr->code = code;

  /* FIXME: content-type and data (how about block?) */
  if (res->uri->scheme)
    coap_add_option ( pdu, COAP_OPTION_URI_SCHEME, 
		      strlen(res->uri->scheme), 
		      (unsigned char *)res->uri->scheme );

  if (res->uri->na)
    coap_add_option ( pdu, COAP_OPTION_URI_AUTHORITY, 
		      strlen(res->uri->na), 
		      (unsigned char *)res->uri->na );

  if (res->uri->path)
    coap_add_option ( pdu, COAP_OPTION_URI_PATH, 
		      strlen(res->uri->path), 
		      (unsigned char *)res->uri->path );
  
  d = COAP_PSEUDOFP_ENCODE_8_4_DOWN(duration, ls);
	      
  coap_add_option ( pdu, COAP_OPTION_SUBSCRIPTION, 1, &d );
	    
#ifndef NDEBUG
  if ( inet_ntop(AF_INET6, &(sub->subscriber.sin6_addr), addr, INET6_ADDRSTRLEN) ) {
    debug("*** notify for %s to [%s]:%d\n", res->uri->path, addr, ntohs(sub->subscriber.sin6_port));
  }
#endif
  if ( pdu && coap_send_confirmed(context, 
		  &sub->subscriber, pdu ) == COAP_INVALID_TID ) {
    debug("coap_check_resource_list: error sending notification\n");
    coap_delete_pdu(pdu);
  }  
}

void 
coap_check_resource_list(coap_context_t *context) {
  coap_list_t *res, *sub;
  coap_key_t key;
  time_t now;

  if ( !context || !context->resources /* || !context->subscribers */) 
    return;

  time(&now);
  for (res = context->resources; res; res = res->next) {
    COAP_RESOURCE(res)->dirty = (rand() & 0x03) == 3; /* just for testing */
    if ( COAP_RESOURCE(res)->dirty && COAP_RESOURCE(res)->uri ) {
      key = coap_uri_hash( COAP_RESOURCE(res)->uri ) ;

      /* is subscribed? */
      for (sub = context->subscriptions; sub; sub = sub->next) {
	if ( COAP_SUBSCRIPTION(sub)->resource == key ) {
	  /* notify subscriber */
	  notify(context, COAP_RESOURCE(res), COAP_SUBSCRIPTION(sub), 
		 COAP_SUBSCRIPTION(sub)->expires - now, COAP_RESPONSE_200);
	}

      }

      COAP_RESOURCE(res)->dirty = 0;
    }
  }
}

coap_resource_t *
coap_get_resource_from_key(coap_context_t *ctx, coap_key_t key) {
  coap_list_t *node;

  if (ctx) {
    /* TODO: use hash table for resources with key to access */
    for (node = ctx->resources; node; node = node->next) {
      if ( key == coap_uri_hash(COAP_RESOURCE(node)->uri) )
	return COAP_RESOURCE(node);
    }
  }
  
  return NULL;
}

coap_resource_t *
coap_get_resource(coap_context_t *ctx, coap_uri_t *uri) {
  return uri ? coap_get_resource_from_key(ctx, coap_uri_hash(uri)) : NULL;
}

void 
coap_check_subscriptions(coap_context_t *context) {
  time_t now;
  coap_list_t *node;
#ifndef NDEBUG
  char addr[INET6_ADDRSTRLEN];
#endif
  
  if ( !context )
    return;

  time(&now);

  node = context->subscriptions;
  while ( node && COAP_SUBSCRIPTION(node)->expires < now ) {
#ifndef NDEBUG
    if ( inet_ntop(AF_INET6, &(COAP_SUBSCRIPTION(node)->subscriber.sin6_addr), addr, INET6_ADDRSTRLEN) ) {
      
      debug("** removed expired subscription from [%s]:%d\n", addr, ntohs(COAP_SUBSCRIPTION(node)->subscriber.sin6_port));
    }
#endif
    notify(context, 
	   coap_get_resource_from_key(context, COAP_SUBSCRIPTION(node)->resource), 
	   COAP_SUBSCRIPTION(node), 
	   0, COAP_RESPONSE_400);

    context->subscriptions = node->next;
    coap_delete(node);
    node = context->subscriptions;
  }
}

void
coap_free_resource(void *res) {
  if ( res )
    coap_free( ((coap_resource_t *)res)->uri );
}
						  
coap_key_t 
_hash(coap_key_t init, const char *s) {
  int c;
  
  if ( s )
    while ( (c = *s++) ) {
      init = ((init << 7) + init) + c;
    }

  return init & HMASK;
}

coap_key_t 
_hash2(coap_key_t init, const char *s, unsigned int len) {
  if ( !s )
    return COAP_INVALID_HASHKEY;

  while ( len-- ) {
    init = ((init << 7) + init) + *s++;
  }
  
  return init & HMASK;
}
    
coap_key_t 
coap_uri_hash(const coap_uri_t *uri) {
  return _hash(_hash(_hash( 0, uri->scheme ), uri->na ), uri->path);
}

coap_key_t 
coap_add_resource(coap_context_t *context, coap_resource_t *resource) {
  coap_list_t *node;

  if ( !context || !resource )
    return COAP_INVALID_HASHKEY;

  node = coap_new_listnode(resource, coap_free_resource);
  if ( !node )
    return COAP_INVALID_HASHKEY;

  if ( !context->resources ) {
    context->resources = node;
  } else {
    node->next = context->resources;
    context->resources = node;
  }

  return coap_uri_hash( resource->uri );
}
 

/**
 * Deletes the resource that is identified by key. Returns 1 if the resource was
 * removed, 0 on error (e.g. if no such resource exists). 
 */
int
coap_delete_resource(coap_context_t *context, coap_key_t key) {
  /* FIXME */
  return 0;
}
coap_subscription_t *
coap_new_subscription(coap_context_t *context, const coap_uri_t *resource,
		      const struct sockaddr_in6 *subscriber, time_t expiry) {
  coap_subscription_t *result;

  if ( !context || !resource || !subscriber
       || !(result = coap_malloc(sizeof(coap_subscription_t))))
    return NULL;

  result->resource = coap_uri_hash(resource);
  result->expires = expiry;
  memcpy( &result->subscriber, subscriber, sizeof(struct sockaddr_in6) );

  return result;

}

coap_list_t *
coap_list_push_first(coap_list_t **list, void *data, void (*delete)(void *) ) {
  coap_list_t *node;
  node = coap_new_listnode(data, delete);
  if ( !node || !list )
    return NULL;

  if ( !*list ) {
    *list = node;
  } else {
    node->next = *list;
    *list = node;
  }

  return node;
} 

int
_order_subscription(void *a, void *b) {
  if ( !a || !b ) 
    return a < b ? -1 : 1;
  
  return ((coap_subscription_t *)a)->expires < ((coap_subscription_t *)b)->expires ? -1 : 1;
}

coap_key_t 
coap_subscription_hash(coap_subscription_t *subscription) {
  if ( !subscription )
    return COAP_INVALID_HASHKEY;

  return _hash2( subscription->resource, (char *)&subscription->subscriber, 
		 sizeof(subscription->subscriber) );
}

coap_key_t 
coap_add_subscription(coap_context_t *context,
		      coap_subscription_t *subscription) {
  coap_list_t *node;
  if ( !context || !subscription )
    return COAP_INVALID_HASHKEY;
  
  if ( !(node = coap_new_listnode(subscription, NULL)) ) 
    return COAP_INVALID_HASHKEY;

  if ( !coap_insert(&context->subscriptions, node, _order_subscription ) ) {
    coap_free( node );	/* do not call coap_delete(), so subscription object will survive */
    return COAP_INVALID_HASHKEY;
  }

  return coap_subscription_hash(subscription); 
}
