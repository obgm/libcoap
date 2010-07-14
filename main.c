/* coap -- simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in draft-ietf-core-coap-01
 *
 * (c) 2010 Olaf Bergmann <bergmann@tzi.org>
 */

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "subscribe.h"
#include "coap.h"

#define COAP_RESOURCE_CHECK_TIME 2

#define GENERATE_PDU(var,t,c,i) {		\
    var = coap_new_pdu();			\
    if (var) {					\
      var->hdr->type = (t);			\
      var->hdr->code = (c);			\
      var->hdr->id = (i);			\
    }						\
  }

coap_pdu_t *
new_ack( coap_context_t  *ctx, coap_queue_t *node ) {
  coap_pdu_t *pdu;
  GENERATE_PDU(pdu,COAP_MESSAGE_ACK,0,node->pdu->hdr->id);
  return pdu;
}

coap_pdu_t *
new_rst( coap_context_t  *ctx, coap_queue_t *node ) {
  coap_pdu_t *pdu;
  GENERATE_PDU(pdu,COAP_MESSAGE_RST,0,node->pdu->hdr->id);
  return pdu;
}

coap_pdu_t *
new_response( coap_context_t  *ctx, coap_queue_t *node, unsigned int code ) {
  coap_pdu_t *pdu;
  GENERATE_PDU(pdu,COAP_MESSAGE_ACK,code,node->pdu->hdr->id);
  return pdu;
}

void
add_contents( coap_pdu_t *pdu, unsigned int mediatype, unsigned int len, unsigned char *data ) {
  unsigned char ct = COAP_MEDIATYPE_APPLICATION_LINK_FORMAT;
  if (!pdu)
    return;
  
  /* add content-encoding */
  coap_add_option(pdu, COAP_OPTION_CONTENT_TYPE, 1, &ct);

  /* TODO: handle fragmentation (check result code) */
  coap_add_data(pdu, len, data);
}

static unsigned char resources[] = 
  "</first-resource>;sh=/f;n=Example Resource 1,"
  "</second-resource>;sh=/s;ct=41,42;n=second example";

/* Fills result with URI components that are present in pdu. Returns 0 on error,
 * 1 otherwise. */
int
get_request_uri(coap_pdu_t *pdu, coap_uri_t *result) {
  coap_opt_t *opt;

  if ( !pdu || !result )
    return 0;

  opt = coap_check_option(pdu, COAP_OPTION_URI_SCHEME);
  result->scheme = opt ? (char*)COAP_OPT_VALUE(*opt) : NULL;

  opt = coap_check_option(pdu, COAP_OPTION_URI_AUTHORITY);
  result->na = opt ? (char*)COAP_OPT_VALUE(*opt) : NULL;

  opt = coap_check_option(pdu, COAP_OPTION_URI_PATH);
  result->path = opt ? (char*)COAP_OPT_VALUE(*opt) : NULL;

  return 1;
}

coap_resource_t *
coap_get_resource(coap_context_t *ctx, coap_uri_t *uri) {
  coap_list_t *node;
  coap_key_t key;

  if ( !ctx || !uri ) 
    return NULL;

  key = coap_uri_hash(uri);
  /* TODO: use hash table for resources with key to access */
  for (node = ctx->resources; node; node = node->next) {
    if ( key == coap_uri_hash(COAP_RESOURCE(node)->uri) )
      return COAP_RESOURCE(node);
  }

  return NULL;
}

#define INDEX "Hi there!"

coap_opt_t *
coap_next_option(coap_pdu_t *pdu, coap_opt_t *opt) {
  coap_opt_t *next;
  if ( !pdu || !opt )
    return NULL;

  next = (coap_opt_t *)( (unsigned char *)opt + COAP_OPT_SIZE(*opt) );
  return (unsigned char *)next < pdu->data && COAP_OPT_DELTA(*next) == 0 ? next : NULL;
}

int
mediatype_matches(coap_pdu_t *pdu, unsigned char mediatype) {
  coap_opt_t *ct;

  for (ct = coap_check_option(pdu, COAP_OPTION_CONTENT_TYPE); ct; ct = coap_next_option(pdu, ct)) {
    if ( *COAP_OPT_VALUE(*ct) == mediatype )
      return 1;
  }
  
  return 0;
}

coap_pdu_t *
handle_get(coap_context_t  *ctx, coap_queue_t *node, void *data) {
  coap_pdu_t *pdu;
  coap_uri_t uri;
  coap_resource_t *resource;
  coap_opt_t *block;
  int len, blklen;
  unsigned int blk;
  static unsigned char buf[COAP_MAX_PDU_SIZE];
  

  if ( !get_request_uri( node->pdu, &uri ) )
    return NULL;

  if ( !uri.path ) {
    pdu = new_response(ctx, node, COAP_RESPONSE_200);
    if ( !pdu )
      return NULL;
    
    add_contents( pdu, COAP_MEDIATYPE_TEXT_PLAIN, sizeof(INDEX) - 1, (unsigned char *)INDEX );
    goto ok;
  }
   
  if ( strlen(uri.path) == sizeof(COAP_DEFAULT_URI_WELLKNOWN) - 1
       && memcmp(uri.path, COAP_DEFAULT_URI_WELLKNOWN, sizeof(COAP_DEFAULT_URI_WELLKNOWN - 1) == 0 )) {
    /* handle .well-known/r */
  
    /* FIXME: generate resource list from ctx->resources (use key as short URI) */
    pdu = new_response(ctx, node, COAP_RESPONSE_200);
    if ( !pdu )
      return NULL;

    add_contents( pdu, COAP_MEDIATYPE_APPLICATION_LINK_FORMAT, 
		  (unsigned int)strlen((char *)resources), resources );
    goto ok;
  }

  /* any other resource */
  resource = coap_get_resource(ctx, &uri);
  if ( !resource )
    return new_response(ctx, node, COAP_RESPONSE_404);

  /* check if requested mediatypes match */
  if ( coap_check_option(node->pdu, COAP_OPTION_CONTENT_TYPE) 
       && !mediatype_matches(node->pdu, resource->mediatype) )
    return new_response(ctx, node, COAP_RESPONSE_415);

  block = coap_check_option(node->pdu, COAP_OPTION_BLOCK);
  if ( block ) {
    blk = coap_decode_var_bytes( COAP_OPT_VALUE(*block), COAP_OPT_LENGTH(*block) );
    blklen = 16 << (blk & 0x07);
    blk >>= 4;
  } else {
    blklen = COAP_MAX_PDU_SIZE;
    blk = 0;
  }

  if ( !resource->data )
    return new_response(ctx, node, COAP_RESPONSE_200);

  len = resource->data(&uri, resource->mediatype, blk, buf, blklen);
  if ( len > 0 ) {
    pdu = new_response(ctx, node, COAP_RESPONSE_200);
    if ( !pdu )
      return NULL;

    add_contents(pdu, resource->mediatype, len, buf);
    /* FIXME: add block option; where to get the M-bit from? */
    goto ok;
  } 

  /* if we reach this point, something went wrong */
  return new_response(ctx, node, COAP_RESPONSE_500);

 ok:
  /* pdu is set, handle subscription if requested */
#if 0
  coap_add_subscription(ctx, coap_new_subscription(ctx, r->uri, &sub1, time(&now)+20));
#endif
  return pdu;
}

void 
message_handler(coap_context_t  *ctx, coap_queue_t *node, void *data) {
  coap_pdu_t *pdu = NULL;

#ifndef NDEBUG
  debug("** process pdu: ");
  coap_show_pdu( node->pdu );
#endif

  if ( node->pdu->hdr->version != COAP_DEFAULT_VERSION ) {
    debug("dropped packet with unknown version %u\n", node->pdu->hdr->version);
    return;
  }
    
  switch (node->pdu->hdr->code) {
  case COAP_REQUEST_GET :
    pdu = handle_get(ctx, node, data);

    if ( !pdu && node->pdu->hdr->type == COAP_MESSAGE_CON )
      pdu = new_rst( ctx, node );
    break;
  case COAP_REQUEST_POST:
  case COAP_REQUEST_PUT:
  case COAP_REQUEST_DELETE:
    debug("request method not implemented: %u\n", node->pdu->hdr->code);

    /* TODO: send 165 response */
    pdu = new_response( ctx, node, COAP_RESPONSE_405 );
    break;
  default:
      if ( node->pdu->hdr->code >= COAP_RESPONSE_100 && node->pdu->hdr->type == COAP_MESSAGE_CON ) {
	pdu = new_ack( ctx, node );
      }
  }

  if ( pdu && coap_send( ctx, &node->remote, pdu ) == COAP_INVALID_TID ) {
    debug("message_handler: error sending reponse");
    coap_delete_pdu(pdu);
  }

}

void 
usage( const char *program, const char *version) {
  const char *p;

  p = strrchr( program, '/' );
  if ( p )
    program = ++p;

  fprintf( stderr, "%s v%s -- a small CoAP implementation\n"
	   "(c) 2010 Olaf Bergmann <bergmann@tzi.org>\n\n"
	   "usage: %s [-g group] [-p port] URI\n\n"
	   "\tURI can be an absolute or relative coap URI,\n"
	   "\t-g group\tjoin the given multicast group\n"
	   "\t-p port\t\tlisten on specified port\n",
	   program, version, program );
}

int
join( coap_context_t *ctx, char *group_name ){
  struct ipv6_mreq mreq;
  struct addrinfo   *reslocal = NULL, *resmulti = NULL, hints, *ainfo;
  int result = -1;

  /* we have to resolve the link-local interface to get the interface id */
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_DGRAM;

  result = getaddrinfo("::", NULL, &hints, &reslocal);
  if ( result < 0 ) {
    perror("join: cannot resolve link-local interface");
    goto finish;
  }

  /* get the first suitable interface identifier */
  for (ainfo = reslocal; ainfo != NULL; ainfo = ainfo->ai_next) {
    if ( ainfo->ai_family == AF_INET6 ) {
      mreq.ipv6mr_interface = 
	      ((struct sockaddr_in6 *)ainfo->ai_addr)->sin6_scope_id;
      break;
    }
  }

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_DGRAM;

  /* resolve the multicast group address */
  result = getaddrinfo(group_name, NULL, &hints, &resmulti);

  if ( result < 0 ) {
    perror("join: cannot resolve multicast address");
    goto finish;
  }

  for (ainfo = resmulti; ainfo != NULL; ainfo = ainfo->ai_next) {
    if ( ainfo->ai_family == AF_INET6 ) {
      mreq.ipv6mr_multiaddr = 
	((struct sockaddr_in6 *)ainfo->ai_addr)->sin6_addr;
      break;
    }
  }
  
  result = setsockopt( ctx->sockfd, IPPROTO_IPV6, IPV6_JOIN_GROUP,
		       (char *)&mreq, sizeof(mreq) );
  if ( result < 0 ) 
    perror("join: setsockopt");

 finish:
  freeaddrinfo(resmulti);
  freeaddrinfo(reslocal);
  
  return result;
}


unsigned int 
create_plain_data(coap_uri_t *uri, unsigned short mediatype, unsigned int offset16, unsigned char *buf, unsigned int buflen) {
  memcpy(buf, "some data\n", 10);
  return 10;
}

void 
init_resources(coap_context_t *ctx) {
  coap_resource_t *r;
  struct sockaddr_in6 sub1, sub2;
  time_t now;

  if ( !(r = coap_malloc( sizeof(coap_resource_t) ))) 
    return;

  r->uri = coap_new_uri( "/first" );
  r->mediatype = COAP_MEDIATYPE_TEXT_PLAIN;
  r->dirty = 1;
  r->data = create_plain_data;
  coap_add_resource( ctx, r );

  /* build two subscriptions */
  sub1.sin6_family = AF_INET6;
  sub1.sin6_port = htons(12345);;

  inet_pton(AF_INET6, "ff02:1234:dead:7890::1", &sub1.sin6_addr);

  sub2.sin6_family = AF_INET6;
  sub2.sin6_port = htons(54321);;

  inet_pton(AF_INET6, "ABCD:2001:DEAF::beed", &sub2.sin6_addr);

  coap_add_subscription(ctx, coap_new_subscription(ctx, r->uri, &sub1, time(&now)+20));
  coap_add_subscription(ctx, coap_new_subscription(ctx, r->uri, &sub2, time(&now)+12));

  if ( !(r = coap_malloc( sizeof(coap_resource_t) ))) 
    return;

  r->uri = coap_new_uri( "/second" );
  r->mediatype = COAP_MEDIATYPE_TEXT_PLAIN;
  r->dirty = 0;
  coap_add_resource( ctx, r );

  if ( !(r = coap_malloc( sizeof(coap_resource_t) ))) 
    return;

  r->uri = coap_new_uri( "/third" );
  r->mediatype = COAP_MEDIATYPE_TEXT_PLAIN;
  r->dirty = 1;
  coap_add_resource( ctx, r );

  if ( !(r = coap_malloc( sizeof(coap_resource_t) ))) 
    return;

  r->uri = coap_new_uri( "/fourth" );
  r->mediatype = COAP_MEDIATYPE_TEXT_PLAIN;
  r->dirty = 0;
  coap_add_resource( ctx, r );

}

int 
main(int argc, char **argv) {
  coap_context_t  *ctx;
  fd_set readfds;
  struct timeval tv, *timeout;
  int result;
  time_t now;
  coap_queue_t *nextpdu;
  unsigned short port = COAP_DEFAULT_PORT;
  int opt;
  char *group = NULL;

  while ((opt = getopt(argc, argv, "g:p:")) != -1) {
    switch (opt) {
    case 'g' :
      group = optarg;
      break;
    case 'p' :
      port = atoi(optarg);
      break;
    default:
      usage( argv[0], VERSION );
      exit( 1 );
    }
  }

  ctx = coap_new_context( port );
  if ( !ctx )
    return -1;

  if ( group )
    join( ctx, group );

  coap_register_message_handler( ctx, message_handler );
  init_resources(ctx);
  while ( 1 ) {
    FD_ZERO(&readfds); 
    FD_SET( ctx->sockfd, &readfds );
    
    nextpdu = coap_peek_next( ctx );

    time(&now);
    while ( nextpdu && nextpdu->t <= now ) {
      coap_retransmit( ctx, coap_pop_next( ctx ) );
      nextpdu = coap_peek_next( ctx );
    }

    if ( nextpdu && nextpdu->t <= now + COAP_RESOURCE_CHECK_TIME ) {
      /* set timeout if there is a pdu to send before our automatic timeout occurs */
      tv.tv_usec = 0;
      tv.tv_sec = nextpdu->t - now;
      timeout = &tv;
    } else {
      tv.tv_usec = 0;
      tv.tv_sec = COAP_RESOURCE_CHECK_TIME;
      timeout = &tv;
    }
    result = select( FD_SETSIZE, &readfds, 0, 0, timeout );
    
    if ( result < 0 ) {		/* error */
      perror("select");
    } else if ( result > 0 ) {	/* read from socket */
      if ( FD_ISSET( ctx->sockfd, &readfds ) ) {
	coap_read( ctx );	/* read received data */
	coap_dispatch( ctx );	/* and dispatch PDUs from receivequeue */
      } 
    } else {			/* timeout */
      coap_check_resource_list( ctx );
      coap_check_subscriptions( ctx );
    }
  }

  coap_free_context( ctx );

  return 0;
}
