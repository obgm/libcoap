/* coap-client -- simple CoAP client
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

#include "coap.h"

extern unsigned int
print_readable( const unsigned char *data, unsigned int len, 
		unsigned char *result, unsigned int buflen );

coap_pdu_t *
new_ack( coap_context_t  *ctx, coap_queue_t *node ) {
  coap_pdu_t *pdu = coap_new_pdu();
  
  if (pdu) {
    pdu->hdr->type = COAP_MESSAGE_ACK;
    pdu->hdr->code = 0;
    pdu->hdr->id = node->pdu->hdr->id;
  }

  return pdu;
}

coap_pdu_t *
new_response( coap_context_t  *ctx, coap_queue_t *node, unsigned int code ) {
  coap_pdu_t *pdu = new_ack(ctx, node);

  if (pdu)
    pdu->hdr->code = code;

  return pdu;
}

coap_pdu_t *
coap_new_get( const coap_uri_t *uri ) {
  coap_pdu_t *pdu;

  if ( ! ( pdu = coap_new_pdu() ) )
    return NULL;

  pdu->hdr->type = COAP_MESSAGE_CON;
  pdu->hdr->code = COAP_REQUEST_GET;

  if (!uri)
    return pdu;

  if (uri->scheme)
    coap_add_option ( pdu, COAP_OPTION_URI_SCHEME, strlen(uri->scheme), (unsigned char *)uri->scheme );

  if (uri->na)
    coap_add_option ( pdu, COAP_OPTION_URI_AUTHORITY, strlen(uri->na), (unsigned char *)uri->na );

  if (uri->path)
    coap_add_option ( pdu, COAP_OPTION_URI_PATH, strlen(uri->path), (unsigned char *)uri->path );

  return pdu;
}

void 
send_request( coap_context_t  *ctx, coap_pdu_t  *pdu, const char *server, unsigned short port ) {
  struct addrinfo *res, *ainfo;
  struct addrinfo hints;
  int error;
  struct sockaddr_in6 dst;
  static unsigned char buf[COAP_MAX_PDU_SIZE];
  memset ((char *)&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_family = AF_INET6;

  error = getaddrinfo(server, "", &hints, &res);

  if (error != 0) {
    perror("getaddrinfo");
    exit(1);
  }

  for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {

    if ( ainfo->ai_family == AF_INET6 ) {

      memset(&dst, 0, sizeof dst );
      dst.sin6_family = AF_INET6;
      dst.sin6_port = htons( port );
      memcpy( &dst.sin6_addr, &((struct sockaddr_in6 *)ainfo->ai_addr)->sin6_addr, sizeof(dst.sin6_addr) );

      print_readable( (unsigned char *)pdu->hdr, pdu->length, buf, COAP_MAX_PDU_SIZE);
      printf("%s\n",buf);
      coap_send_confirmed( ctx, &dst, pdu );
      goto leave;
    }
  }
 
 leave:
  freeaddrinfo(res);
}

void 
message_handler( coap_context_t  *ctx, coap_queue_t *node, void *data) {
  coap_pdu_t *pdu = NULL;
  coap_opt_t *block;

#ifndef NDEBUG
  printf("** process pdu: ");
  coap_show_pdu( node->pdu );
#endif

  if ( node->pdu->hdr->version != COAP_DEFAULT_VERSION ) {
    debug("dropped packet with unknown version %u\n", node->pdu->hdr->version);
    return;
  }
    
  if ( node->pdu->hdr->code < COAP_RESPONSE_100 && node->pdu->hdr->type == COAP_MESSAGE_CON ) {
    /* send 500 response */
    pdu = new_response( ctx, node, COAP_RESPONSE_500 );
    goto finish;
  }

  switch (node->pdu->hdr->code) {
  case COAP_RESPONSE_200:
    /* got some data, check if block option is set */
    block = coap_check_option( node->pdu, COAP_OPTION_BLOCK );
    if ( block && (*COAP_OPT_VALUE(*block) & 0x08) ) { 
      /* more bit is set */
      printf("found the M bit, block size is %u, block nr. %u\n",
	     *COAP_OPT_VALUE(*block) & 0x07, 
	     (*COAP_OPT_VALUE(*block) & 0xf0) << *COAP_OPT_VALUE(*block) & 0x07);
      
      /* FIXME: create pdu with request for next block 
       * need original uri for this (destination address is node->remote) 
       * copy transaction id or better not?
       */      

    }
    
    /* need to acknowledge if message was asyncronous */
    if ( node->pdu->hdr->type == COAP_MESSAGE_CON ) {
      pdu = new_ack( ctx, node );      
    }
    break;
  default:
    /* acknowledge if requested */
    if ( node->pdu->hdr->type == COAP_MESSAGE_CON ) {
      pdu = new_ack( ctx, node );
    }
  }

  finish:
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

int 
main(int argc, char **argv) {
  coap_context_t  *ctx;
  fd_set readfds;
  struct timeval tv, *timeout;
  int result;
  time_t now;
  coap_queue_t *nextpdu;
  coap_pdu_t  *pdu;
  static char *server = NULL, *p;
  unsigned short localport = COAP_DEFAULT_PORT, port = COAP_DEFAULT_PORT;
  int opt;
  char *group = NULL;
  coap_uri_t uri;

  while ((opt = getopt(argc, argv, "g:p:")) != -1) {
    switch (opt) {
    case 'g' :
      group = optarg;
      break;
    case 'p' :
      localport = atoi(optarg);
      break;
    default:
      usage( argv[0], VERSION );
      exit( 1 );
    }
  }

  ctx = coap_new_context( localport );
  if ( !ctx )
    return -1;

  coap_register_message_handler( ctx, message_handler );

  if ( optind < argc )
    coap_split_uri( argv[optind], &uri );
  else {
    usage( argv[0], VERSION );
    exit( 1 );
  }

  if ( group )
    join( ctx, group );

  if (! (pdu = coap_new_get( &uri ) ) )
    return -1;

  /* split server address and port */
  server = uri.na;

  if (server) {
    if (*server == '[') {	/* IPv6 address reference */
      p = ++server;
      
      while ( *p && *p != ']' ) 
	++p;

      if (*p == ']')
	*p++ = '\0';		/* port starts here */
    } else {			/* IPv4 address or hostname */
      p = server;
      while ( *p && *p != ':' ) 
	++p;
    }
  
    if (*p == ':') {		/* port starts here */
      *p++ = '\0';
      port = 0;
      
      /* set port */
      while( isdigit(*p) ) {
	port = port * 10 + ( *p - '0' );
	++p;
      }
    }
  }

  /* send request */
  send_request( ctx, pdu, server ? server : "::1", port );

  while ( 1 ) {
    FD_ZERO(&readfds); 
    FD_SET( ctx->sockfd, &readfds );
    
    nextpdu = coap_peek_next( ctx );

    time(&now);
    while ( nextpdu && nextpdu->t <= now ) {
      coap_retransmit( ctx, coap_pop_next( ctx ) );
      nextpdu = coap_peek_next( ctx );
    }

    if ( nextpdu ) {	        /* set timeout if there is a pdu to send */
      tv.tv_usec = 0;
      tv.tv_sec = nextpdu->t - now;
      timeout = &tv;
    } else 
      timeout = NULL;		/* no timeout otherwise */

    result = select( ctx->sockfd + 1, &readfds, 0, 0, timeout );
    
    if ( result < 0 ) {		/* error */
      perror("select");
    } else if ( result > 0 ) {	/* read from socket */
      if ( FD_ISSET( ctx->sockfd, &readfds ) ) {
	coap_read( ctx );	/* read received data */
	coap_dispatch( ctx );	/* and dispatch PDUs from receivequeue */
      }
    }
  }

  coap_free_context( ctx );

  return 0;
}
