/* coap -- simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in draft-ietf-core-coap-00
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

coap_pdu_t *
coap_new_get( const char *uri ) {
  coap_pdu_t *pdu;

  if ( ! ( pdu = coap_new_pdu() ) )
    return NULL;

  pdu->hdr->type = COAP_MESSAGE_CON;
  pdu->hdr->code = COAP_REQUEST_GET;

  if ( uri && *uri ) {
    if ( *uri != '/' )
      coap_add_option ( pdu, COAP_OPTION_URI_FULL, strlen( uri ), (unsigned char *)uri );
    else {
      ++uri;
      if ( *uri )
	coap_add_option ( pdu, COAP_OPTION_URI_PATH, strlen( uri ), (unsigned char *)uri );
    }
  }

  return pdu;
}

void 
send_request( coap_context_t  *ctx, coap_pdu_t  *pdu, const char *server, unsigned short port ) {
  struct addrinfo *res, *ainfo;
  struct addrinfo hints;
  int error;
  struct sockaddr_in6 dst;

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

      coap_send_confirmed( ctx, &dst, pdu );
      goto leave;
    }
  }
 
 leave:
  freeaddrinfo(res);
}

void 
message_handler( coap_context_t  *ctx, coap_queue_t *node, void *data) {
#ifndef NDEBUG
  printf("** process pdu: ");
  coap_show_pdu( node->pdu );
#endif
}

void
split_uri( char *str, char **server, unsigned short *port, char **path ) {
  char *p;
  *port = COAP_DEFAULT_PORT;
  
  if ( strncmp( str, "coap://", 7 ) == 0 ) {
    *server = str + 7;
    
    *path = *server;
    /* note that we do not support URIs like coap://server?query or coap://server#fragment */
    while ( **path && **path != '/' ) 
      ++*path;

    if ( **path ) {
      **path = '\0';
      ++*path;
    }

    /* split server address and port */
    if ( **server == '[' ) {	/* IPv6 address reference */
      p = ++*server;
      while ( *p && *p != ']' ) 
	++p;
      *p++ = '\0';
    } else {			/* IPv4 address or hostname */
      p = *server;
      while ( *p && *p != ':' ) 
	++p;
    }
    
    if ( *p++ == ':' ) {	/* handle port */
      *port = 0;
      while ( isdigit(*p) ) {
	*port *= 10;
	*port += *p - '0';
	++p;
      }
    }

  } else {
    *path = str;
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
  static char *server = NULL, *path = NULL;
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

  coap_register_message_handler( ctx, message_handler );

  if ( optind < argc )
    split_uri( argv[optind], &server, &port, &path );
  else {
    usage( argv[0], VERSION );
    exit( 1 );
  }

  if ( group )
    join( ctx, group );

  if (! (pdu = coap_new_get( path ) ) )
    return -1;

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
