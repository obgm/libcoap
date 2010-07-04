/* coap -- simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in draft-ietf-core-coap-00
 *
 * (c) 2010 Olaf Bergmann <bergmann@tzi.org>
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
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

  if ( !uri || ! ( pdu = coap_new_pdu() ) )
    return NULL;

  pdu->hdr->type = COAP_MESSAGE_CON;
  pdu->hdr->code = COAP_REQUEST_GET;

  if ( *uri ) {
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
send_request( coap_context_t  *ctx, coap_pdu_t  *pdu ) {
  struct addrinfo *res, *ainfo;
  struct addrinfo hints;
  int error;
  struct sockaddr_in6 dst;

  memset ((char *)&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_family = AF_INET6;

  /*  error = getaddrinfo("ns.tzi.org", "", &hints, &res);*/
  error = getaddrinfo("::1", "", &hints, &res);

  if (error != 0) {
    perror("getaddrinfo");
    exit(1);
  }


  for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {

    if ( ainfo->ai_family == AF_INET6 ) {

      memset(&dst, 0, sizeof dst );
      dst.sin6_family = AF_INET6;
      dst.sin6_port = htons( COAP_DEFAULT_PORT );
      memcpy( &dst.sin6_addr, &((struct sockaddr_in6 *)ainfo->ai_addr)->sin6_addr, ainfo->ai_addrlen );

      coap_send_confirmed( ctx, &dst, pdu );
      return;
    }
  }
}

void 
message_handler( coap_context_t  *ctx, coap_queue_t *node, void *data) {
#ifndef NDEBUG
  printf("** process pdu: ");
  coap_show_pdu( node->pdu );
#endif
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

  ctx = coap_new_context();
  if ( !ctx )
    return -1;

  coap_register_message_handler( ctx, message_handler );

  if (! (pdu = coap_new_get( COAP_DEFAULT_URI_WELLKNOWN ) ) )
    return -1;

  send_request( ctx, pdu );

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
