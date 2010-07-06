/* tiny -- tiny sender
 *
 * (c) 2010 Olaf Bergmann <bergmann@tzi.org>
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "../coap.h"

coap_pdu_t *
make_pdu( unsigned int value ) {
  coap_pdu_t *pdu;
  unsigned char enc;

  if ( ! ( pdu = coap_new_pdu() ) )
    return NULL;

  pdu->hdr->type = COAP_MESSAGE_NON;
  pdu->hdr->code = COAP_REQUEST_POST;
  
  enc = COAP_PSEUDOFP_ENCODE(value);
  coap_add_data( pdu, 1, &enc);

  return pdu;
}

void 
usage( const char *program ) {
  const char *p;

  p = strrchr( program, '/' );
  if ( p )
    program = ++p;

  fprintf( stderr, "%s -- tiny fake sensor\n"
	   "(c) 2010 Olaf Bergmann <bergmann@tzi.org>\n\n"
	   "usage: %s [group address]\n"
	   "\n\nSends some fake sensor values to specified multicast group\n",
	   program, program );
}

int 
main(int argc, char **argv) {
  coap_context_t  *ctx;
  struct timeval tv;
  coap_pdu_t  *pdu;
  struct sockaddr_in6 dst;
  int hops = 1, loop = 1;
  struct ipv6_mreq mreq;

  if ( argc > 1 && strncmp(argv[1], "-h", 2) == 0 ) {
    usage( argv[0] );
    exit( 1 );
  }

  ctx = coap_new_context();
  if ( !ctx )
    return -1;

  memset(&dst, 0, sizeof(struct sockaddr_in6 ));
  dst.sin6_family = AF_INET6;
  inet_pton( AF_INET6, argc > 1 ? argv[1] : "::1", &dst.sin6_addr );
  dst.sin6_port = htons( COAP_DEFAULT_PORT );

  if ( IN6_IS_ADDR_MULTICAST(&dst.sin6_addr) ) {
    /* set socket options for multicast */ 
    
    if ( setsockopt( ctx->sockfd, SOL_SOCKET, IPV6_MULTICAST_HOPS,
		     &hops, sizeof(hops) ) < 0 )
      perror("setsockopt: IPV6_MULTICAST_HOPS");

    if ( setsockopt( ctx->sockfd, SOL_SOCKET, IPV6_MULTICAST_LOOP,
		     &loop, sizeof(loop) ) < 0 )
      perror("setsockopt: IPV6_MULTICAST_LOOP");

    memcpy( &mreq.ipv6mr_multiaddr, &dst.sin6_addr, sizeof ( dst.sin6_addr ) );
    mreq.ipv6mr_interface = 0;

    if ( setsockopt( ctx->sockfd, SOL_SOCKET, IPV6_ADD_MEMBERSHIP,
		     &mreq, sizeof(mreq) ) < 0 )
      perror("setsockopt: IPV6_ADD_MEMBERSHIP");
  }

  while ( 1 ) {
    
    if (! (pdu = make_pdu( rand() & 0xfff ) ) )
      return -1;

    coap_send( ctx, &dst, pdu );

    tv.tv_sec = 5; tv.tv_usec = 0;

    select( 0, 0, 0, 0, &tv );
    
  }

  coap_free_context( ctx );

  return 0;
}
