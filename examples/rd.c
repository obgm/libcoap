/* coap -- simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in draft-ietf-core-coap
 *
 * Copyright (C) 2010,2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */


/**
 * @file rd.c
 * @brief CoRE resource directory
 *
 * @see http://tools.ietf.org/id/draft-shelby-core-resource-directory
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
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>

#include "config.h"
#include "resource.h"
#include "coap.h"

#define COAP_RESOURCE_CHECK_TIME 2

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

/* temporary storage for dynamic resource representations */
static int quit = 0;

/* SIGINT handler: set quit to 1 for graceful termination */
void
handle_sigint(int signum) {
  quit = 1;
}

void 
hnd_get_rd(coap_context_t  *ctx, struct coap_resource_t *resource, 
	      coap_address_t *peer, coap_pdu_t *request, coap_tid_t id) {
  coap_opt_iterator_t opt_iter;
  coap_opt_t *token;
  coap_pdu_t *response;
  size_t size = sizeof(coap_hdr_t) + strlen("FIXME") + 6;
  int type;
  unsigned char buf[3];

  if (request->hdr->type == COAP_MESSAGE_CON)
    type = COAP_MESSAGE_ACK;
  else 
    type = COAP_MESSAGE_NON;

  token = coap_check_option(request, COAP_OPTION_TOKEN, &opt_iter);
  if (token)
    size += COAP_OPT_SIZE(token);

  response = coap_pdu_init(type, COAP_RESPONSE_CODE(205), 
			   request->hdr->id, size);

  if (!response) {
    debug("cannot create response for message %d\n", request->hdr->id);
    return;
  }

  coap_add_option(response, COAP_OPTION_CONTENT_TYPE,
	  coap_encode_var_bytes(buf, COAP_MEDIATYPE_APPLICATION_LINK_FORMAT), buf);

  coap_add_option(response, COAP_OPTION_MAXAGE,
	  coap_encode_var_bytes(buf, 0x2ffff), buf);
    
  if (token)
    coap_add_option(response, COAP_OPTION_TOKEN,
		    COAP_OPT_LENGTH(token), COAP_OPT_VALUE(token));

  coap_add_data(response, strlen("FIXME"), (unsigned char *)"FIXME");

  if (coap_send(ctx, peer, response) == COAP_INVALID_TID) {
    debug("hnd_get_rd: cannot send response for message %d\n", 
	  request->hdr->id);
    coap_delete_pdu(response);
  }
}

void 
hnd_post_rd(coap_context_t  *ctx, struct coap_resource_t *resource, 
	      coap_address_t *peer, coap_pdu_t *request, coap_tid_t id) {
}

void 
hnd_delete_rd(coap_context_t  *ctx, struct coap_resource_t *resource, 
	      coap_address_t *peer, coap_pdu_t *request, coap_tid_t id) {
}

void
init_resources(coap_context_t *ctx) {
  coap_resource_t *r;

  r = coap_resource_init((unsigned char *)"rd", 2, 0);
  coap_register_handler(r, COAP_REQUEST_GET, hnd_get_rd);
  coap_register_handler(r, COAP_REQUEST_PUT, hnd_post_rd);
  coap_register_handler(r, COAP_REQUEST_DELETE, hnd_delete_rd);

  coap_add_attr(r, (unsigned char *)"ct", 2, (unsigned char *)"40", 2, 0);
  coap_add_attr(r, (unsigned char *)"rt", 2, (unsigned char *)"\"core-rd\"", 9, 0);
  coap_add_attr(r, (unsigned char *)"ins", 2, (unsigned char *)"\"default\"", 9, 0);

  coap_add_resource(ctx, r);

}

void
usage( const char *program, const char *version) {
  const char *p;

  p = strrchr( program, '/' );
  if ( p )
    program = ++p;

  fprintf( stderr, "%s v%s -- CoRE Resource Directory implementation\n"
	   "(c) 2011 Olaf Bergmann <bergmann@tzi.org>\n\n"
	   "usage: %s [-A address] [-p port]\n\n"
	   "\t-A address\tinterface address to bind to\n"
	   "\t-p port\t\tlisten on specified port\n"
	   "\t-v num\t\tverbosity level (default: 3)\n",
	   program, version, program );
}

coap_context_t *
get_context(const char *node, const char *port) {
  coap_context_t *ctx = NULL;  
  int s;
  struct addrinfo hints;
  struct addrinfo *result, *rp;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
  hints.ai_socktype = SOCK_DGRAM; /* Coap uses UDP */
  hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;
  
  s = getaddrinfo(node, port, &hints, &result);
  if ( s != 0 ) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
    return NULL;
  } 

  /* iterate through results until success */
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    ctx = coap_new_context(rp->ai_addr, rp->ai_addrlen);
    if (ctx) {
      /* TODO: output address:port for successful binding */
      goto finish;
    }
  }
  
  fprintf(stderr, "no context available for interface '%s'\n", node);

 finish:
  freeaddrinfo(result);
  return ctx;
}

int
join(coap_context_t *ctx, char *group_name) {
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
  coap_tick_t now;
  coap_queue_t *nextpdu;
  char addr_str[NI_MAXHOST] = "::";
  char port_str[NI_MAXSERV] = "5683";
  char *group = NULL;
  int opt;
  coap_log_t log_level = LOG_WARN;

  while ((opt = getopt(argc, argv, "A:g:p:v:")) != -1) {
    switch (opt) {
    case 'A' :
      strncpy(addr_str, optarg, NI_MAXHOST-1);
      addr_str[NI_MAXHOST - 1] = '\0';
      break;
    case 'g' :
      group = optarg;
      break;
    case 'p' :
      strncpy(port_str, optarg, NI_MAXSERV-1);
      port_str[NI_MAXSERV - 1] = '\0';
      break;
    case 'v' :
      log_level = strtol(optarg, NULL, 10);
      break;
    default:
      usage( argv[0], PACKAGE_VERSION );
      exit( 1 );
    }
  }

  coap_set_log_level(log_level);

  ctx = get_context(addr_str, port_str);
  if (!ctx)
    return -1;

  if (group)
    join(ctx, group);

  init_resources(ctx);

  signal(SIGINT, handle_sigint);

  while ( !quit ) {
    FD_ZERO(&readfds);
    FD_SET( ctx->sockfd, &readfds );

    nextpdu = coap_peek_next( ctx );

    coap_ticks(&now);
    while ( nextpdu && nextpdu->t <= now ) {
      coap_retransmit( ctx, coap_pop_next( ctx ) );
      nextpdu = coap_peek_next( ctx );
    }

    if ( nextpdu && nextpdu->t <= now + COAP_RESOURCE_CHECK_TIME ) {
      /* set timeout if there is a pdu to send before our automatic timeout occurs */
      tv.tv_usec = ((nextpdu->t - now) % COAP_TICKS_PER_SECOND) << 10;
      tv.tv_sec = (nextpdu->t - now) / COAP_TICKS_PER_SECOND;
      timeout = &tv;
    } else {
      tv.tv_usec = 0;
      tv.tv_sec = COAP_RESOURCE_CHECK_TIME;
      timeout = &tv;
    }
    result = select( FD_SETSIZE, &readfds, 0, 0, timeout );

    if ( result < 0 ) {		/* error */
      if (errno != EINTR)
	perror("select");
    } else if ( result > 0 ) {	/* read from socket */
      if ( FD_ISSET( ctx->sockfd, &readfds ) ) {
	coap_read( ctx );	/* read received data */
	coap_dispatch( ctx );	/* and dispatch PDUs from receivequeue */
      }
    } else {			/* timeout */
      /* coap_check_resource_list( ctx ); */
    }
  }

  coap_free_context( ctx );

  return 0;
}
