/* coap -- simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in draft-ietf-core-coap
 *
 * Copyright (C) 2010,2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
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

/* changeable clock base (see handle_put_time()) */
static time_t my_clock_base = 0;

/* SIGINT handler: set quit to 1 for graceful termination */
void
handle_sigint(int signum) {
  quit = 1;
}

#define INDEX "This is a test server made with libcoap (see http://libcoap.sf.net)\n" \
   	      "Copyright (C) 2010 Olaf Bergmann <bergmann@tzi.org>\n\n"

void 
hnd_get_index(coap_context_t  *ctx, struct coap_resource_t *resource, 
	      coap_address_t *peer, coap_pdu_t *request) {
  coap_opt_iterator_t opt_iter;
  coap_opt_t *token;
  coap_pdu_t *response;
  size_t size = sizeof(coap_hdr_t) + strlen(INDEX) + 6;
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
	  coap_encode_var_bytes(buf, COAP_MEDIATYPE_TEXT_PLAIN), buf);

  coap_add_option(response, COAP_OPTION_MAXAGE,
	  coap_encode_var_bytes(buf, 0x2ffff), buf);
    
  if (token)
    coap_add_option(response, COAP_OPTION_TOKEN,
		    COAP_OPT_LENGTH(token), COAP_OPT_VALUE(token));

  coap_add_data(response, strlen(INDEX), (unsigned char *)INDEX);

  if (coap_send(ctx, peer, response) == COAP_INVALID_TID) {
    debug("hnd_get_index: cannot send response for message %d\n", 
	  request->hdr->id);
    coap_delete_pdu(response);
  }
}

void 
hnd_get_time(coap_context_t  *ctx, struct coap_resource_t *resource, 
		  coap_address_t *peer, coap_pdu_t *request) {
  coap_opt_iterator_t opt_iter;
  coap_opt_t *token;
  coap_pdu_t *response;
  size_t size = sizeof(coap_hdr_t) + 32;
  int type;
  unsigned char buf[2];
  time_t now;
  coap_tick_t t;
  unsigned char code;

  /* FIXME: return time, e.g. in human-readable by default and ticks
   * when query ?ticks is given. */

  /* if my_clock_base was deleted, we pretend to have no such resource */
  code = my_clock_base ? COAP_RESPONSE_CODE(205) : COAP_RESPONSE_CODE(404);

  if (request->hdr->type == COAP_MESSAGE_CON)
    type = COAP_MESSAGE_ACK;
  else 
    type = COAP_MESSAGE_NON;

  token = coap_check_option(request, COAP_OPTION_TOKEN, &opt_iter);
  if (token)
    size += COAP_OPT_SIZE(token);

  response = coap_pdu_init(type, code, request->hdr->id, size);

  if (!response) {
    debug("cannot create response for message %d\n", request->hdr->id);
    return;
  }

  if (my_clock_base)
    coap_add_option(response, COAP_OPTION_CONTENT_TYPE,
		    coap_encode_var_bytes(buf, COAP_MEDIATYPE_TEXT_PLAIN), buf);

  coap_add_option(response, COAP_OPTION_MAXAGE,
	  coap_encode_var_bytes(buf, 0x01), buf);
    
  if (token)
    coap_add_option(response, COAP_OPTION_TOKEN,
		    COAP_OPT_LENGTH(token), COAP_OPT_VALUE(token));

  if (my_clock_base) {

    /* calculate current time */
    coap_ticks(&t);
    now = my_clock_base + (t / COAP_TICKS_PER_SECOND);
    
    if (coap_check_option(request, COAP_OPTION_URI_QUERY, &opt_iter)
	&& memcmp(COAP_OPT_VALUE(opt_iter.option), "ticks",
		  min(5, COAP_OPT_LENGTH(opt_iter.option))) == 0) {
      /* output ticks */
      response->length += snprintf((char *)response->data, 
				   response->max_size - response->length,
				   "%u", (unsigned int)now);

    } else {			/* output human-readable time */
      struct tm *tmp;
      tmp = gmtime(&now);
      response->length += strftime((char *)response->data, 
				   response->max_size - response->length,
				   "%b %d %H:%M:%S", tmp);
    }
  }

  if (coap_send(ctx, peer, response) == COAP_INVALID_TID) {
    debug("hnd_get_time: cannot send response for message %d\n", 
	  request->hdr->id);
    coap_delete_pdu(response);
  }
}

void 
hnd_put_time(coap_context_t  *ctx, struct coap_resource_t *resource, 
		  coap_address_t *peer, coap_pdu_t *request) {

  coap_opt_iterator_t opt_iter;
  coap_opt_t *token;
  coap_pdu_t *response;
  size_t size = sizeof(coap_hdr_t);
  int type;
  coap_tick_t t;
  unsigned char code;
  unsigned char *data;

  /* FIXME: re-set my_clock_base to clock_offset if my_clock_base == 0
   * and request is empty. When not empty, set to value in request payload
   * (insist on query ?ticks). Return Created or Ok.
   */

  /* if my_clock_base was deleted, we pretend to have no such resource */
  code = my_clock_base ? COAP_RESPONSE_CODE(204) : COAP_RESPONSE_CODE(201);

  if (request->hdr->type == COAP_MESSAGE_CON)
    type = COAP_MESSAGE_ACK;
  else 
    type = COAP_MESSAGE_NON;

  token = coap_check_option(request, COAP_OPTION_TOKEN, &opt_iter);
  if (token)
    size += COAP_OPT_SIZE(token);

  response = coap_pdu_init(type, code, request->hdr->id, size);

  if (!response) {
    debug("cannot create response for message %d\n", request->hdr->id);
    return;
  }

  coap_get_data(request, &size, &data);
  
  if (size == 0)		/* re-init */
    my_clock_base = clock_offset;
  else {
    my_clock_base = 0;
    coap_ticks(&t);
    while(size--) 
      my_clock_base = my_clock_base * 10 + *data++;
    my_clock_base -= t / COAP_TICKS_PER_SECOND;
  }

  if (token)
    coap_add_option(response, COAP_OPTION_TOKEN,
		    COAP_OPT_LENGTH(token), COAP_OPT_VALUE(token));

  if (coap_send(ctx, peer, response) == COAP_INVALID_TID) {
    debug("hnd_get_time: cannot send response for message %d\n", 
	  request->hdr->id);
    coap_delete_pdu(response);
  }
}

void 
hnd_delete_time(coap_context_t  *ctx, struct coap_resource_t *resource, 
		  coap_address_t *peer, coap_pdu_t *request) {
  coap_opt_t *token;
  coap_pdu_t *response;
  coap_opt_iterator_t opt_iter;
  size_t size = sizeof(coap_hdr_t);
  unsigned char type;

  my_clock_base = 0;		/* mark clock as "deleted" */
  
  type = request->hdr->type == COAP_MESSAGE_CON 
    ? COAP_MESSAGE_ACK : COAP_MESSAGE_NON;

  token = coap_check_option(request, COAP_OPTION_TOKEN, &opt_iter);
  if (token)
    size += COAP_OPT_SIZE(token);
  
  response = coap_pdu_init(type, COAP_RESPONSE_CODE(202), 
			   request->hdr->id, size);

  if (!response) {
    debug("cannot create response for message %d\n", request->hdr->id);
    return;
  }

  if (token)
    coap_add_option(response, COAP_OPTION_TOKEN,
		    COAP_OPT_LENGTH(token), COAP_OPT_VALUE(token));
  
  if (coap_send(ctx, peer, response) == COAP_INVALID_TID) {
    debug("hnd_delete_time: cannot send response for message %d\n", 
	  request->hdr->id);
    coap_delete_pdu(response);
  }
}

void
init_resources(coap_context_t *ctx) {
  coap_resource_t *r;

  r = coap_resource_init((unsigned char *)"", 0, 0);
  coap_register_handler(r, COAP_REQUEST_GET, hnd_get_index);

  coap_add_attr(r, (unsigned char *)"ct", 2, (unsigned char *)"0", 1, 0);
  coap_add_attr(r, (unsigned char *)"title", 5, (unsigned char *)"\"General Info\"", 14, 0);
  coap_add_resource(ctx, r);

  /* store clock base to use in /time */
  my_clock_base = clock_offset;

  r = coap_resource_init((unsigned char *)"time", 4, 0);
  coap_register_handler(r, COAP_REQUEST_GET, hnd_get_time);
  coap_register_handler(r, COAP_REQUEST_PUT, hnd_put_time);
  coap_register_handler(r, COAP_REQUEST_DELETE, hnd_delete_time);

  coap_add_attr(r, (unsigned char *)"ct", 2, (unsigned char *)"0", 1, 0);
  coap_add_attr(r, (unsigned char *)"title", 5, (unsigned char *)"\"Internal Clock\"", 16, 0);
  coap_add_attr(r, (unsigned char *)"rt", 2, (unsigned char *)"\"Ticks\"", 7, 0);
  /* coap_add_attr(r, (unsigned char *)"obs", 3, NULL, 0, 0); */
  coap_add_attr(r, (unsigned char *)"if", 2, (unsigned char *)"\"clock\"", 7, 0);

  coap_add_resource(ctx, r);
}

void
usage( const char *program, const char *version) {
  const char *p;

  p = strrchr( program, '/' );
  if ( p )
    program = ++p;

  fprintf( stderr, "%s v%s -- a small CoAP implementation\n"
	   "(c) 2010,2011 Olaf Bergmann <bergmann@tzi.org>\n\n"
	   "usage: %s [-A address] [-p port]\n\n"
	   "\t-A address\tinterface address to bind to\n"
	   "\t-p port\t\tlisten on specified port\n",
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
  hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV | AI_ALL;
  
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
main(int argc, char **argv) {
  coap_context_t  *ctx;
  fd_set readfds;
  struct timeval tv, *timeout;
  int result;
  coap_tick_t now;
  coap_queue_t *nextpdu;
  char addr_str[NI_MAXHOST] = "::";
  char port_str[NI_MAXSERV] = "5683";
  int opt;

  while ((opt = getopt(argc, argv, "A:p:")) != -1) {
    switch (opt) {
    case 'A' :
      strncpy(addr_str, optarg, NI_MAXHOST-1);
      addr_str[NI_MAXHOST - 1] = '\0';
      break;
    case 'p' :
      strncpy(port_str, optarg, NI_MAXSERV-1);
      port_str[NI_MAXSERV - 1] = '\0';
      break;
    default:
      usage( argv[0], PACKAGE_VERSION );
      exit( 1 );
    }
  }

  ctx = get_context(addr_str, port_str);
  if (!ctx)
    return -1;

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
