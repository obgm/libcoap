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

#define RD_ROOT_STR   ((unsigned char *)"rd")
#define RD_ROOT_SIZE  2

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

typedef struct rd_t {
  UT_hash_handle hh;	/**< hash handle (for internal use only) */
  coap_key_t key;	/**< the actual key bytes for this resource */

  size_t etag_len;		/**< actual length of @c etag */
  unsigned char etag[8];	/**< ETag for current description */

  str data;			/**< points to the resource description  */
} rd_t;

rd_t *resources = NULL;

inline rd_t *
rd_new() {
  rd_t *rd;
  rd = (rd_t *)coap_malloc(sizeof(rd_t));
  if (rd)
    memset(rd, 0, sizeof(rd_t));

  return rd;
}	

inline void
rd_delete(rd_t *rd) {
  if (rd) {
    coap_free(rd->data.s);
    coap_free(rd);
  }
}

/* temporary storage for dynamic resource representations */
static int quit = 0;

/* SIGINT handler: set quit to 1 for graceful termination */
void
handle_sigint(int signum) {
  quit = 1;
}

#define DUMMY "<coap://[::1]:40000/sensors/light>;rt=\"lux\";ct=0"

void 
hnd_get_resource(coap_context_t  *ctx, struct coap_resource_t *resource, 
		 coap_address_t *peer, coap_pdu_t *request, coap_tid_t id) {
  coap_opt_iterator_t opt_iter;
  coap_opt_t *token;
  coap_pdu_t *response;
  size_t size = sizeof(coap_hdr_t) + 6 + strlen(DUMMY);
  int type = (request->hdr->type == COAP_MESSAGE_CON) 
    ? COAP_MESSAGE_ACK : COAP_MESSAGE_NON;
  rd_t *rd = NULL;
  unsigned char buf[3];
  
  token = coap_check_option(request, COAP_OPTION_TOKEN, &opt_iter);
  if (token)
    size += COAP_OPT_SIZE(token);

  HASH_FIND(hh, resources, resource->key, sizeof(coap_key_t), rd);
  if (rd && rd->data.s)
    size += rd->data.length;

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

  if (rd && rd->data.s)
    coap_add_data(response, rd->data.length, rd->data.s);

  if (coap_send(ctx, peer, response) == COAP_INVALID_TID) {
    debug("hnd_get_rd: cannot send response for message %d\n", 
	  request->hdr->id);
    coap_delete_pdu(response);
  }  
}

void 
hnd_delete_resource(coap_context_t  *ctx, struct coap_resource_t *resource, 
		    coap_address_t *peer, coap_pdu_t *request, coap_tid_t id) {
  coap_opt_iterator_t opt_iter;
  coap_opt_t *token;
  coap_pdu_t *response;
  size_t size = sizeof(coap_hdr_t) + 6;
  int type = (request->hdr->type == COAP_MESSAGE_CON) 
    ? COAP_MESSAGE_ACK : COAP_MESSAGE_NON;
  rd_t *rd = NULL;

  token = coap_check_option(request, COAP_OPTION_TOKEN, &opt_iter);
  if (token)
    size += COAP_OPT_SIZE(token);

  HASH_FIND(hh, resources, resource->key, sizeof(coap_key_t), rd);
  if (rd) {
    HASH_DELETE(hh, resources, rd);
    rd_delete(rd);
  }

  coap_delete_resource(ctx, resource->key);

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
    debug("hnd_get_rd: cannot send response for message %d\n", 
	  request->hdr->id);
    coap_delete_pdu(response);
  }  
}

void 
hnd_get_rd(coap_context_t  *ctx, struct coap_resource_t *resource, 
	      coap_address_t *peer, coap_pdu_t *request, coap_tid_t id) {
  coap_opt_iterator_t opt_iter;
  coap_opt_t *token;
  coap_pdu_t *response;
  size_t size = sizeof(coap_hdr_t) + strlen("FIXME") + 6;
  int type = (request->hdr->type == COAP_MESSAGE_CON) 
    ? COAP_MESSAGE_ACK : COAP_MESSAGE_NON;
  unsigned char buf[3];

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

int
parse_param(unsigned char *search, size_t search_len,
	    unsigned char *data, size_t data_len, str *result) {

  if (result)
    memset(result, 0, sizeof(str));

  if (!search_len) 
    return 0;
  
  while (search_len <= data_len) {

    /* handle parameter if found */
    if (memcmp(search, data, search_len) == 0) {
      data += search_len;
      data_len -= search_len;

      /* key is only valid if we are at end of string or delimiter follows */
      if (!data_len || *data == '=' || *data == '&') {
	while (data_len && *data != '=') {
	  ++data; --data_len;
	}
      
	if (data_len > 1 && result) {
	  /* value begins after '=' */
	  
	  result->s = ++data;
	  while (--data_len && *data != '&') {
	    ++data; result->length++;
	  }
	}
	
	return 1;
      }
    }

    /* otherwise proceed to next */
    while (--data_len && *data++ != '&')
      ;
  }
  
  return 0;
}

void
add_source_address(struct coap_resource_t *resource, coap_address_t *peer) {
  char buf[64];
  size_t n = 1;
  
  buf[0] = '"';

  switch(peer->addr.sa.sa_family) {

  case AF_INET:
    /* FIXME */
    break;

  case AF_INET6:
    n += snprintf(buf + n, sizeof(buf) - n,
		  "[%02x%02x:%02x%02x:%02x%02x:%02x%02x"	\
		  ":%02x%02x:%02x%02x:%02x%02x:%02x%02x]",
		  peer->addr.sin6.sin6_addr.s6_addr[0],
		  peer->addr.sin6.sin6_addr.s6_addr[1],
		  peer->addr.sin6.sin6_addr.s6_addr[2],
		  peer->addr.sin6.sin6_addr.s6_addr[3],
		  peer->addr.sin6.sin6_addr.s6_addr[4],
		  peer->addr.sin6.sin6_addr.s6_addr[5],
		  peer->addr.sin6.sin6_addr.s6_addr[6],
		  peer->addr.sin6.sin6_addr.s6_addr[7],
		  peer->addr.sin6.sin6_addr.s6_addr[8],
		  peer->addr.sin6.sin6_addr.s6_addr[9],
		  peer->addr.sin6.sin6_addr.s6_addr[10],
		  peer->addr.sin6.sin6_addr.s6_addr[11],
		  peer->addr.sin6.sin6_addr.s6_addr[12],
		  peer->addr.sin6.sin6_addr.s6_addr[13],
		  peer->addr.sin6.sin6_addr.s6_addr[14],
		  peer->addr.sin6.sin6_addr.s6_addr[15]);    
    
    if (peer->addr.sin6.sin6_port != htons(COAP_DEFAULT_PORT)) {
      n += 
	snprintf(buf + n, sizeof(buf) - n, ":%d", peer->addr.sin6.sin6_port);
    }
    break;
  default:
    ;
  }

  if (n < sizeof(buf))
    buf[n++] = '"';

  coap_add_attr(resource, (unsigned char *)"A", 1, (unsigned char *)buf, n, 1);
}


rd_t *
make_rd(coap_address_t *peer, coap_pdu_t *pdu) {    
  rd_t *rd;
  unsigned char *data;

  rd = rd_new();
  
  if (!rd) {
    debug("hnd_get_rd: cannot allocate storage for rd\n");
    return NULL;
  }

  if (coap_get_data(pdu, &rd->data.length, &data)) {
    rd->data.s = (unsigned char *)coap_malloc(rd->data.length);
    if (!rd->data.s) {
      debug("hnd_get_rd: cannot allocate storage for rd->data\n");
      rd_delete(rd);
      return NULL;
    }
    memcpy(rd->data.s, data, rd->data.length);
  }

  return rd;
}

void 
hnd_post_rd(coap_context_t  *ctx, struct coap_resource_t *resource, 
	    coap_address_t *peer, coap_pdu_t *request, coap_tid_t id) {
  coap_resource_t *r;
  coap_opt_iterator_t opt_iter;
  coap_opt_t *token, *query;
  coap_pdu_t *response;
  size_t size = sizeof(coap_hdr_t);
  int type = (request->hdr->type == COAP_MESSAGE_CON) 
    ? COAP_MESSAGE_ACK : COAP_MESSAGE_NON;
  unsigned char loc[68];
  size_t loc_size;
  str h, ins, rt, lt;		/* store query parameters */

  loc[0] = '/';
  memcpy(loc+1, RD_ROOT_STR, RD_ROOT_SIZE);

  loc_size = RD_ROOT_SIZE + 1;
  loc[loc_size++] = '/';

  token = coap_check_option(request, COAP_OPTION_TOKEN, &opt_iter);

  if (token)
    size += COAP_OPT_SIZE(token);

  /* store query parameters for later use */
  query = coap_check_option(request, COAP_OPTION_URI_QUERY, &opt_iter);
  if (query) {
    parse_param((unsigned char *)"h", 1, 
		COAP_OPT_VALUE(query), COAP_OPT_LENGTH(query), &h);
    parse_param((unsigned char *)"ins", 3, 
		COAP_OPT_VALUE(query), COAP_OPT_LENGTH(query), &ins);
    parse_param((unsigned char *)"lt", 2, 
		COAP_OPT_VALUE(query), COAP_OPT_LENGTH(query), &lt);
    parse_param((unsigned char *)"rt", 2, 
		COAP_OPT_VALUE(query), COAP_OPT_LENGTH(query), &rt);
  } 
  
  if (h.length) {		/* client has specified a node name */
    memcpy(loc + loc_size, h.s, min(h.length, sizeof(loc) - loc_size - 1));
    loc_size += min(h.length, sizeof(loc) - loc_size - 1);

    if (ins.length && loc_size > 1) {
      loc[loc_size++] = '-';
      memcpy((char *)(loc + loc_size), 
	     ins.s, min(ins.length, sizeof(loc) - loc_size - 1));
      loc_size += min(ins.length, sizeof(loc) - loc_size - 1);
    }
 
  } else {			/* generate node identifier */
    loc_size += 
      snprintf((char *)(loc + loc_size), sizeof(loc) - loc_size - 1, 
	       "%x", id);
    
    if (loc_size > 1) {
      if (ins.length) {
	loc[loc_size++] = '-';
	memcpy((char *)(loc + loc_size), 
	       ins.s, min(ins.length, sizeof(loc) - loc_size - 1));
	loc_size += min(ins.length, sizeof(loc) - loc_size - 1);
      } else {
	coap_tick_t now;
	coap_ticks(&now);
	
	loc_size += 
	  snprintf((char *)(loc + loc_size), sizeof(loc) - loc_size - 1, 
		   "-%x", now);
      }
    }
  }

  /* TODO:
   *   - store payload from POST request for retrieval with hnd_get_resource
   *   - update resource URIs in payload with real URI as seen from here
   *   - use lt to check expiration
   *   - updates and etag handling
   */
  
  r = coap_resource_init(loc + 1, loc_size - 1, 1);
  coap_register_handler(r, COAP_REQUEST_GET, hnd_get_resource);
  coap_register_handler(r, COAP_REQUEST_DELETE, hnd_delete_resource);

  if (ins.s) {
    /* neglect missing quotes for now... */
    coap_add_attr(r, (unsigned char *)"ins", 3, ins.s, ins.length, 1);
  }
  if (rt.s) {
    /* neglect missing quotes for now... */
    coap_add_attr(r, (unsigned char *)"rt", 2, rt.s, rt.length, 1);
  }

  add_source_address(r, peer);

  {
    rd_t *rd;
    rd = make_rd(peer, request);
    if (rd) {
      coap_hash_path(loc + 1, loc_size - 1, rd->key);
      HASH_ADD(hh, resources, key, sizeof(coap_key_t), rd);
    } else {
      /* FIXME: send error response and delete r */
    }
  }

  coap_add_resource(ctx, r);


  /* create response */
    
  size += loc_size + 2;   /* add size for location path option */
  response = coap_pdu_init(type, COAP_RESPONSE_CODE(201), 
			   request->hdr->id, size);

  if (!response) {
    debug("cannot create response for message %d\n", request->hdr->id);
    return;
  }

  coap_add_option(response, COAP_OPTION_LOCATION_PATH, loc_size, loc);

  if (token)
    coap_add_option(response, COAP_OPTION_TOKEN,
		    COAP_OPT_LENGTH(token), COAP_OPT_VALUE(token));

  if (coap_send(ctx, peer, response) == COAP_INVALID_TID) {
    debug("hnd_get_rd: cannot send response for message %d\n", 
	  request->hdr->id);
    coap_delete_pdu(response);
  }
}

void 
hnd_put_rd(coap_context_t  *ctx, struct coap_resource_t *resource, 
	      coap_address_t *peer, coap_pdu_t *request, coap_tid_t id) {
}

void
init_resources(coap_context_t *ctx) {
  coap_resource_t *r;

  r = coap_resource_init(RD_ROOT_STR, RD_ROOT_SIZE, 0);
  coap_register_handler(r, COAP_REQUEST_GET, hnd_get_rd);
  coap_register_handler(r, COAP_REQUEST_POST, hnd_post_rd);
  coap_register_handler(r, COAP_REQUEST_PUT, hnd_put_rd);

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
