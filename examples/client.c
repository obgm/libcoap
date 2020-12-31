/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/* coap-client -- simple CoAP client
 *
 * Copyright (C) 2010--2019 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * This file is part of the CoAP library libcoap. Please see README for terms of
 * use.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef _WIN32
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#include "getopt.c"
#if !defined(S_ISDIR)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif
static char* strndup(const char* s1, size_t n)
{
  char* copy = (char*)malloc(n + 1);
  if (copy) {
    memcpy(copy, s1, n);
    copy[n] = 0;
  }
  return copy;
};
#else
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#include <coap2/coap.h>

#define MAX_USER 128 /* Maximum length of a user name (i.e., PSK
                      * identity) in bytes. */
#define MAX_KEY   64 /* Maximum length of a key (i.e., PSK) in bytes. */

int flags = 0;

static unsigned char _token_data[8];
coap_binary_t the_token = { 0, _token_data };

#define FLAGS_BLOCK 0x01

static coap_optlist_t *optlist = NULL;
/* Request URI.
 * TODO: associate the resources with transaction id and make it expireable */
static coap_uri_t uri;
static coap_uri_t proxy = { {0, NULL}, 0, {0, NULL}, {0, NULL}, 0 };
static int proxy_scheme_option = 0;
static int uri_host_option = 0;
static unsigned int ping_seconds = 0;

/* reading is done when this flag is set */
static int ready = 0;

/* processing a block response when this flag is set */
static int doing_getting_block = 0;

static coap_string_t output_file = { 0, NULL };   /* output file name */
static FILE *file = NULL;               /* output file stream */

static coap_string_t payload = { 0, NULL };       /* optional payload to send */

static int reliable = 0;

static int add_nl = 0;

unsigned char msgtype = COAP_MESSAGE_CON; /* usually, requests are sent confirmable */

static char *cert_file = NULL; /* certificate and optional private key in PEM,
                                  or PKCS11 URI*/
static char *key_file = NULL; /* private key in PEM, DER or PKCS11 URI */
static char *pkcs11_pin = NULL; /* PKCS11 pin to unlock access to token */
static char *ca_file = NULL;   /* CA for cert_file - for cert checking in PEM,
                                  DER or PKCS11 URI */
static char *root_ca_file = NULL; /* List of trusted Root CAs in PEM */
static int is_rpk_not_cert = 0; /* Cert is RPK if set */
static uint8_t *cert_mem = NULL; /* certificate and private key in PEM_BUF */
static uint8_t *key_mem = NULL; /* private key in PEM_BUF */
static uint8_t *ca_mem = NULL;   /* CA for cert checking in PEM_BUF */
static size_t cert_mem_len = 0;
static size_t key_mem_len = 0;
static size_t ca_mem_len = 0;

typedef struct ih_def_t {
  char* hint_match;
  coap_bin_const_t *new_identity;
  coap_bin_const_t *new_key;
} ih_def_t;

typedef struct valid_ihs_t {
  size_t count;
  ih_def_t *ih_list;
} valid_ihs_t;

static valid_ihs_t valid_ihs = {0, NULL};

typedef unsigned char method_t;
method_t method = 1;                    /* the method we are using in our requests */

coap_block_t block = { .num = 0, .m = 0, .szx = 6 };
uint16_t last_block1_tid = 0;


unsigned int wait_seconds = 90;                /* default timeout in seconds */
unsigned int wait_ms = 0;
int wait_ms_reset = 0;
int obs_started = 0;
unsigned int obs_seconds = 30;          /* default observe time */
unsigned int obs_ms = 0;                /* timeout for current subscription */
int obs_ms_reset = 0;

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__ ((unused))
#else /* not a GCC */
#define UNUSED_PARAM
#endif /* GCC */

static int quit = 0;

/* SIGINT handler: set quit to 1 for graceful termination */
static void
handle_sigint(int signum UNUSED_PARAM) {
  quit = 1;
}

static int
append_to_output(const uint8_t *data, size_t len) {
  size_t written;

  if (!file) {
    if (!output_file.s || (output_file.length && output_file.s[0] == '-'))
      file = stdout;
    else {
      if (!(file = fopen((char *)output_file.s, "w"))) {
        perror("fopen");
        return -1;
      }
    }
  }

  do {
    written = fwrite(data, 1, len, file);
    len -= written;
    data += written;
  } while ( written && len );
  fflush(file);

  return 0;
}

static void
close_output(void) {
  if (file) {

    /* add a newline before closing if no option '-o' was specified */
    if (!output_file.s)
      fwrite("\n", 1, 1, file);

    fflush(file);
    fclose(file);
  }
}

static coap_pdu_t *
coap_new_request(coap_context_t *ctx,
                 coap_session_t *session,
                 method_t m,
                 coap_optlist_t **options,
                 unsigned char *data,
                 size_t length) {
  coap_pdu_t *pdu;
  (void)ctx;

  if (!(pdu = coap_new_pdu(session)))
    return NULL;

  pdu->type = msgtype;
  pdu->tid = coap_new_message_id(session);
  pdu->code = m;

  if ( !coap_add_token(pdu, the_token.length, the_token.s)) {
    coap_log(LOG_DEBUG, "cannot add token to request\n");
  }

  if (options)
    coap_add_optlist_pdu(pdu, options);

  if (length) {
    if ((flags & FLAGS_BLOCK) == 0)
      coap_add_data(pdu, length, data);
    else {
      unsigned char buf[4];
      coap_add_option(pdu,
                      COAP_OPTION_SIZE1,  /* 60 */
                      coap_encode_var_safe8(buf, sizeof(buf), length),
                      buf);

      coap_add_block(pdu, length, data, block.num, block.szx);
    }
  }

  return pdu;
}

static coap_tid_t
clear_obs(coap_context_t *ctx, coap_session_t *session) {
  coap_pdu_t *pdu;
  coap_optlist_t *option;
  coap_tid_t tid = COAP_INVALID_TID;
  unsigned char buf[2];
  (void)ctx;

  /* create bare PDU w/o any option  */
  pdu = coap_pdu_init(msgtype,
                      COAP_REQUEST_GET,
                      coap_new_message_id(session),
                      coap_session_max_pdu_size(session));

  if (!pdu) {
    return tid;
  }

  if (!coap_add_token(pdu, the_token.length, the_token.s)) {
    coap_log(LOG_CRIT, "cannot add token\n");
    goto error;
  }

  for (option = optlist; option; option = option->next ) {
    switch (option->number) {
    case COAP_OPTION_URI_HOST : /*  3 */
      if (!coap_add_option(pdu, option->number, option->length,
                           option->data)) {
        goto error;
      }
      break;
    default:
      ;
    }
  }

  /* Observe option comes after Uri-Host, but before the others */
  if (!coap_add_option(pdu,
      COAP_OPTION_OBSERVE,  /* 6 */
      coap_encode_var_safe(buf, sizeof(buf), COAP_OBSERVE_CANCEL),
      buf)) {
    coap_log(LOG_CRIT, "cannot add option Observe: %u\n", COAP_OBSERVE_CANCEL);
    goto error;
  }

  for (option = optlist; option; option = option->next ) {
    switch (option->number) {
    case COAP_OPTION_URI_PORT :  /*  7 */
    case COAP_OPTION_URI_PATH :  /* 11 */
    case COAP_OPTION_URI_QUERY : /* 15 */
    case COAP_OPTION_HOP_LIMIT : /* 16 */
      if (!coap_add_option(pdu, option->number, option->length,
                           option->data)) {
        goto error;
      }
      break;
    default:
      ;
    }
  }

  if (flags & FLAGS_BLOCK) {
    block.num = 0;
    block.m = 0;
    coap_add_option(pdu,
      COAP_OPTION_BLOCK2,  /* 23 */
      coap_encode_var_safe(buf, sizeof(buf), (block.num << 4 | block.m << 3 | block.szx)),
      buf);
  }
  for (option = optlist; option; option = option->next ) {
    switch (option->number) {
    case COAP_OPTION_PROXY_URI :    /* 35 */
    case COAP_OPTION_PROXY_SCHEME : /* 39 */
      if (!coap_add_option(pdu, option->number, option->length,
                           option->data)) {
        goto error;
      }
      break;
    default:
      ;
    }
  }

  if (coap_get_log_level() < LOG_DEBUG)
    coap_show_pdu(LOG_INFO, pdu);


  tid = coap_send(session, pdu);

  if (tid == COAP_INVALID_TID)
    coap_log(LOG_DEBUG, "clear_obs: error sending new request\n");

  return tid;
 error:

  coap_delete_pdu(pdu);
  return tid;
}

static int
resolve_address(const coap_str_const_t *server, struct sockaddr *dst) {

  struct addrinfo *res, *ainfo;
  struct addrinfo hints;
  static char addrstr[256];
  int error, len=-1;

  memset(addrstr, 0, sizeof(addrstr));
  if (server->length)
    memcpy(addrstr, server->s, server->length);
  else
    memcpy(addrstr, "localhost", 9);

  memset ((char *)&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_family = AF_UNSPEC;

  error = getaddrinfo(addrstr, NULL, &hints, &res);

  if (error != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
    return error;
  }

  for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {
    switch (ainfo->ai_family) {
    case AF_INET6:
    case AF_INET:
      len = (int)ainfo->ai_addrlen;
      memcpy(dst, ainfo->ai_addr, len);
      goto finish;
    default:
      ;
    }
  }

 finish:
  freeaddrinfo(res);
  return len;
}

#define HANDLE_BLOCK1(Pdu)                                        \
  ((method == COAP_REQUEST_PUT || method == COAP_REQUEST_POST) && \
   ((flags & FLAGS_BLOCK) == 0) &&                                \
   ((Pdu)->hdr->code == COAP_RESPONSE_CODE(201) ||                \
    (Pdu)->hdr->code == COAP_RESPONSE_CODE(204)))

static inline int
check_token(coap_pdu_t *received) {
  return received->token_length == the_token.length &&
    memcmp(received->token, the_token.s, the_token.length) == 0;
}

static int
event_handler(coap_context_t *ctx UNUSED_PARAM,
              coap_event_t event,
              struct coap_session_t *session UNUSED_PARAM) {

  switch(event) {
  case COAP_EVENT_DTLS_CLOSED:
  case COAP_EVENT_TCP_CLOSED:
  case COAP_EVENT_SESSION_CLOSED:
    quit = 1;
    break;
  default:
    break;
  }
  return 0;
}

static void
nack_handler(coap_context_t *context UNUSED_PARAM,
             coap_session_t *session UNUSED_PARAM,
             coap_pdu_t *sent UNUSED_PARAM,
             coap_nack_reason_t reason,
             const coap_tid_t id UNUSED_PARAM) {

  switch(reason) {
  case COAP_NACK_TOO_MANY_RETRIES:
  case COAP_NACK_NOT_DELIVERABLE:
  case COAP_NACK_RST:
  case COAP_NACK_TLS_FAILED:
    quit = 1;
    break;
  case COAP_NACK_ICMP_ISSUE:
  default:
    ;
  }
  return;
}

static void
message_handler(struct coap_context_t *ctx,
                coap_session_t *session,
                coap_pdu_t *sent,
                coap_pdu_t *received,
                const coap_tid_t id UNUSED_PARAM) {

  coap_pdu_t *pdu = NULL;
  coap_opt_t *block_opt;
  coap_opt_iterator_t opt_iter;
  unsigned char buf[4];
  coap_optlist_t *option;
  size_t len;
  unsigned char *databuf;
  coap_tid_t tid;

  coap_log(LOG_DEBUG, "** process incoming %d.%02d response:\n",
           COAP_RESPONSE_CLASS(received->code), received->code & 0x1F);
  if (coap_get_log_level() < LOG_DEBUG)
    coap_show_pdu(LOG_INFO, received);

  /* check if this is a response to our original request */
  if (!check_token(received)) {
    /* drop if this was just some message, or send RST in case of notification */
    if (!sent && (received->type == COAP_MESSAGE_CON ||
                  received->type == COAP_MESSAGE_NON))
      coap_send_rst(session, received);
    return;
  }

  if (received->type == COAP_MESSAGE_RST) {
    coap_log(LOG_INFO, "got RST\n");
    return;
  }

  /* output the received data, if any */
  if (COAP_RESPONSE_CLASS(received->code) == 2) {

    /* set obs timer if we have successfully subscribed a resource */
    if (!obs_started && coap_check_option(received, COAP_OPTION_OBSERVE, &opt_iter)) {
      coap_log(LOG_DEBUG,
               "observation relationship established, set timeout to %d\n",
               obs_seconds);
      obs_started = 1;
      obs_ms = obs_seconds * 1000;
      obs_ms_reset = 1;
    }

    /* Got some data, check if block option is set. Behavior is undefined if
     * both, Block1 and Block2 are present. */
    block_opt = coap_check_option(received, COAP_OPTION_BLOCK2, &opt_iter);
    if (block_opt) { /* handle Block2 */
      uint16_t blktype = opt_iter.type;

      /* TODO: check if we are looking at the correct block number */
      if (coap_get_data(received, &len, &databuf)) {
        append_to_output(databuf, len);
        if (!COAP_OPT_BLOCK_MORE(block_opt) && add_nl)
          append_to_output((const uint8_t*)"\n", 1);
      }

      if (coap_opt_block_num(block_opt) == 0) {
        /* See if observe is set in first response */
        ready = coap_check_option(received,
                                  COAP_OPTION_OBSERVE, &opt_iter) == NULL;
      }
      if(COAP_OPT_BLOCK_MORE(block_opt)) {
        /* more bit is set */
        coap_log(LOG_DEBUG, "found the M bit, block size is %u, block nr. %u\n",
              COAP_OPT_BLOCK_SZX(block_opt),
              coap_opt_block_num(block_opt));

        /* create pdu with request for next block */
        pdu = coap_new_request(ctx, session, method, NULL, NULL, 0); /* first, create bare PDU w/o any option  */
        if ( pdu ) {
          /* add URI components from optlist in ascending order */
          for (option = optlist; option; option = option->next ) {
            switch (option->number) {
              case COAP_OPTION_URI_HOST :  /*  3 */
              case COAP_OPTION_URI_PORT :  /*  7 */
              case COAP_OPTION_URI_PATH :  /* 11 */
              case COAP_OPTION_URI_QUERY : /* 15 */
              case COAP_OPTION_HOP_LIMIT : /* 16 */
                coap_add_option(pdu, option->number, option->length,
                                option->data);
                break;
              default:
                ;     /* skip other options */
            }
          }

          /* finally add updated block option from response, clear M bit */
          /* blocknr = (blocknr & 0xfffffff7) + 0x10; */
          coap_log(LOG_DEBUG, "query block %d\n",
                   (coap_opt_block_num(block_opt) + 1));
          coap_add_option(pdu,
                          blktype,     /* 23 or 27 */
                          coap_encode_var_safe(buf, sizeof(buf),
                                 ((coap_opt_block_num(block_opt) + 1) << 4) |
                                  COAP_OPT_BLOCK_SZX(block_opt)), buf);

          for (option = optlist; option; option = option->next ) {
            switch (option->number) {
              case COAP_OPTION_PROXY_URI :    /* 35 */
              case COAP_OPTION_PROXY_SCHEME : /* 39 */
                coap_add_option(pdu, option->number, option->length,
                                option->data);
                break;
              default:
                ;     /* skip other options */
            }
          }
          tid = coap_send(session, pdu);

          if (tid == COAP_INVALID_TID) {
            coap_log(LOG_DEBUG, "message_handler: error sending new request\n");
          } else {
            wait_ms = wait_seconds * 1000;
            wait_ms_reset = 1;
            doing_getting_block = 1;
          }

          return;
        }
      }
      /* Failure of some sort */
      doing_getting_block = 0;
      return;
    } else { /* no Block2 option */
      block_opt = coap_check_option(received, COAP_OPTION_BLOCK1, &opt_iter);

      if (block_opt) { /* handle Block1 */
        unsigned int szx = COAP_OPT_BLOCK_SZX(block_opt);
        unsigned int num = coap_opt_block_num(block_opt);
        coap_log(LOG_DEBUG,
                 "found Block1 option, block size is %u, block nr. %u\n",
                 szx, num);
        if (szx != block.szx) {
          unsigned int bytes_sent = ((block.num + 1) << (block.szx + 4));
          if (bytes_sent % (1 << (szx + 4)) == 0) {
            /* Recompute the block number of the previous packet given the new block size */
            num = block.num = (bytes_sent >> (szx + 4)) - 1;
            block.szx = szx;
            coap_log(LOG_DEBUG,
                     "new Block1 size is %u, block number %u completed\n",
                     (1 << (block.szx + 4)), block.num);
          } else {
            coap_log(LOG_DEBUG, "ignoring request to increase Block1 size, "
            "next block is not aligned on requested block size boundary. "
            "(%u x %u mod %u = %u != 0)\n",
                  block.num + 1, (1 << (block.szx + 4)), (1 << (szx + 4)),
                  bytes_sent % (1 << (szx + 4)));
          }
        }

        if (last_block1_tid == received->tid) {
          /*
           * Duplicate BLOCK1 ACK
           *
           * RFCs not clear here, but on a lossy connection, there could
           * be multiple BLOCK1 ACKs, causing the client to retransmit the
           * same block multiple times.
           *
           * Once a block has been ACKd, there is no need to retransmit it.
           */
          return;
        }
        last_block1_tid = received->tid;

        if (payload.length <= (block.num+1) * (1 << (block.szx + 4))) {
          coap_log(LOG_DEBUG, "upload ready\n");
          if (coap_get_data(received, &len, &databuf)) {
            append_to_output(databuf, len);
            if (add_nl)
              append_to_output((const uint8_t*)"\n", 1);
          }
          ready = 1;
          return;
        }

       /* create pdu with request for next block */
        pdu = coap_new_request(ctx, session, method, NULL, NULL, 0); /* first, create bare PDU w/o any option  */
        if (pdu) {

          /* add URI components from optlist */
          for (option = optlist; option; option = option->next ) {
            switch (option->number) {
              case COAP_OPTION_URI_HOST :       /*  3 */
              case COAP_OPTION_URI_PORT :       /*  7 */
              case COAP_OPTION_URI_PATH :       /* 11 */
              case COAP_OPTION_CONTENT_FORMAT : /* 12 */
              case COAP_OPTION_URI_QUERY :      /* 15 */
              case COAP_OPTION_HOP_LIMIT :      /* 16 */
                coap_add_option(pdu, option->number, option->length,
                                option->data);
                break;
              default:
                ;     /* skip other options */
            }
          }

          /* finally add updated block option from response, clear M bit */
          /* blocknr = (blocknr & 0xfffffff7) + 0x10; */
          block.num = num + 1;
          block.m = ((block.num+1) * (1 << (block.szx + 4)) < payload.length);

          coap_log(LOG_DEBUG, "send block %d\n", block.num);
          coap_add_option(pdu,
                          COAP_OPTION_BLOCK1,  /* 27 */
                          coap_encode_var_safe(buf, sizeof(buf),
                          (block.num << 4) | (block.m << 3) | block.szx), buf);

          for (option = optlist; option; option = option->next ) {
            switch (option->number) {
              case COAP_OPTION_PROXY_URI :    /* 35 */
              case COAP_OPTION_PROXY_SCHEME : /* 39 */
                coap_add_option(pdu, option->number, option->length,
                                option->data);
                break;
              default:
                ;     /* skip other options */
            }
          }

          coap_add_option(pdu,
                          COAP_OPTION_SIZE1,  /* 60 */
                          coap_encode_var_safe8(buf, sizeof(buf), payload.length),
                          buf);

          coap_add_block(pdu,
                         payload.length,
                         payload.s,
                         block.num,
                         block.szx);
          if (coap_get_log_level() < LOG_DEBUG)
            coap_show_pdu(LOG_INFO, pdu);

          tid = coap_send(session, pdu);

          if (tid == COAP_INVALID_TID) {
            coap_log(LOG_DEBUG, "message_handler: error sending new request\n");
          } else {
            wait_ms = wait_seconds * 1000;
            wait_ms_reset = 1;
          }

          return;
        }
      } else {
        /* There is no block option set, just read the data and we are done. */
        if (coap_get_data(received, &len, &databuf)) {
          append_to_output(databuf, len);
          if (add_nl)
            append_to_output((const uint8_t*)"\n", 1);
        }
      }
    }
  } else {      /* no 2.05 */

    /* check if an error was signaled and output payload if so */
    if (COAP_RESPONSE_CLASS(received->code) >= 4) {
      fprintf(stderr, "%d.%02d",
              (received->code >> 5), received->code & 0x1F);
      if (coap_get_data(received, &len, &databuf)) {
        fprintf(stderr, " ");
        while(len--)
        fprintf(stderr, "%c", *databuf++);
      }
      fprintf(stderr, "\n");
    }

  }

  /* any pdu that has been created in this function must be sent by now */
  assert(pdu == NULL);

  /* our job is done, we can exit at any time */
  ready = coap_check_option(received, COAP_OPTION_OBSERVE, &opt_iter) == NULL;
}

static void
usage( const char *program, const char *version) {
  const char *p;
  char buffer[64];

  p = strrchr( program, '/' );
  if ( p )
    program = ++p;

  fprintf( stderr, "%s v%s -- a small CoAP implementation\n"
     "Copyright (C) 2010-2019 Olaf Bergmann <bergmann@tzi.org> and others\n\n"
     "%s\n\n"
     "Usage: %s [-a addr] [-b [num,]size] [-e text] [-f file] [-l loss]\n"
     "\t\t[-m method] [-o file] [-p port] [-r] [-s duration] [-t type]\n"
     "\t\t[-v num] [-w] [-A type] [-B seconds] [-H hoplimit] [-K interval]\n"
     "\t\t[-N] [-O num,text] [-P scheme://address[:port]] [-T token] [-U]\n"
     "\t\t[[-h match_hint_file] [-k key] [-u user]]\n"
     "\t\t[[-c certfile] [-j keyfile] [-C cafile] [-J pkcs11_pin]\n"
     "\t\t[-M raw_pk] [-R root_cafile] [-S match_pki_sni_file]] URI\n"
     "\tURI can be an absolute URI or a URI prefixed with scheme and host\n\n"
     "General Options\n"
     "\t-a addr\t\tThe local interface address to use\n"
     "\t-b [num,]size\tBlock size to be used in GET/PUT/POST requests\n"
     "\t       \t\t(value must be a multiple of 16 not larger than 1024)\n"
     "\t       \t\tIf num is present, the request chain will start at\n"
     "\t       \t\tblock num\n"
     "\t-e text\t\tInclude text as payload (use percent-encoding for\n"
     "\t       \t\tnon-ASCII characters)\n"
     "\t-f file\t\tFile to send with PUT/POST (use '-' for STDIN)\n"
     "\t-l list\t\tFail to send some datagrams specified by a comma\n"
     "\t       \t\tseparated list of numbers or number ranges\n"
     "\t       \t\t(for debugging only)\n"
     "\t-l loss%%\tRandomly fail to send datagrams with the specified\n"
     "\t       \t\tprobability - 100%% all datagrams, 0%% no datagrams\n"
     "\t-m method\tRequest method (get|put|post|delete|fetch|patch|ipatch),\n"
     "\t       \t\tdefault is 'get'\n"
     "\t-o file\t\tOutput received data to this file (use '-' for STDOUT)\n"
     "\t-p port\t\tListen on specified port\n"
     "\t-r     \t\tUse reliable protocol (TCP or TLS); requires TCP support\n"
     "\t-s duration\tSubscribe to / Observe resource for given duration\n"
     "\t       \t\tin seconds\n"
     "\t-t type\t\tContent format for given resource for PUT/POST\n"
     "\t-v num \t\tVerbosity level (default 3, maximum is 9). Above 7,\n"
     "\t       \t\tthere is increased verbosity in GnuTLS logging\n"
     "\t-w     \t\tAppend a newline to received data\n"
     "\t-A type\t\tAccepted media type\n"
     "\t-B seconds\tBreak operation after waiting given seconds\n"
     "\t       \t\t(default is %d)\n"
     "\t-H hoplimit\tSet the Hop Limit count to hoplimit for proxies. Must\n"
     "\t       \t\thave a value between 1 and 255 inclusive.\n"
     "\t       \t\tDefault is '16'\n"
     "\t-K interval\tSend a ping after interval seconds of inactivity\n"
     "\t-N     \t\tSend NON-confirmable message\n"
     "\t-O num,text\tAdd option num with contents text to request. If the\n"
     "\t       \t\ttext begins with 0x, then the hex text is converted to\n"
     "\t       \t\tbinary data\n"
     "\t-P scheme://address[:port]\tScheme, address and optional port to\n"
     "\t       \t\tdefine how to connect to a CoAP proxy (automatically adds\n"
     "\t       \t\tProxy-Uri option to request) to forward the request to.\n"
     "\t       \t\tScheme is one of coap, coaps, coap+tcp and coaps+tcp\n"
     "\t-T token\tInclude specified token\n"
     "\t-U     \t\tNever include Uri-Host or Uri-Port options\n"
     ,program, version, coap_string_tls_version(buffer, sizeof(buffer))
     ,program, wait_seconds);
  fprintf( stderr,
     "PSK Options (if supported by underlying (D)TLS library)\n"
     "\t-h match_hint_file\n"
     "\t       \t\tThis is a file that contains one or more lines of Identity\n"
     "\t       \t\tHints to match for new user and new pre-shared key\n"
     "\t       \t\t(PSK) (comma separated) to be used. E.g., per line\n"
     "\t       \t\t hint_to_match,new_user,new_key\n"
     "\t       \t\tNote: -k and -u still need to be defined for the default\n"
     "\t       \t\tcase\n"
     "\t-k key \t\tPre-shared key for the specified user\n"
     "\t-u user\t\tUser identity for pre-shared key mode\n"
     "PKI Options (if supported by underlying (D)TLS library)\n"
     "\tNote: If any one of '-c certfile', '-j keyfile' or '-C cafile' is in\n"
     "\tPKCS11 URI naming format (pkcs11: prefix), then any remaining non\n"
     "\tPKCS11 URI file definitions have to be in DER, not PEM, format.\n"
     "\tOtherwise all of '-c certfile', '-j keyfile' or '-C cafile' are in\n"
     "\tPEM format.\n\n"
     "\t-c certfile\tPEM file or PKCS11 URI for the Certificate. The private\n"
     "\t       \t\tkey can be in the PEM file, or use the same PKCS11 URI.\n"
     "\t       \t\tIf not, the private ney is defined by '-j keyfile'\n"
     "\t-j keyfile\tPEM file or PKCS11 URI for the private key for the\n"
     "\t       \t\tnertificate in '-c certfile' if the parameter is different\n"
     "\t       \t\tfrom certfile in '-c certfile'\n"
     "\t-C cafile\tPEM file or PKCS11 URI for the CA Certificate that was\n"
     "\t       \t\tused to sign the certfile. This will trigger\n"
     "\t       \t\tthe validation of the server certificate.  If certfile is\n"
     "\t       \t\tself-signed (as defined by '-c certfile'), then you need\n"
     "\t       \t\tto have on the command line the same filename for both\n"
     "\t       \t\tthe certfile and cafile (as in '-c certfile -C certfile')\n"
     "\t       \t\tto trigger validation\n"
     "\t-J pkcs11_pin\tThe user pin to unlock access to the PKCS11 token\n"
     "\t-M rpk_file\tRaw Public Key (RPK) PEM file or PKCS11 URI that contains\n"
     "\t       \t\tboth PUBLIC KEY and PRIVATE KEY or just EC PRIVATE KEY.\n"
     "\t       \t\t(GnuTLS and TinyDTLS support only) '-C cafile' not required\n"
     "\t-R root_cafile\tPEM file containing the set of trusted root CAs that\n"
     "\t       \t\tare to be used to validate the server certificate.\n"
     "\t       \t\tThe '-C cafile' does not have to be in this list and is\n"
     "\t       \t\t'trusted' for the verification.\n"
     "\t       \t\tAlternatively, this can point to a directory containing\n"
     "\t       \t\ta set of CA PEM files\n"
     );
  fprintf( stderr,
     "Examples:\n"
     "\tcoap-client -m get coap://[::1]/\n"
     "\tcoap-client -m get coap://[::1]/.well-known/core\n"
     "\tcoap-client -m get coap+tcp://[::1]/.well-known/core\n"
     "\tcoap-client -m get coaps://[::1]/.well-known/core\n"
     "\tcoap-client -m get coaps+tcp://[::1]/.well-known/core\n"
     "\tcoap-client -m get -T cafe coap://[::1]/time\n"
     "\techo -n 1000 | coap-client -m put -T cafe coap://[::1]/time -f -\n"
     );
}

typedef struct {
  unsigned char code;
  const char *media_type;
} content_type_t;

static void
cmdline_content_type(char *arg, uint16_t key) {
  static content_type_t content_types[] = {
    {  0, "plain" },
    {  0, "text/plain" },
    { 40, "link" },
    { 40, "link-format" },
    { 40, "application/link-format" },
    { 41, "xml" },
    { 41, "application/xml" },
    { 42, "binary" },
    { 42, "octet-stream" },
    { 42, "application/octet-stream" },
    { 47, "exi" },
    { 47, "application/exi" },
    { 50, "json" },
    { 50, "application/json" },
    { 60, "cbor" },
    { 60, "application/cbor" },
    { 255, NULL }
  };
  coap_optlist_t *node;
  unsigned char i;
  uint16_t value;
  uint8_t buf[2];

  if (isdigit((int)arg[0])) {
    value = atoi(arg);
  } else {
    for (i=0;
         content_types[i].media_type &&
           strncmp(arg, content_types[i].media_type, strlen(arg)) != 0 ;
         ++i)
      ;

    if (content_types[i].media_type) {
      value = content_types[i].code;
    } else {
      coap_log(LOG_WARNING, "W: unknown content-format '%s'\n",arg);
      return;
    }
  }

  node = coap_new_optlist(key, coap_encode_var_safe(buf, sizeof(buf), value), buf);
  if (node) {
    coap_insert_optlist(&optlist, node);
  }
}

static int
cmdline_hop_limit(char *arg) {
  coap_optlist_t *node;
  uint32_t value;
  uint8_t buf[4];

  value = strtol(arg, NULL, 10);
  if (value < 1 || value > 255) {
    return 0;
  }
  node = coap_new_optlist(COAP_OPTION_HOP_LIMIT, coap_encode_var_safe(buf, sizeof(buf), value), buf);
  if (node) {
    coap_insert_optlist(&optlist, node);
  }
  return 1;
}


static uint16_t
get_default_port(const coap_uri_t *u) {
  return coap_uri_scheme_is_secure(u) ? COAPS_DEFAULT_PORT : COAP_DEFAULT_PORT;
}

/**
 * Sets global URI options according to the URI passed as @p arg.
 * This function returns 0 on success or -1 on error.
 *
 * @param arg             The URI string.
 * @param create_uri_opts Flags that indicate whether Uri-Host and
 *                        Uri-Port should be suppressed.
 * @return 0 on success, -1 otherwise
 */
static int
cmdline_uri(char *arg, int create_uri_opts) {
  unsigned char portbuf[2];
#define BUFSIZE 100
  unsigned char _buf[BUFSIZE];
  unsigned char *buf = _buf;
  size_t buflen;
  int res;

  if (!proxy_scheme_option && proxy.host.length) {
    /* create Proxy-Uri from argument */
    size_t len = strlen(arg);
    if (len > 1034) {
      coap_log(LOG_ERR, "Absolute URI length must be <= 1034 bytes for a proxy\n");
      return -1;
    }

    coap_insert_optlist(&optlist,
                coap_new_optlist(COAP_OPTION_PROXY_URI,
                len,
                (unsigned char *)arg));

  } else {      /* split arg into Uri-* options */
    if (coap_split_uri((unsigned char *)arg, strlen(arg), &uri) < 0) {
      coap_log(LOG_ERR, "invalid CoAP URI\n");
      return -1;
    }

    if (uri.scheme==COAP_URI_SCHEME_COAPS && !reliable && !coap_dtls_is_supported()) {
      coap_log(LOG_EMERG,
               "coaps URI scheme not supported in this version of libcoap\n");
      return -1;
    }

    if ((uri.scheme==COAP_URI_SCHEME_COAPS_TCP || (uri.scheme==COAP_URI_SCHEME_COAPS && reliable)) && !coap_tls_is_supported()) {
      coap_log(LOG_EMERG,
            "coaps+tcp URI scheme not supported in this version of libcoap\n");
      return -1;
    }

    if (uri.scheme==COAP_URI_SCHEME_COAP_TCP && !coap_tcp_is_supported()) {
      /* coaps+tcp caught above */
      coap_log(LOG_EMERG,
            "coap+tcp URI scheme not supported in this version of libcoap\n");
      return -1;
    }

    if (uri.port != get_default_port(&uri) && create_uri_opts) {
      coap_insert_optlist(&optlist,
                  coap_new_optlist(COAP_OPTION_URI_PORT,
                                   coap_encode_var_safe(portbuf, sizeof(portbuf),
                                                        (uri.port & 0xffff)),
                  portbuf));
    }

    if (uri.path.length) {
      buflen = BUFSIZE;
      if (uri.path.length > BUFSIZE)
        coap_log(LOG_WARNING, "URI path will be truncated (max buffer %d)\n", BUFSIZE);
      res = coap_split_path(uri.path.s, uri.path.length, buf, &buflen);

      while (res--) {
        coap_insert_optlist(&optlist,
                    coap_new_optlist(COAP_OPTION_URI_PATH,
                    coap_opt_length(buf),
                    coap_opt_value(buf)));

        buf += coap_opt_size(buf);
      }
    }

    if (uri.query.length) {
      buflen = BUFSIZE;
      buf = _buf;
      res = coap_split_query(uri.query.s, uri.query.length, buf, &buflen);

      while (res--) {
        coap_insert_optlist(&optlist,
                    coap_new_optlist(COAP_OPTION_URI_QUERY,
                    coap_opt_length(buf),
                    coap_opt_value(buf)));

        buf += coap_opt_size(buf);
      }
    }
  }

  return 0;
}

static int
cmdline_blocksize(char *arg) {
  uint16_t size;

  again:
  size = 0;
  while(*arg && *arg != ',')
    size = size * 10 + (*arg++ - '0');

  if (*arg == ',') {
    arg++;
    block.num = size;
    goto again;
  }

  if (size)
    block.szx = (coap_fls(size >> 4) - 1) & 0x07;

  flags |= FLAGS_BLOCK;
  return 1;
}

/* Called after processing the options from the commandline to set
 * Block1 or Block2 depending on method. */
static void
set_blocksize(void) {
  static unsigned char buf[4];        /* hack: temporarily take encoded bytes */
  uint16_t opt;
  unsigned int opt_length;

  if (method != COAP_REQUEST_DELETE) {
    opt = method == COAP_REQUEST_GET ? COAP_OPTION_BLOCK2 : COAP_OPTION_BLOCK1;

    block.m = (opt == COAP_OPTION_BLOCK1) &&
      ((1ull << (block.szx + 4)) < payload.length);

    opt_length = coap_encode_var_safe(buf, sizeof(buf),
          (block.num << 4 | block.m << 3 | block.szx));

    coap_insert_optlist(&optlist, coap_new_optlist(opt, opt_length, buf));
  }
}

static void
cmdline_subscribe(char *arg) {
  uint8_t buf[4];

  obs_seconds = atoi(arg);
  coap_insert_optlist(&optlist,
                      coap_new_optlist(COAP_OPTION_OBSERVE,
                        coap_encode_var_safe(buf, sizeof(buf),
                        COAP_OBSERVE_ESTABLISH), buf)
                      );
}

static int
cmdline_proxy(char *arg) {
  if (coap_split_uri((unsigned char *)arg, strlen(arg), &proxy) < 0 ||
      proxy.path.length != 0 || proxy.query.length != 0) {
    coap_log(LOG_ERR, "invalid CoAP Proxy definition\n");
    return 0;
  }
  return 1;
}

static inline void
cmdline_token(char *arg) {
  the_token.length = min(sizeof(_token_data), strlen(arg));
  if (the_token.length > 0) {
    memcpy((char *)the_token.s, arg, the_token.length);
  }
}

/**
 * Utility function to convert a hex digit to its corresponding
 * numerical value.
 *
 * param c  The hex digit to convert. Must be in [0-9A-Fa-f].
 *
 * return The numerical representation of @p c.
 */
static uint8_t
hex2char(char c) {
  assert(isxdigit(c));
  if ('a' <= c && c <= 'f')
    return c - 'a' + 10;
  else if ('A' <= c && c <= 'F')
    return c - 'A' + 10;
  else
    return c - '0';
}

/**
 * Converts the sequence of hex digits in src to a sequence of bytes.
 *
 * This function returns the number of bytes that have been written to
 * @p dst.
 *
 * param[in]  src  The null-terminated hex string to convert.
 * param[out] dst  Conversion result.
 *
 * return The length of @p dst.
 */
static size_t
convert_hex_string(const char *src, uint8_t *dst) {
  uint8_t *p = dst;
  while (isxdigit((int)src[0]) && isxdigit((int)src[1])) {
    *p++ = (hex2char(src[0]) << 4) + hex2char(src[1]);
    src += 2;
  }
  if (src[0] != '\0') { /* error in hex input */
    coap_log(LOG_WARNING, "invalid hex string in option '%s'\n", src);
  }
  return p - dst;
}

static void
cmdline_option(char *arg) {
  unsigned int num = 0;

  while (*arg && *arg != ',') {
    num = num * 10 + (*arg - '0');
    ++arg;
  }
  if (*arg == ',')
    ++arg;

   /* read hex string when arg starts with "0x" */
  if (arg[0] == '0' && arg[1] == 'x') {
    /* As the command line option is part of our environment we can do
     * the conversion in place. */
    size_t len = convert_hex_string(arg + 2, (uint8_t *)arg);

    /* On success, 2 * len + 2 == strlen(arg) */
    coap_insert_optlist(&optlist,
                        coap_new_optlist(num, len, (unsigned char *)arg));
  } else { /* null-terminated character string */
    coap_insert_optlist(&optlist,
                        coap_new_optlist(num, strlen(arg), (unsigned char *)arg));
  }
  if (num == COAP_OPTION_PROXY_SCHEME) {
    proxy_scheme_option = 1;
    if (strcasecmp(arg, "coaps+tcp") == 0) {
      proxy.scheme = COAP_URI_SCHEME_COAPS_TCP;
      proxy.port = COAPS_DEFAULT_PORT;
    }
    else if (strcasecmp(arg, "coap+tcp") == 0) {
      proxy.scheme = COAP_URI_SCHEME_COAP_TCP;
      proxy.port = COAP_DEFAULT_PORT;
    }
    else if (strcasecmp(arg, "coaps") == 0) {
      proxy.scheme = COAP_URI_SCHEME_COAPS;
      proxy.port = COAPS_DEFAULT_PORT;
    }
    else if (strcasecmp(arg, "coap") == 0) {
      proxy.scheme = COAP_URI_SCHEME_COAP;
      proxy.port = COAP_DEFAULT_PORT;
    }
    else {
      coap_log(LOG_WARNING, "%s is not a supported CoAP Proxy-Scheme\n", arg);
    }
  }
  if (num == COAP_OPTION_URI_HOST) {
    uri_host_option = 1;
  }
}

/**
 * Calculates decimal value from hexadecimal ASCII character given in
 * @p c. The caller must ensure that @p c actually represents a valid
 * heaxdecimal character, e.g. with isxdigit(3).
 *
 * @hideinitializer
 */
#define hexchar_to_dec(c) ((c) & 0x40 ? ((c) & 0x0F) + 9 : ((c) & 0x0F))

/**
 * Decodes percent-encoded characters while copying the string @p seg
 * of size @p length to @p buf. The caller of this function must
 * ensure that the percent-encodings are correct (i.e. the character
 * '%' is always followed by two hex digits. and that @p buf provides
 * sufficient space to hold the result. This function is supposed to
 * be called by make_decoded_option() only.
 *
 * @param seg     The segment to decode and copy.
 * @param length  Length of @p seg.
 * @param buf     The result buffer.
 */
static void
decode_segment(const uint8_t *seg, size_t length, unsigned char *buf) {

  while (length--) {

    if (*seg == '%') {
      *buf = (hexchar_to_dec(seg[1]) << 4) + hexchar_to_dec(seg[2]);

      seg += 2; length -= 2;
    } else {
      *buf = *seg;
    }

    ++buf; ++seg;
  }
}

/**
 * Runs through the given path (or query) segment and checks if
 * percent-encodings are correct. This function returns @c -1 on error
 * or the length of @p s when decoded.
 */
static int
check_segment(const uint8_t *s, size_t length) {

  int n = 0;

  while (length) {
    if (*s == '%') {
      if (length < 2 || !(isxdigit(s[1]) && isxdigit(s[2])))
        return -1;

      s += 2;
      length -= 2;
    }

    ++s; ++n; --length;
  }

  return n;
}

static int
cmdline_input(char *text, coap_string_t *buf) {
  int len;
  len = check_segment((unsigned char *)text, strlen(text));

  if (len < 0)
    return 0;

  buf->s = (unsigned char *)coap_malloc(len);
  if (!buf->s)
    return 0;

  buf->length = len;
  decode_segment((unsigned char *)text, strlen(text), buf->s);
  return 1;
}

static int
cmdline_input_from_file(char *filename, coap_string_t *buf) {
  FILE *inputfile = NULL;
  ssize_t len;
  int result = 1;
  struct stat statbuf;

  if (!filename || !buf)
    return 0;

  if (filename[0] == '-' && !filename[1]) { /* read from stdin */
    buf->length = 20000;
    buf->s = (unsigned char *)coap_malloc(buf->length);
    if (!buf->s)
      return 0;

    inputfile = stdin;
  } else {
    /* read from specified input file */
    inputfile = fopen(filename, "r");
    if ( !inputfile ) {
      perror("cmdline_input_from_file: fopen");
      return 0;
    }

    if (fstat(fileno(inputfile), &statbuf) < 0) {
      perror("cmdline_input_from_file: stat");
      fclose(inputfile);
      return 0;
    }

    buf->length = statbuf.st_size;
    buf->s = (unsigned char *)coap_malloc(buf->length);
    if (!buf->s) {
      fclose(inputfile);
      return 0;
    }
  }

  len = fread(buf->s, 1, buf->length, inputfile);

  if (len < 0 || ((size_t)len < buf->length)) {
    if (ferror(inputfile) != 0) {
      perror("cmdline_input_from_file: fread");
      coap_free(buf->s);
      buf->length = 0;
      buf->s = NULL;
      result = 0;
    } else {
      buf->length = len;
    }
  }

  if (inputfile != stdin)
    fclose(inputfile);

  return result;
}

static method_t
cmdline_method(char *arg) {
  static const char *methods[] =
    { 0, "get", "post", "put", "delete", "fetch", "patch", "ipatch", 0};
  unsigned char i;

  for (i=1; methods[i] && strcasecmp(arg,methods[i]) != 0 ; ++i)
    ;

  return i;     /* note that we do not prevent illegal methods */
}

static ssize_t
cmdline_read_user(char *arg, unsigned char **buf, size_t maxlen) {
  size_t len = strnlen(arg, maxlen);
  if (len) {
    *buf = (unsigned char *)arg;
    /* len is the size or less, so 0 terminate to maxlen */
    (*buf)[len] = '\000';
  }
  /* 0 length Identity is valid */
  return len;
}

static ssize_t
cmdline_read_key(char *arg, unsigned char **buf, size_t maxlen) {
  size_t len = strnlen(arg, maxlen);
  if (len) {
    *buf = (unsigned char *)arg;
    return len;
  }
  /* Need at least one byte for the pre-shared key */
  coap_log( LOG_CRIT, "Invalid Pre-Shared Key specified\n" );
  return -1;
}

static int cmdline_read_hint_check(const char *arg) {
  FILE *fp = fopen(arg, "r");
  static char tmpbuf[256];
  if (fp == NULL) {
    coap_log(LOG_ERR, "Hint file: %s: Unable to open\n", arg);
    return 0;
  }
  while (fgets(tmpbuf, sizeof(tmpbuf), fp) != NULL) {
    char *cp = tmpbuf;
    char *tcp = strchr(cp, '\n');

    if (tmpbuf[0] == '#')
      continue;
    if (tcp)
      *tcp = '\000';

    tcp = strchr(cp, ',');
    if (tcp) {
      ih_def_t *new_ih_list;
      new_ih_list = realloc(valid_ihs.ih_list,
                          (valid_ihs.count + 1)*sizeof (valid_ihs.ih_list[0]));
      if (new_ih_list == NULL) {
        break;
      }
      valid_ihs.ih_list = new_ih_list;
      valid_ihs.ih_list[valid_ihs.count].hint_match = strndup(cp, tcp-cp);
      cp = tcp+1;
      tcp = strchr(cp, ',');
      if (tcp) {
        valid_ihs.ih_list[valid_ihs.count].new_identity =
                               coap_new_bin_const((const uint8_t *)cp, tcp-cp);
        cp = tcp+1;
        valid_ihs.ih_list[valid_ihs.count].new_key =
                           coap_new_bin_const((const uint8_t *)cp, strlen(cp));
        valid_ihs.count++;
      }
      else {
        /* Badly formatted */
        free(valid_ihs.ih_list[valid_ihs.count].hint_match);
      }
    }
  }
  fclose(fp);
  return valid_ihs.count > 0;
}

static uint8_t *read_file_mem(const char* filename, size_t *length) {
  FILE *f;
  uint8_t *buf;
  struct stat statbuf;

  *length = 0;
  if (!filename || !(f = fopen(filename, "r")))
    return NULL;

  if (fstat(fileno(f), &statbuf) == -1) {
    fclose(f);
    return NULL;
  }

  buf = coap_malloc(statbuf.st_size+1);
  if (!buf) {
    fclose(f);
    return NULL;
  }

  if (fread(buf, 1, statbuf.st_size, f) != (size_t)statbuf.st_size) {
    fclose(f);
    coap_free(buf);
    return NULL;
  }
  buf[statbuf.st_size] = '\000';
  *length = (size_t)(statbuf.st_size + 1);
  fclose(f);
  return buf;
}

static int
verify_cn_callback(const char *cn,
                   const uint8_t *asn1_public_cert UNUSED_PARAM,
                   size_t asn1_length UNUSED_PARAM,
                   coap_session_t *session UNUSED_PARAM,
                   unsigned depth,
                   int validated UNUSED_PARAM,
                   void *arg UNUSED_PARAM
) {
  coap_log(LOG_INFO, "CN '%s' presented by server (%s)\n",
           cn, depth ? "CA" : "Certificate");
  return 1;
}

static const coap_dtls_cpsk_info_t *
verify_ih_callback(coap_str_const_t *hint,
                   coap_session_t *c_session UNUSED_PARAM,
                   void *arg
) {
  coap_dtls_cpsk_info_t *psk_info = (coap_dtls_cpsk_info_t *)arg;
  char lhint[COAP_DTLS_HINT_LENGTH];
  static coap_dtls_cpsk_info_t psk_identity_info;
  size_t i;

  snprintf(lhint, sizeof(lhint), "%.*s", (int)hint->length, hint->s);
  coap_log(LOG_INFO, "Identity Hint '%s' provided\n", lhint);

  /* Test for hint to possibly change identity + key */
  for (i = 0; i < valid_ihs.count; i++) {
    if (strcmp(lhint, valid_ihs.ih_list[i].hint_match) == 0) {
      /* Preset */
      psk_identity_info = *psk_info;
      if (valid_ihs.ih_list[i].new_key) {
        psk_identity_info.key = *valid_ihs.ih_list[i].new_key;
      }
      if (valid_ihs.ih_list[i].new_identity) {
        psk_identity_info.identity = *valid_ihs.ih_list[i].new_identity;
      }
      coap_log(LOG_INFO, "Switching to using '%s' identity + '%s' key\n",
               psk_identity_info.identity.s, psk_identity_info.key.s);
      return &psk_identity_info;
    }
  }
  /* Just use the defined key for now as passed in by arg */
  return psk_info;
}

static coap_dtls_pki_t *
setup_pki(coap_context_t *ctx) {
  static coap_dtls_pki_t dtls_pki;
  static char client_sni[256];

  /* If general root CAs are defined */
  if (root_ca_file) {
    struct stat stbuf;
    if ((stat(root_ca_file, &stbuf) == 0) && S_ISDIR(stbuf.st_mode)) {
      coap_context_set_pki_root_cas(ctx, NULL, root_ca_file);
    } else {
      coap_context_set_pki_root_cas(ctx, root_ca_file, NULL);
    }
  }

  memset(client_sni, 0, sizeof(client_sni));
  memset (&dtls_pki, 0, sizeof(dtls_pki));
  dtls_pki.version = COAP_DTLS_PKI_SETUP_VERSION;
  if (ca_file || root_ca_file) {
    /*
     * Add in additional certificate checking.
     * This list of enabled can be tuned for the specific
     * requirements - see 'man coap_encryption'.
     *
     * Note: root_ca_file is setup separately using
     * coap_context_set_pki_root_cas(), but this is used to define what
     * checking actually takes place.
     */
    dtls_pki.verify_peer_cert        = !is_rpk_not_cert;
    dtls_pki.require_peer_cert       = 1;
    dtls_pki.allow_self_signed       = 1;
    dtls_pki.allow_expired_certs     = 1;
    dtls_pki.cert_chain_validation   = 1;
    dtls_pki.cert_chain_verify_depth = 2;
    dtls_pki.check_cert_revocation   = 1;
    dtls_pki.allow_no_crl            = 1;
    dtls_pki.allow_expired_crl       = 1;
    dtls_pki.validate_cn_call_back   = verify_cn_callback;
    dtls_pki.cn_call_back_arg        = NULL;
    dtls_pki.validate_sni_call_back  = NULL;
    dtls_pki.sni_call_back_arg       = NULL;
  }
  if ((uri.host.length == 3 && memcmp(uri.host.s, "::1", 3) != 0) ||
      (uri.host.length == 9 && memcmp(uri.host.s, "127.0.0.1", 9) != 0))
    memcpy(client_sni, uri.host.s, min(uri.host.length, sizeof(client_sni)-1));
  else
    memcpy(client_sni, "localhost", 9);

  dtls_pki.is_rpk_not_cert = is_rpk_not_cert;
  dtls_pki.client_sni = client_sni;
  if ((key_file && strncasecmp (key_file, "pkcs11:", 7) == 0) ||
      (cert_file && strncasecmp (cert_file, "pkcs11:", 7) == 0) ||
      (ca_file && strncasecmp (ca_file, "pkcs11:", 7) == 0)) {
    dtls_pki.pki_key.key_type = COAP_PKI_KEY_PKCS11;
    dtls_pki.pki_key.key.pkcs11.public_cert = cert_file;
    dtls_pki.pki_key.key.pkcs11.private_key = key_file ?
                                                     key_file : cert_file;
    dtls_pki.pki_key.key.pkcs11.ca = ca_file;
    dtls_pki.pki_key.key.pkcs11.user_pin = pkcs11_pin;
  }
  else if (!is_rpk_not_cert) {
    dtls_pki.pki_key.key_type = COAP_PKI_KEY_PEM;
    dtls_pki.pki_key.key.pem.public_cert = cert_file;
    dtls_pki.pki_key.key.pem.private_key = key_file ? key_file : cert_file;
    dtls_pki.pki_key.key.pem.ca_file = ca_file;
  }
  else {
    /* Map file into memory */
    if (ca_mem == 0 && cert_mem == 0 && key_mem == 0) {
      ca_mem = read_file_mem(ca_file, &ca_mem_len);
      cert_mem = read_file_mem(cert_file, &cert_mem_len);
      key_mem = read_file_mem(key_file, &key_mem_len);
    }
    dtls_pki.pki_key.key_type = COAP_PKI_KEY_PEM_BUF;
    dtls_pki.pki_key.key.pem_buf.ca_cert = ca_mem;
    dtls_pki.pki_key.key.pem_buf.public_cert = cert_mem;
    dtls_pki.pki_key.key.pem_buf.private_key = key_mem ? key_mem : cert_mem;
    dtls_pki.pki_key.key.pem_buf.ca_cert_len = ca_mem_len;
    dtls_pki.pki_key.key.pem_buf.public_cert_len = cert_mem_len;
    dtls_pki.pki_key.key.pem_buf.private_key_len = key_mem ?
                                                    key_mem_len : cert_mem_len;
  }
  return &dtls_pki;
}

static coap_dtls_cpsk_t *
setup_psk(
  const uint8_t *identity,
  size_t identity_len,
  const uint8_t *key,
  size_t key_len
) {
  static coap_dtls_cpsk_t dtls_psk;
  static char client_sni[256];

  memset(client_sni, 0, sizeof(client_sni));
  memset (&dtls_psk, 0, sizeof(dtls_psk));
  dtls_psk.version = COAP_DTLS_CPSK_SETUP_VERSION;
  dtls_psk.validate_ih_call_back = verify_ih_callback;
  dtls_psk.ih_call_back_arg = &dtls_psk.psk_info;
  if (uri.host.length)
    memcpy(client_sni, uri.host.s,
           min(uri.host.length, sizeof(client_sni) - 1));
  else
    memcpy(client_sni, "localhost", 9);
  dtls_psk.client_sni = client_sni;
  dtls_psk.psk_info.identity.s = identity;
  dtls_psk.psk_info.identity.length = identity_len;
  dtls_psk.psk_info.key.s = key;
  dtls_psk.psk_info.key.length = key_len;
  return &dtls_psk;
}

#ifdef _WIN32
#define S_ISDIR(x) (((x) & S_IFMT) == S_IFDIR)
#endif

static coap_session_t*
open_session(
  coap_context_t *ctx,
  coap_proto_t proto,
  coap_address_t *bind_addr,
  coap_address_t *dst,
  const uint8_t *identity,
  size_t identity_len,
  const uint8_t *key,
  size_t key_len
) {
  coap_session_t *session;

  if (proto == COAP_PROTO_DTLS || proto == COAP_PROTO_TLS) {
    /* Encrypted session */
    if (root_ca_file || ca_file || cert_file) {
      /* Setup PKI session */
      coap_dtls_pki_t *dtls_pki = setup_pki(ctx);
      session = coap_new_client_session_pki(ctx, bind_addr, dst, proto, dtls_pki);
    }
    else if (identity || key) {
      /* Setup PSK session */
      coap_dtls_cpsk_t *dtls_psk = setup_psk(identity, identity_len,
                                               key, key_len);
      session = coap_new_client_session_psk2(ctx, bind_addr, dst, proto,
                                           dtls_psk);
    }
    else {
      /* No PKI or PSK defined, as encrypted, use PKI */
      coap_dtls_pki_t *dtls_pki = setup_pki(ctx);
      session = coap_new_client_session_pki(ctx, bind_addr, dst, proto, dtls_pki);
    }
  }
  else {
    /* Non-encrypted session */
    session = coap_new_client_session(ctx, bind_addr, dst, proto);
  }
  return session;
}

static coap_session_t *
get_session(
  coap_context_t *ctx,
  const char *local_addr,
  const char *local_port,
  coap_proto_t proto,
  coap_address_t *dst,
  const uint8_t *identity,
  size_t identity_len,
  const uint8_t *key,
  size_t key_len
) {
  coap_session_t *session = NULL;

  if ( local_addr ) {
    int s;
    struct addrinfo hints;
    struct addrinfo *result = NULL, *rp;

    memset( &hints, 0, sizeof( struct addrinfo ) );
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = COAP_PROTO_RELIABLE(proto) ? SOCK_STREAM : SOCK_DGRAM; /* Coap uses UDP */
    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV | AI_ALL;

    s = getaddrinfo( local_addr, local_port, &hints, &result );
    if ( s != 0 ) {
      fprintf( stderr, "getaddrinfo: %s\n", gai_strerror( s ) );
      return NULL;
    }

    /* iterate through results until success */
    for ( rp = result; rp != NULL; rp = rp->ai_next ) {
      coap_address_t bind_addr;
      if ( rp->ai_addrlen <= (socklen_t)sizeof( bind_addr.addr ) ) {
        coap_address_init( &bind_addr );
        bind_addr.size = (socklen_t)rp->ai_addrlen;
        memcpy( &bind_addr.addr, rp->ai_addr, rp->ai_addrlen );
        session = open_session(ctx, proto, &bind_addr, dst,
                               identity, identity_len, key, key_len);
        if ( session )
          break;
      }
    }
    freeaddrinfo( result );
  } else {
    session = open_session(ctx, proto, NULL, dst,
                               identity, identity_len, key, key_len);
  }
  return session;
}

int
main(int argc, char **argv) {
  coap_context_t  *ctx = NULL;
  coap_session_t *session = NULL;
  coap_address_t dst;
  static char addr[INET6_ADDRSTRLEN];
  void *addrptr = NULL;
  int result = -1;
  coap_pdu_t  *pdu;
  static coap_str_const_t server;
  uint16_t port = COAP_DEFAULT_PORT;
  char port_str[NI_MAXSERV] = "0";
  char node_str[NI_MAXHOST] = "";
  int opt, res;
  coap_log_t log_level = LOG_WARNING;
  unsigned char *user = NULL, *key = NULL;
  ssize_t user_length = -1, key_length = 0;
  int create_uri_opts = 1;
  size_t i;
  coap_uri_scheme_t scheme;
#ifndef _WIN32
  struct sigaction sa;
#endif

  while ((opt = getopt(argc, argv, "a:b:c:e:f:h:j:k:l:m:o:p:rs:t:u:v:wA:B:C:H:J:K:M:NO:P:R:T:U")) != -1) {
    switch (opt) {
    case 'a':
      strncpy(node_str, optarg, NI_MAXHOST - 1);
      node_str[NI_MAXHOST - 1] = '\0';
      break;
    case 'b':
      cmdline_blocksize(optarg);
      break;
    case 'B':
      wait_seconds = atoi(optarg);
      break;
    case 'c':
      cert_file = optarg;
      break;
    case 'C':
      ca_file = optarg;
      break;
    case 'R':
      root_ca_file = optarg;
      break;
    case 'e':
      if (!cmdline_input(optarg, &payload))
        payload.length = 0;
      break;
    case 'f':
      if (!cmdline_input_from_file(optarg, &payload))
        payload.length = 0;
      break;
    case 'j' :
      key_file = optarg;
      break;
    case 'J' :
      pkcs11_pin = optarg;
      break;
    case 'k':
      key_length = cmdline_read_key(optarg, &key, MAX_KEY);
      break;
    case 'p':
      strncpy(port_str, optarg, NI_MAXSERV - 1);
      port_str[NI_MAXSERV - 1] = '\0';
      break;
    case 'm':
      method = cmdline_method(optarg);
      break;
    case 'w':
      add_nl = 1;
      break;
    case 'N':
      msgtype = COAP_MESSAGE_NON;
      break;
    case 's':
      cmdline_subscribe(optarg);
      break;
    case 'o':
      output_file.length = strlen(optarg);
      output_file.s = (unsigned char *)coap_malloc(output_file.length + 1);

      if (!output_file.s) {
        fprintf(stderr, "cannot set output file: insufficient memory\n");
        exit(-1);
      } else {
        /* copy filename including trailing zero */
        memcpy(output_file.s, optarg, output_file.length + 1);
      }
      break;
    case 'A':
      cmdline_content_type(optarg, COAP_OPTION_ACCEPT);
      break;
    case 't':
      cmdline_content_type(optarg, COAP_OPTION_CONTENT_TYPE);
      break;
    case 'M':
      cert_file = optarg;
      is_rpk_not_cert = 1;
      break;
    case 'O':
      cmdline_option(optarg);
      break;
    case 'P':
      if (!cmdline_proxy(optarg)) {
        fprintf(stderr, "error specifying proxy address\n");
        exit(-1);
      }
      break;
    case 'T':
      cmdline_token(optarg);
      break;
    case 'u':
      user_length = cmdline_read_user(optarg, &user, MAX_USER);
      break;
    case 'U':
      create_uri_opts = 0;
      break;
    case 'v':
      log_level = strtol(optarg, NULL, 10);
      break;
    case 'l':
      if (!coap_debug_set_packet_loss(optarg)) {
        usage(argv[0], LIBCOAP_PACKAGE_VERSION);
        exit(1);
      }
      break;
    case 'r':
      reliable = coap_tcp_is_supported();
      break;
    case 'K':
      ping_seconds = atoi(optarg);
      break;
    case 'h':
      if (!cmdline_read_hint_check(optarg)) {
        usage(argv[0], LIBCOAP_PACKAGE_VERSION);
        exit(1);
      }
      break;
    case 'H':
      if (!cmdline_hop_limit(optarg))
        fprintf(stderr, "Hop Limit has to be > 0 and < 256\n");
      break;
    default:
      usage( argv[0], LIBCOAP_PACKAGE_VERSION );
      exit( 1 );
    }
  }

  coap_startup();
  coap_dtls_set_log_level(log_level);
  coap_set_log_level(log_level);

  if (optind < argc) {
    if (cmdline_uri(argv[optind], create_uri_opts) < 0) {
      exit(1);
    }
  } else {
    usage( argv[0], LIBCOAP_PACKAGE_VERSION );
    exit( 1 );
  }

  if (key_length < 0) {
    coap_log( LOG_CRIT, "Invalid pre-shared key specified\n" );
    goto finish;
  }

  if (proxy.host.length) {
    server = proxy.host;
    port = proxy.port;
    scheme = proxy.scheme;
  } else {
    server = uri.host;
    port = proxy_scheme_option ? proxy.port : uri.port;
    scheme = proxy_scheme_option ? proxy.scheme : uri.scheme;
  }

  /* resolve destination address where server should be sent */
  res = resolve_address(&server, &dst.addr.sa);

  if (res < 0) {
    fprintf(stderr, "failed to resolve address\n");
    exit(-1);
  }

  ctx = coap_new_context( NULL );
  if ( !ctx ) {
    coap_log( LOG_EMERG, "cannot create context\n" );
    goto finish;
  }

  coap_context_set_keepalive(ctx, ping_seconds);

  dst.size = res;
  dst.addr.sin.sin_port = htons( port );

  session = get_session(
    ctx,
    node_str[0] ? node_str : NULL, port_str,
    scheme==COAP_URI_SCHEME_COAP_TCP ? COAP_PROTO_TCP :
    scheme==COAP_URI_SCHEME_COAPS_TCP ? COAP_PROTO_TLS :
    (reliable ?
        scheme==COAP_URI_SCHEME_COAPS ? COAP_PROTO_TLS : COAP_PROTO_TCP
      : scheme==COAP_URI_SCHEME_COAPS ? COAP_PROTO_DTLS : COAP_PROTO_UDP),
    &dst,
    user_length >= 0 ? user : NULL,
    user_length >= 0 ? user_length : 0,
    key_length > 0 ? key : NULL,
    key_length > 0 ? key_length : 0
  );

  if ( !session ) {
    coap_log( LOG_EMERG, "cannot create client session\n" );
    goto finish;
  }

  /* add Uri-Host if server address differs from uri.host */

  switch (dst.addr.sa.sa_family) {
  case AF_INET:
    addrptr = &dst.addr.sin.sin_addr;
    /* create context for IPv4 */
    break;
  case AF_INET6:
    addrptr = &dst.addr.sin6.sin6_addr;
    break;
  default:
    ;
  }

  coap_register_option(ctx, COAP_OPTION_BLOCK2);
  coap_register_response_handler(ctx, message_handler);
  coap_register_event_handler(ctx, event_handler);
  coap_register_nack_handler(ctx, nack_handler);

  /* construct CoAP message */

  if (!uri_host_option && (!proxy.host.length && addrptr
      && (inet_ntop(dst.addr.sa.sa_family, addrptr, addr, sizeof(addr)) != 0)
      && (strlen(addr) != uri.host.length
      || memcmp(addr, uri.host.s, uri.host.length) != 0)
      && create_uri_opts)) {
        /* add Uri-Host */

        coap_insert_optlist(&optlist,
                    coap_new_optlist(COAP_OPTION_URI_HOST,
                    uri.host.length,
                    uri.host.s));
  }

  /* set block option if requested at commandline */
  if (flags & FLAGS_BLOCK)
    set_blocksize();

  if (! (pdu = coap_new_request(ctx, session, method, &optlist, payload.s, payload.length))) {
    goto finish;
  }

  coap_log(LOG_DEBUG, "sending CoAP request:\n");
  if (coap_get_log_level() < LOG_DEBUG)
    coap_show_pdu(LOG_INFO, pdu);

  coap_send(session, pdu);

  wait_ms = wait_seconds * 1000;
  coap_log(LOG_DEBUG, "timeout is set to %u seconds\n", wait_seconds);

#ifdef _WIN32
  signal(SIGINT, handle_sigint);
#else
  memset (&sa, 0, sizeof(sa));
  sigemptyset(&sa.sa_mask);
  sa.sa_handler = handle_sigint;
  sa.sa_flags = 0;
  sigaction (SIGINT, &sa, NULL);
  sigaction (SIGTERM, &sa, NULL);
  /* So we do not exit on a SIGPIPE */
  sa.sa_handler = SIG_IGN;
  sigaction (SIGPIPE, &sa, NULL);
#endif

  while (!quit && !(ready && !doing_getting_block && coap_can_exit(ctx)) ) {

    result = coap_io_process( ctx, wait_ms == 0 ?
                                 obs_ms : obs_ms == 0 ?
                                 min(wait_ms, 1000) : min( wait_ms, obs_ms ) );

    if ( result >= 0 ) {
      if ( wait_ms > 0 && !wait_ms_reset ) {
        if ( (unsigned)result >= wait_ms ) {
          coap_log(LOG_INFO, "timeout\n");
          break;
        } else {
          wait_ms -= result;
        }
      }
      if ( obs_ms > 0 && !obs_ms_reset ) {
        if ( (unsigned)result >= obs_ms ) {
          coap_log(LOG_DEBUG, "clear observation relationship\n" );
          clear_obs( ctx, session ); /* FIXME: handle error case COAP_TID_INVALID */

          /* make sure that the obs timer does not fire again */
          obs_ms = 0;
          obs_seconds = 0;
        } else {
          obs_ms -= result;
        }
      }
      wait_ms_reset = 0;
      obs_ms_reset = 0;
    }
  }

  result = 0;

 finish:

  coap_free(ca_mem);
  coap_free(cert_mem);
  coap_free(key_mem);
  for (i = 0; i < valid_ihs.count; i++) {
    free(valid_ihs.ih_list[i].hint_match);
    coap_delete_bin_const(valid_ihs.ih_list[i].new_identity);
    coap_delete_bin_const(valid_ihs.ih_list[i].new_key);
  }
  if (valid_ihs.count)
    free(valid_ihs.ih_list);
  coap_delete_optlist(optlist);
  if (payload.s) coap_free(payload.s);
  coap_session_release( session );
  coap_free_context( ctx );
  coap_cleanup();
  close_output();

  return result;
}
