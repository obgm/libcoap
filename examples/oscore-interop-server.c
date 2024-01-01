/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/* oscore-interop-server
 *
 * A server for use in the RFC 8613 OSCORE interop testing.
 * https://core-wg.github.io/oscore/test-spec5.html
 *
 * Copyright (C) 2022-2024 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#ifdef _WIN32
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#include "getopt.c"
#if !defined(S_ISDIR)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif
#ifndef R_OK
#define R_OK 4
#endif
static char *
strndup(const char *s1, size_t n) {
  char *copy = (char *)malloc(n + 1);
  if (copy) {
    memcpy(copy, s1, n);
    copy[n] = 0;
  }
  return copy;
}
#include <io.h>
#define access _access
#define fileno _fileno
#else
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dirent.h>
#endif

#include <coap3/coap.h>

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

static coap_oscore_conf_t *oscore_conf;
static int doing_oscore = 0;

/* set to 1 to request clean server shutdown */
static int quit = 0;

static coap_resource_t *r_observe_1;
static coap_resource_t *r_observe_2;

static int resource_flags = COAP_RESOURCE_FLAGS_NOTIFY_CON;

static uint32_t block_mode = COAP_BLOCK_USE_LIBCOAP;
static uint32_t csm_max_message_size = 0;

/* SIGINT handler: set quit to 1 for graceful termination */
static void
handle_sigint(int signum COAP_UNUSED) {
  quit = 1;
}

#define INDEX "This is a OSCORE test server made with libcoap " \
  "(see https://libcoap.net)\n" \
  "Copyright (C) 2022-2024 Olaf Bergmann <bergmann@tzi.org> " \
  "and others\n\n"

static void
hnd_get_index(coap_resource_t *resource,
              coap_session_t *session,
              const coap_pdu_t *request,
              const coap_string_t *query COAP_UNUSED,
              coap_pdu_t *response) {

  coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
  coap_add_data_large_response(resource, session, request, response,
                               query, COAP_MEDIATYPE_TEXT_PLAIN,
                               0x2ffff, 0, strlen(INDEX),
                               (const uint8_t *)INDEX, NULL, NULL);
}

#define HELLO_WORLD "Hello World!"

static void
hnd_get_hello_coap(coap_resource_t *resource,
                   coap_session_t *session,
                   const coap_pdu_t *request,
                   const coap_string_t *query,
                   coap_pdu_t *response) {
  coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
  coap_add_data_large_response(resource, session, request, response,
                               query, COAP_MEDIATYPE_TEXT_PLAIN,
                               -1, 0, strlen(HELLO_WORLD),
                               (const uint8_t *)HELLO_WORLD, NULL, NULL);
}

static void
hnd_get_hello_1(coap_resource_t *resource,
                coap_session_t *session,
                const coap_pdu_t *request,
                const coap_string_t *query,
                coap_pdu_t *response) {
  coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
  coap_add_data_large_response(resource, session, request, response,
                               query, COAP_MEDIATYPE_TEXT_PLAIN,
                               -1, 0, strlen(HELLO_WORLD),
                               (const uint8_t *)HELLO_WORLD, NULL, NULL);
}

static void
hnd_get_hello_2(coap_resource_t *resource,
                coap_session_t *session,
                const coap_pdu_t *request,
                const coap_string_t *query,
                coap_pdu_t *response) {
  coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
  coap_add_data_large_response(resource, session, request, response,
                               query, COAP_MEDIATYPE_TEXT_PLAIN,
                               -1, 0x2b, strlen(HELLO_WORLD),
                               (const uint8_t *)HELLO_WORLD, NULL, NULL);
}

static void
hnd_get_hello_3(coap_resource_t *resource,
                coap_session_t *session,
                const coap_pdu_t *request,
                const coap_string_t *query,
                coap_pdu_t *response) {
  coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
  coap_add_data_large_response(resource, session, request, response,
                               query, COAP_MEDIATYPE_TEXT_PLAIN,
                               5, 0, strlen(HELLO_WORLD),
                               (const uint8_t *)HELLO_WORLD, NULL, NULL);
}

static void
hnd_post_hello_6(coap_resource_t *resource,
                 coap_session_t *session,
                 const coap_pdu_t *request,
                 const coap_string_t *query,
                 coap_pdu_t *response) {
  size_t size;
  const uint8_t *data;

  (void)coap_get_data(request, &size, &data);
  coap_pdu_set_code(response, COAP_RESPONSE_CODE_CHANGED);
  coap_add_data_large_response(resource, session, request, response,
                               query, COAP_MEDIATYPE_TEXT_PLAIN,
                               -1, 0, size,
                               data, NULL, NULL);
}

static void
hnd_put_hello_7(coap_resource_t *resource,
                coap_session_t *session,
                const coap_pdu_t *request,
                const coap_string_t *query,
                coap_pdu_t *response) {
  size_t size;
  const uint8_t *data;
  coap_opt_iterator_t opt_iter;
  coap_opt_t *option;
  uint64_t etag;


  if ((option = coap_check_option(request, COAP_OPTION_IF_MATCH,
                                  &opt_iter)) != NULL) {
    etag = coap_decode_var_bytes8(coap_opt_value(option),
                                  coap_opt_length(option));
    if (etag != 0x7b) {
      coap_pdu_set_code(response, COAP_RESPONSE_CODE_PRECONDITION_FAILED);
      return;
    }
  }

  coap_pdu_set_code(response, COAP_RESPONSE_CODE_CHANGED);
  (void)coap_get_data(request, &size, &data);
  coap_add_data_large_response(resource, session, request, response,
                               query, COAP_MEDIATYPE_TEXT_PLAIN,
                               -1, 0x7b, size,
                               data, NULL, NULL);
}

static void
hnd_get_observe1(coap_resource_t *resource,
                 coap_session_t *session,
                 const coap_pdu_t *request,
                 const coap_string_t *query,
                 coap_pdu_t *response) {
  static int count = 0;

  count++;
  switch (count) {
  case 1:
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
    coap_add_data_large_response(resource, session, request, response,
                                 query, COAP_MEDIATYPE_TEXT_PLAIN,
                                 1, 0, strlen("one"),
                                 (const uint8_t *)"one", NULL, NULL);
    break;
  case 2:
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
    coap_add_data_large_response(resource, session, request, response,
                                 query, COAP_MEDIATYPE_TEXT_PLAIN,
                                 1, 0, strlen("two"),
                                 (const uint8_t *)"two", NULL, NULL);
    break;
  default:
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_INTERNAL_ERROR);
    coap_add_data_large_response(resource, session, request, response,
                                 query, COAP_MEDIATYPE_TEXT_PLAIN,
                                 -1, 0, strlen("Terminate Observe"),
                                 (const uint8_t *)"Terminate Observe",
                                 NULL, NULL);
    r_observe_1 = NULL;
  }
}

static void
hnd_get_observe2(coap_resource_t *resource,
                 coap_session_t *session,
                 const coap_pdu_t *request,
                 const coap_string_t *query,
                 coap_pdu_t *response) {
  static int count = 0;

  count++;
  switch (count) {
  case 1:
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
    coap_add_data_large_response(resource, session, request, response,
                                 query, COAP_MEDIATYPE_TEXT_PLAIN,
                                 1, 0, strlen("one"),
                                 (const uint8_t *)"one", NULL, NULL);
    break;
  case 2:
  default:
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
    coap_add_data_large_response(resource, session, request, response,
                                 query, COAP_MEDIATYPE_TEXT_PLAIN,
                                 1, 0, strlen("two"),
                                 (const uint8_t *)"two", NULL, NULL);
    r_observe_2 = NULL;
    break;
  }
}

static void
hnd_del_test(coap_resource_t *resource COAP_UNUSED,
             coap_session_t *session COAP_UNUSED,
             const coap_pdu_t *request COAP_UNUSED,
             const coap_string_t *query COAP_UNUSED,
             coap_pdu_t *response) {
  coap_pdu_set_code(response, COAP_RESPONSE_CODE_DELETED);
}

static void
init_resources(coap_context_t *ctx) {
  coap_resource_t *r;

  r = coap_resource_init(NULL, COAP_RESOURCE_FLAGS_HAS_MCAST_SUPPORT);
  coap_register_request_handler(r, COAP_REQUEST_GET, hnd_get_index);

  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("0"), 0);
  coap_add_attr(r, coap_make_str_const("title"),
                coap_make_str_const("\"General Info\""), 0);
  coap_add_resource(ctx, r);

  r = coap_resource_init(coap_make_str_const("oscore/hello/coap"),
                         resource_flags);
  coap_register_request_handler(r, COAP_REQUEST_GET, hnd_get_hello_coap);
  coap_add_resource(ctx, r);

  r = coap_resource_init(coap_make_str_const("oscore/hello/1"),
                         resource_flags | COAP_RESOURCE_FLAGS_OSCORE_ONLY);
  coap_register_request_handler(r, COAP_REQUEST_GET, hnd_get_hello_1);
  coap_add_resource(ctx, r);

  r = coap_resource_init(coap_make_str_const("oscore/hello/2"),
                         resource_flags | COAP_RESOURCE_FLAGS_OSCORE_ONLY);
  coap_register_request_handler(r, COAP_REQUEST_GET, hnd_get_hello_2);
  coap_add_resource(ctx, r);

  r = coap_resource_init(coap_make_str_const("oscore/hello/3"),
                         resource_flags | COAP_RESOURCE_FLAGS_OSCORE_ONLY);
  coap_register_request_handler(r, COAP_REQUEST_GET, hnd_get_hello_3);
  coap_add_resource(ctx, r);

  r = coap_resource_init(coap_make_str_const("oscore/hello/6"),
                         resource_flags | COAP_RESOURCE_FLAGS_OSCORE_ONLY);
  coap_register_request_handler(r, COAP_REQUEST_POST, hnd_post_hello_6);
  coap_add_resource(ctx, r);

  r = coap_resource_init(coap_make_str_const("oscore/hello/7"),
                         resource_flags | COAP_RESOURCE_FLAGS_OSCORE_ONLY);
  coap_register_request_handler(r, COAP_REQUEST_PUT, hnd_put_hello_7);
  coap_add_resource(ctx, r);

  r = coap_resource_init(coap_make_str_const("oscore/observe1"),
                         resource_flags | COAP_RESOURCE_FLAGS_OSCORE_ONLY);
  coap_register_request_handler(r, COAP_REQUEST_GET, hnd_get_observe1);
  coap_resource_set_get_observable(r, 1);
  coap_add_resource(ctx, r);
  r_observe_1 = r;

  r = coap_resource_init(coap_make_str_const("oscore/observe2"),
                         resource_flags | COAP_RESOURCE_FLAGS_OSCORE_ONLY);
  coap_register_request_handler(r, COAP_REQUEST_GET, hnd_get_observe2);
  coap_resource_set_get_observable(r, 1);
  coap_add_resource(ctx, r);
  r_observe_2 = r;

  r = coap_resource_init(coap_make_str_const("oscore/test"),
                         resource_flags | COAP_RESOURCE_FLAGS_OSCORE_ONLY);
  coap_register_request_handler(r, COAP_REQUEST_DELETE, hnd_del_test);
  coap_add_resource(ctx, r);
}

static uint8_t *
read_file_mem(const char *file, size_t *length) {
  FILE *f;
  uint8_t *buf;
  struct stat statbuf;

  *length = 0;
  if (!file || !(f = fopen(file, "r")))
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

static void
usage(const char *program, const char *version) {
  const char *p;
  char buffer[120];
  const char *lib_build = coap_package_build();

  p = strrchr(program, '/');
  if (p)
    program = ++p;

  fprintf(stderr, "%s v%s -- OSCORE interop implementation\n"
          "(c) 2022-2024 Olaf Bergmann <bergmann@tzi.org> and others\n\n"
          "Build: %s\n"
          "%s\n"
          , program, version, lib_build,
          coap_string_tls_version(buffer, sizeof(buffer)));
  fprintf(stderr, "%s\n", coap_string_tls_support(buffer, sizeof(buffer)));
  fprintf(stderr, "\n"
          "Usage: %s [-d max] [-g group] [-l loss] [-p port] [-r] [-v num]\n"
          "\t\t[-A address] [-E oscore_conf_file[,seq_file]] [-G group_if]\n"
          "\t\t[-L value] [-N] [-P scheme://address[:port],[name1[,name2..]]]\n"
          "\t\t[-X size]\n"
          "General Options\n"
          "\t-d max \t\tAllow dynamic creation of up to a total of max\n"
          "\t       \t\tresources. If max is reached, a 4.06 code is returned\n"
          "\t       \t\tuntil one of the dynamic resources has been deleted\n"
          "\t-g group\tJoin the given multicast group\n"
          "\t       \t\tNote: DTLS over multicast is not currently supported\n"
          "\t-l list\t\tFail to send some datagrams specified by a comma\n"
          "\t       \t\tseparated list of numbers or number ranges\n"
          "\t       \t\t(for debugging only)\n"
          "\t-l loss%%\tRandomly fail to send datagrams with the specified\n"
          "\t       \t\tprobability - 100%% all datagrams, 0%% no datagrams\n"
          "\t       \t\t(for debugging only)\n"
          "\t-p port\t\tListen on specified port for UDP and TCP. If (D)TLS is\n"
          "\t       \t\tenabled, then the coap-server will also listen on\n"
          "\t       \t\t 'port'+1 for DTLS and TLS.  The default port is 5683\n"
          "\t-r     \t\tEnable multicast per resource support.  If enabled,\n"
          "\t       \t\tonly '/', '/async' and '/.well-known/core' are enabled\n"
          "\t       \t\tfor multicast requests support, otherwise all\n"
          "\t       \t\tresources are enabled\n"
          "\t-v num \t\tVerbosity level (default 3, maximum is 9). Above 7,\n"
          "\t       \t\tthere is increased verbosity in GnuTLS and OpenSSL\n"
          "\t       \t\tlogging\n"
          "\t-A address\tInterface address to bind to\n"
          "\t-E oscore_conf_file[,seq_file]\n"
          "\t       \t\toscore_conf_file contains OSCORE configuration. See\n"
          "\t       \t\tcoap-oscore-conf(5) for definitions.\n"
          "\t       \t\tOptional seq_file is used to save the current transmit\n"
          "\t       \t\tsequence number, so on restart sequence numbers continue\n"
          "\t-G group_if\tUse this interface for listening for the multicast\n"
          "\t       \t\tgroup. This can be different from the implied interface\n"
          "\t       \t\tif the -A option is used\n"
          "\t-L value\tSum of one or more COAP_BLOCK_* flag valuess for block\n"
          "\t       \t\thandling methods. Default is 1 (COAP_BLOCK_USE_LIBCOAP)\n"
          "\t       \t\t(Sum of one or more of 1,2 and 4)\n"
          "\t-N     \t\tMake \"observe\" responses NON-confirmable. Even if set\n"
          "\t       \t\tevery fifth response will still be sent as a confirmable\n"
          "\t       \t\tresponse (RFC 7641 requirement)\n"
          , program);
}

static coap_context_t *
get_context(const char *node, const char *port) {
  coap_context_t *ctx = NULL;
  int s;
  struct addrinfo hints;
  struct addrinfo *result, *rp;

  ctx = coap_new_context(NULL);
  if (!ctx) {
    return NULL;
  }

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
  hints.ai_socktype = SOCK_DGRAM; /* Coap uses UDP */
  hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

  s = getaddrinfo(node, port, &hints, &result);
  if (s != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
    coap_free_context(ctx);
    return NULL;
  }

  /* iterate through results until success */
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    coap_address_t addr;
    coap_endpoint_t *ep_udp = NULL;

    if (rp->ai_addrlen <= (socklen_t)sizeof(addr.addr)) {
      coap_address_init(&addr);
      addr.size = (socklen_t)rp->ai_addrlen;
      memcpy(&addr.addr, rp->ai_addr, rp->ai_addrlen);

      ep_udp = coap_new_endpoint(ctx, &addr, COAP_PROTO_UDP);
      if (!ep_udp) {
        coap_log_crit("cannot create UDP endpoint\n");
        continue;
      }
      if (coap_tcp_is_supported()) {
        coap_endpoint_t *ep_tcp;
        ep_tcp = coap_new_endpoint(ctx, &addr, COAP_PROTO_TCP);
        if (!ep_tcp) {
          coap_log_crit("cannot create TCP endpoint\n");
        }
      }
      if (ep_udp)
        goto finish;
    }
  }

  fprintf(stderr, "no context available for interface '%s'\n", node);
  coap_free_context(ctx);
  ctx = NULL;

finish:
  freeaddrinfo(result);
  return ctx;
}

static FILE *oscore_seq_num_fp = NULL;
static const char *oscore_conf_file = NULL;
static const char *oscore_seq_save_file = NULL;

static int
oscore_save_seq_num(uint64_t sender_seq_num, void *param COAP_UNUSED) {
  if (oscore_seq_num_fp) {
    rewind(oscore_seq_num_fp);
    fprintf(oscore_seq_num_fp, "%" PRIu64 "\n", sender_seq_num);
    fflush(oscore_seq_num_fp);
  }
  return 1;
}

static coap_oscore_conf_t *
get_oscore_conf(coap_context_t *context) {
  uint8_t *buf;
  size_t length;
  coap_str_const_t file_mem;
  uint64_t start_seq_num = 0;

  buf = read_file_mem(oscore_conf_file, &length);
  if (buf == NULL) {
    fprintf(stderr, "OSCORE configuration file error: %s\n", oscore_conf_file);
    return NULL;
  }
  file_mem.s = buf;
  file_mem.length = length;
  if (oscore_seq_save_file) {
    oscore_seq_num_fp = fopen(oscore_seq_save_file, "r+");
    if (oscore_seq_num_fp == NULL) {
      /* Try creating it */
      oscore_seq_num_fp = fopen(oscore_seq_save_file, "w+");
      if (oscore_seq_num_fp == NULL) {
        fprintf(stderr, "OSCORE save restart info file error: %s\n",
                oscore_seq_save_file);
        return NULL;
      }
    }
    if (fscanf(oscore_seq_num_fp, "%" PRIu64, &start_seq_num) != 1) {
      /* Must be empty */
      start_seq_num = 0;
    }
  }
  oscore_conf = coap_new_oscore_conf(file_mem,
                                     oscore_save_seq_num,
                                     NULL, start_seq_num);
  coap_free(buf);
  if (oscore_conf == NULL) {
    fprintf(stderr, "OSCORE configuration file error: %s\n", oscore_conf_file);
    return NULL;
  }
  coap_context_oscore_server(context, oscore_conf);
  return oscore_conf;
}

static int
cmdline_oscore(char *arg) {
  if (coap_oscore_is_supported()) {
    char *sep = strchr(arg, ',');

    if (sep)
      *sep = '\000';
    oscore_conf_file = arg;

    if (sep) {
      sep++;
      oscore_seq_save_file = sep;
    }
    doing_oscore = 1;
    return 1;
  }
  fprintf(stderr, "OSCORE support not enabled\n");
  return 0;
}

int
main(int argc, char **argv) {
  coap_context_t  *ctx;
  char *group = NULL;
  char *group_if = NULL;
  coap_tick_t now;
  char addr_str[NI_MAXHOST] = "::";
  char port_str[NI_MAXSERV] = "5683";
  int opt;
  int mcast_per_resource = 0;
  coap_log_t log_level = COAP_LOG_WARN;
  unsigned wait_ms;
  coap_time_t t_last = 0;
  int coap_fd;
  fd_set m_readfds;
  int nfds = 0;
  uint16_t cache_ignore_options[] = { COAP_OPTION_BLOCK1,
                                      COAP_OPTION_BLOCK2,
                                      /* See https://rfc-editor.org/rfc/rfc7959#section-2.10 */
                                      COAP_OPTION_MAXAGE,
                                      /* See https://rfc-editor.org/rfc/rfc7959#section-2.10 */
                                      COAP_OPTION_IF_NONE_MATCH
                                    };
#ifndef _WIN32
  struct sigaction sa;
#endif

  /* Initialize libcoap library */
  coap_startup();

  while ((opt = getopt(argc, argv, "g:G:l:p:rv:A:E:L:NX:")) != -1) {
    switch (opt) {
    case 'A' :
      strncpy(addr_str, optarg, NI_MAXHOST-1);
      addr_str[NI_MAXHOST - 1] = '\0';
      break;
    case 'E':
      if (!cmdline_oscore(optarg)) {
        exit(1);
      }
      break;
    case 'g' :
      group = optarg;
      break;
    case 'G' :
      group_if = optarg;
      break;
    case 'l':
      if (!coap_debug_set_packet_loss(optarg)) {
        usage(argv[0], LIBCOAP_PACKAGE_VERSION);
        exit(1);
      }
      break;
    case 'L':
      block_mode = strtoul(optarg, NULL, 0);
      if (!(block_mode & COAP_BLOCK_USE_LIBCOAP)) {
        fprintf(stderr, "Block mode must include COAP_BLOCK_USE_LIBCOAP (1)\n");
        exit(-1);
      }
      break;
    case 'N':
      resource_flags = COAP_RESOURCE_FLAGS_NOTIFY_NON;
      break;
    case 'p' :
      strncpy(port_str, optarg, NI_MAXSERV-1);
      port_str[NI_MAXSERV - 1] = '\0';
      break;
    case 'r' :
      mcast_per_resource = 1;
      break;
    case 'v' :
      log_level = strtol(optarg, NULL, 10);
      break;
    case 'X':
      csm_max_message_size = strtol(optarg, NULL, 10);
      break;
    default:
      usage(argv[0], LIBCOAP_PACKAGE_VERSION);
      exit(1);
    }
  }

#ifdef _WIN32
  signal(SIGINT, handle_sigint);
#else
  memset(&sa, 0, sizeof(sa));
  sigemptyset(&sa.sa_mask);
  sa.sa_handler = handle_sigint;
  sa.sa_flags = 0;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  /* So we do not exit on a SIGPIPE */
  sa.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &sa, NULL);
#endif

  coap_dtls_set_log_level(log_level);
  coap_set_log_level(log_level);

  ctx = get_context(addr_str, port_str);
  if (!ctx)
    return -1;

  init_resources(ctx);
  if (mcast_per_resource)
    coap_mcast_per_resource(ctx);
  coap_context_set_block_mode(ctx, block_mode);
  if (csm_max_message_size)
    coap_context_set_csm_max_message_size(ctx, csm_max_message_size);
  if (doing_oscore) {
    if (get_oscore_conf(ctx) == NULL)
      goto finish;
  }

  /* Define the options to ignore when setting up cache-keys */
  coap_cache_ignore_options(ctx, cache_ignore_options,
                            sizeof(cache_ignore_options)/sizeof(cache_ignore_options[0]));
  /* join multicast group if requested at command line */
  if (group)
    coap_join_mcast_group_intf(ctx, group, group_if);

  coap_fd = coap_context_get_coap_fd(ctx);
  if (coap_fd != -1) {
    /* if coap_fd is -1, then epoll is not supported within libcoap */
    FD_ZERO(&m_readfds);
    FD_SET(coap_fd, &m_readfds);
    nfds = coap_fd + 1;
  }

  wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;

  while (!quit) {
    int result;

    if (coap_fd != -1) {
      /*
       * Using epoll.  It is more usual to call coap_io_process() with wait_ms
       * (as in the non-epoll branch), but doing it this way gives the
       * flexibility of potentially working with other file descriptors that
       * are not a part of libcoap.
       */
      fd_set readfds = m_readfds;
      struct timeval tv;
      coap_tick_t begin, end;

      coap_ticks(&begin);

      tv.tv_sec = wait_ms / 1000;
      tv.tv_usec = (wait_ms % 1000) * 1000;
      /* Wait until any i/o takes place or timeout */
      result = select(nfds, &readfds, NULL, NULL, &tv);
      if (result == -1) {
        if (errno != EAGAIN) {
          coap_log_debug("select: %s (%d)\n", coap_socket_strerror(),
                         errno);
          break;
        }
      }
      if (result > 0) {
        if (FD_ISSET(coap_fd, &readfds)) {
          result = coap_io_process(ctx, COAP_IO_NO_WAIT);
        }
      }
      if (result >= 0) {
        coap_ticks(&end);
        /* Track the overall time spent in select() and coap_io_process() */
        result = (int)(end - begin);
      }
    } else {
      /*
       * epoll is not supported within libcoap
       *
       * result is time spent in coap_io_process()
       */
      result = coap_io_process(ctx, wait_ms);
    }
    if (result < 0) {
      break;
    } else if (result && (unsigned)result < wait_ms) {
      /* decrement if there is a result wait time returned */
      wait_ms -= result;
    } else {
      /*
       * result == 0, or result >= wait_ms
       * (wait_ms could have decremented to a small value, below
       * the granularity of the timer in coap_io_process() and hence
       * result == 0)
       */
      wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;
    }
    if (r_observe_1 || r_observe_2) {
      coap_time_t t_now;
      unsigned int next_sec_ms;

      coap_ticks(&now);
      t_now = coap_ticks_to_rt(now);
      if (t_last != t_now) {
        /* Happens once per second */
        t_last = t_now;
        if (r_observe_1)
          coap_resource_notify_observers(r_observe_1, NULL);
        if (r_observe_2)
          coap_resource_notify_observers(r_observe_2, NULL);
      }
      /* need to wait until next second starts if wait_ms is too large */
      next_sec_ms = 1000 - (now % COAP_TICKS_PER_SECOND) *
                    1000 / COAP_TICKS_PER_SECOND;
      if (next_sec_ms && next_sec_ms < wait_ms)
        wait_ms = next_sec_ms;
    }
  }

finish:

  if (oscore_seq_num_fp)
    fclose(oscore_seq_num_fp);

  coap_free_context(ctx);
  coap_cleanup();

  return 0;
}
