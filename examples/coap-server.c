/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/* coap -- simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in RFC 7252
 *
 * Copyright (C) 2010--2020 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
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
static char* strndup(const char* s1, size_t n)
{
  char* copy = (char*)malloc(n + 1);
  if (copy) {
    memcpy(copy, s1, n);
    copy[n] = 0;
  }
  return copy;
};
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

#ifndef SERVER_CAN_PROXY
#define SERVER_CAN_PROXY 1
#endif

/* Need to refresh time once per sec */
#define COAP_RESOURCE_CHECK_TIME 1

#include <coap2/coap.h>

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

/* temporary storage for dynamic resource representations */
static int quit = 0;

/* changeable clock base (see handle_put_time()) */
static time_t clock_offset;
static time_t my_clock_base = 0;

struct coap_resource_t *time_resource = NULL;

static coap_binary_t *example_data_ptr = NULL;
static int example_data_media_type = COAP_MEDIATYPE_TEXT_PLAIN;

static int resource_flags = COAP_RESOURCE_FLAGS_NOTIFY_CON;

/*
 * For PKI, if one or more of cert_file, key_file and ca_file is in PKCS11 URI
 * format, then the remainder of cert_file, key_file and ca_file are treated
 * as being in DER format to provide consistency across the underlying (D)TLS
 * libraries.
 */
static char *cert_file = NULL; /* certificate and optional private key in PEM,
                                  or PKCS11 URI*/
static char *key_file = NULL; /* private key in PEM, DER or PKCS11 URI */
static char *pkcs11_pin = NULL; /* PKCS11 pin to unlock access to token */
static char *ca_file = NULL;   /* CA for cert_file - for cert checking in PEM,
                                  DER or PKCS11 URI */
static char *root_ca_file = NULL; /* List of trusted Root CAs in PEM */
static int use_pem_buf = 0; /* Map these cert/key files into memory to test
                               PEM_BUF logic if set */
static int is_rpk_not_cert = 0; /* Cert is RPK if set */
static uint8_t *cert_mem = NULL; /* certificate and private key in PEM_BUF */
static uint8_t *key_mem = NULL; /* private key in PEM_BUF */
static uint8_t *ca_mem = NULL;   /* CA for cert checking in PEM_BUF */
static size_t cert_mem_len = 0;
static size_t key_mem_len = 0;
static size_t ca_mem_len = 0;
static int require_peer_cert = 1; /* By default require peer cert */
#define MAX_KEY   64 /* Maximum length of a pre-shared key in bytes. */
static uint8_t *key = NULL;
static ssize_t key_length = 0;
int key_defined = 0;
static const char *hint = "CoAP";
static int support_dynamic = 0;

static coap_dtls_pki_t *
setup_pki(coap_context_t *ctx, coap_dtls_role_t role, char *sni);

typedef struct psk_sni_def_t {
  char* sni_match;
  coap_bin_const_t *new_key;
  coap_bin_const_t *new_hint;
} psk_sni_def_t;

typedef struct valid_psk_snis_t {
  size_t count;
  psk_sni_def_t *psk_sni_list;
} valid_psk_snis_t;

static valid_psk_snis_t valid_psk_snis = {0, NULL};

typedef struct id_def_t {
  char *hint_match;
  coap_bin_const_t *identity_match;
  coap_bin_const_t *new_key;
} id_def_t;

typedef struct valid_ids_t {
  size_t count;
  id_def_t *id_list;
} valid_ids_t;

static valid_ids_t valid_ids = {0, NULL};
typedef struct pki_sni_def_t {
  char* sni_match;
  char *new_cert;
  char *new_ca;
} pki_sni_def_t;

typedef struct valid_pki_snis_t {
  size_t count;
  pki_sni_def_t *pki_sni_list;
} valid_pki_snis_t;

static valid_pki_snis_t valid_pki_snis = {0, NULL};

#ifndef WITHOUT_ASYNC
/* This variable is used to mimic long-running tasks that require
 * asynchronous responses. */
static coap_async_state_t *async = NULL;

/* A typedef for transfering a value in a void pointer */
typedef union {
  unsigned int val;
  void *ptr;
} async_data_t;
#endif /* WITHOUT_ASYNC */

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__ ((unused))
#else /* not a GCC */
#define UNUSED_PARAM
#endif /* GCC */

/* SIGINT handler: set quit to 1 for graceful termination */
static void
handle_sigint(int signum UNUSED_PARAM) {
  quit = 1;
}

#define INDEX "This is a test server made with libcoap (see https://libcoap.net)\n" \
              "Copyright (C) 2010--2020 Olaf Bergmann <bergmann@tzi.org> and others\n\n"

static void
hnd_get_index(coap_context_t *ctx UNUSED_PARAM,
              struct coap_resource_t *resource,
              coap_session_t *session,
              coap_pdu_t *request,
              coap_binary_t *token,
              coap_string_t *query UNUSED_PARAM,
              coap_pdu_t *response) {

  coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_TEXT_PLAIN, 0x2ffff,
                                 strlen(INDEX),
                                 (const uint8_t *)INDEX);
}

static void
hnd_get_time(coap_context_t  *ctx UNUSED_PARAM,
             struct coap_resource_t *resource,
             coap_session_t *session,
             coap_pdu_t *request,
             coap_binary_t *token,
             coap_string_t *query,
             coap_pdu_t *response) {
  unsigned char buf[40];
  size_t len;
  time_t now;
  coap_tick_t t;
  (void)request;

  /* FIXME: return time, e.g. in human-readable by default and ticks
   * when query ?ticks is given. */

  if (my_clock_base) {

    /* calculate current time */
    coap_ticks(&t);
    now = my_clock_base + (t / COAP_TICKS_PER_SECOND);

    if (query != NULL
        && coap_string_equal(query, coap_make_str_const("ticks"))) {
          /* output ticks */
          len = snprintf((char *)buf, sizeof(buf), "%u", (unsigned int)now);

    } else {      /* output human-readable time */
      struct tm *tmp;
      tmp = gmtime(&now);
      if (!tmp) {
        /* If 'now' is not valid */
        response->code = COAP_RESPONSE_CODE(404);
        return;
      }
      else {
        len = strftime((char *)buf, sizeof(buf), "%b %d %H:%M:%S", tmp);
      }
    }
    coap_add_data_blocked_response(resource, session, request, response, token,
                                   COAP_MEDIATYPE_TEXT_PLAIN, 1,
                                   len,
                                   buf);
  }
  else {
    /* if my_clock_base was deleted, we pretend to have no such resource */
    response->code = COAP_RESPONSE_CODE(404);
  }
}

static void
hnd_put_time(coap_context_t *ctx UNUSED_PARAM,
             struct coap_resource_t *resource,
             coap_session_t *session UNUSED_PARAM,
             coap_pdu_t *request,
             coap_binary_t *token UNUSED_PARAM,
             coap_string_t *query UNUSED_PARAM,
             coap_pdu_t *response) {
  coap_tick_t t;
  size_t size;
  unsigned char *data;

  /* FIXME: re-set my_clock_base to clock_offset if my_clock_base == 0
   * and request is empty. When not empty, set to value in request payload
   * (insist on query ?ticks). Return Created or Ok.
   */

  /* if my_clock_base was deleted, we pretend to have no such resource */
  response->code =
    my_clock_base ? COAP_RESPONSE_CODE(204) : COAP_RESPONSE_CODE(201);

  coap_resource_notify_observers(resource, NULL);

  /* coap_get_data() sets size to 0 on error */
  (void)coap_get_data(request, &size, &data);

  if (size == 0)        /* re-init */
    my_clock_base = clock_offset;
  else {
    my_clock_base = 0;
    coap_ticks(&t);
    while(size--)
      my_clock_base = my_clock_base * 10 + *data++;
    my_clock_base -= t / COAP_TICKS_PER_SECOND;

    /* Sanity check input value */
    if (!gmtime(&my_clock_base)) {
      unsigned char buf[3];
      response->code = COAP_RESPONSE_CODE(400);
      coap_add_option(response,
                      COAP_OPTION_CONTENT_FORMAT,
                      coap_encode_var_safe(buf, sizeof(buf),
                      COAP_MEDIATYPE_TEXT_PLAIN), buf);
      coap_add_data(response, 22, (const uint8_t*)"Invalid set time value");
      /* re-init as value is bad */
      my_clock_base = clock_offset;
    }
  }
}

static void
hnd_delete_time(coap_context_t *ctx UNUSED_PARAM,
                struct coap_resource_t *resource UNUSED_PARAM,
                coap_session_t *session UNUSED_PARAM,
                coap_pdu_t *request UNUSED_PARAM,
                coap_binary_t *token UNUSED_PARAM,
                coap_string_t *query UNUSED_PARAM,
                coap_pdu_t *response UNUSED_PARAM) {
  my_clock_base = 0;    /* mark clock as "deleted" */

  /* type = request->hdr->type == COAP_MESSAGE_CON  */
  /*   ? COAP_MESSAGE_ACK : COAP_MESSAGE_NON; */
}

#ifndef WITHOUT_ASYNC
static void
hnd_get_async(coap_context_t *ctx,
              struct coap_resource_t *resource UNUSED_PARAM,
              coap_session_t *session,
              coap_pdu_t *request,
              coap_binary_t *token UNUSED_PARAM,
              coap_string_t *query UNUSED_PARAM,
              coap_pdu_t *response) {
  unsigned long delay = 5;
  size_t size;

  if (async) {
    if (async->id != request->tid) {
      coap_opt_filter_t f;
      coap_option_filter_clear(f);
      response->code = COAP_RESPONSE_CODE(503);
    }
    return;
  }

  if (query) {
    const uint8_t *p = query->s;

    delay = 0;
    for (size = query->length; size; --size, ++p)
      delay = delay * 10 + (*p - '0');
  }

  /*
   * This is so we can use a local variable to hold the remaining time.
   * The alternative is to malloc the variable and set COAP_ASYNC_RELEASE_DATA
   * in the flags parameter in the call to coap_register_async() and handle
   * the required time as appropriate in check_async() below.
   */
  async_data_t data;
  data.val = COAP_TICKS_PER_SECOND * delay;
  async = coap_register_async(ctx,
                              session,
                              request,
                              COAP_ASYNC_SEPARATE | COAP_ASYNC_CONFIRM,
                              data.ptr);
}

static void
check_async(coap_context_t *ctx,
            coap_tick_t now) {
  coap_pdu_t *response;
  coap_async_state_t *tmp;
  async_data_t data;

  size_t size = 13;

  if (!async)
    return;

  data.ptr = async->appdata;
  if (now < async->created + data.val)
    return;

  response = coap_pdu_init(async->flags & COAP_ASYNC_CONFIRM
             ? COAP_MESSAGE_CON
             : COAP_MESSAGE_NON,
             COAP_RESPONSE_CODE(205), 0, size);
  if (!response) {
    coap_log(LOG_DEBUG, "check_async: insufficient memory, we'll try later\n");
    data.val = data.val + 15 * COAP_TICKS_PER_SECOND;
    async->appdata = data.ptr;
    return;
  }

  response->tid = coap_new_message_id(async->session);

  if (async->tokenlen)
    coap_add_token(response, async->tokenlen, async->token);

  coap_add_data(response, 4, (const uint8_t *)"done");

  if (coap_send(async->session, response) == COAP_INVALID_TID) {
    coap_log(LOG_DEBUG, "check_async: cannot send response for message\n");
  }
  coap_remove_async(ctx, async->session, async->id, &tmp);
  coap_free_async(async);
  async = NULL;
}
#endif /* WITHOUT_ASYNC */

/*
 * Large Data GET handler
 */

static void
hnd_get_example_data(coap_context_t *ctx UNUSED_PARAM,
        coap_resource_t *resource,
        coap_session_t *session,
        coap_pdu_t *request,
        coap_binary_t *token,
        coap_string_t *query UNUSED_PARAM,
        coap_pdu_t *response
) {
  if (!example_data_ptr) {
    /* Initialise for the first time */
    int i;
    example_data_ptr = coap_new_binary(1500);
    if (example_data_ptr) {
      example_data_ptr->length = 1500;
      for (i = 0; i < 1500; i++) {
        if ((i % 10) == 0) {
          example_data_ptr->s[i] = 'a' + (i/10) % 26;
        }
        else {
          example_data_ptr->s[i] = '0' + i%10;
        }
      }
    }
  }
  coap_add_data_blocked_response(resource, session, request, response, token,
                                 example_data_media_type, -1,
                                 example_data_ptr ? example_data_ptr->length : 0,
                                 example_data_ptr ? example_data_ptr->s : NULL);
}

static void
cache_free_app_data(void *data) {
  coap_binary_t *bdata = (coap_binary_t*)data;
  coap_delete_binary(bdata);
}

/*
 * Large Data PUT handler
 */

static void
hnd_put_example_data(coap_context_t *ctx UNUSED_PARAM,
        coap_resource_t *resource,
        coap_session_t *session,
        coap_pdu_t *request,
        coap_binary_t *token UNUSED_PARAM,
        coap_string_t *query UNUSED_PARAM,
        coap_pdu_t *response
) {
  size_t size;
  uint8_t *data;
  coap_block_t block1;
  unsigned char buf[6];      /* space to hold encoded/decoded uints */
  coap_opt_iterator_t opt_iter;
  coap_opt_t *option;

  if (coap_get_block(request, COAP_OPTION_BLOCK1, &block1)) {
    /* handle BLOCK1 */
    coap_cache_entry_t *cache_entry = coap_cache_get_by_pdu(session,
                                                            request,
                                                COAP_CACHE_IS_SESSION_BASED);
    size_t offset = block1.num << (block1.szx + 4);
    coap_binary_t *data_so_far;

    if (!cache_entry && block1.num == 0) {
      cache_entry = coap_new_cache_entry(session, request,
                                         COAP_CACHE_NOT_RECORD_PDU,
                                         COAP_CACHE_IS_SESSION_BASED, 0);
    }
    if (!cache_entry) {
      if (block1.num == 0) {
        coap_log(LOG_WARNING, "Unable to create a new cache entry\n");
      }
      else {
        coap_log(LOG_WARNING,
                 "No cache entry available for the non-first BLOCK1\n");
      }
      response->code = COAP_RESPONSE_CODE(500);
      return;
    }

    data_so_far = coap_cache_get_app_data(cache_entry);
    if (offset == 0) {
      if (data_so_far) {
        coap_delete_binary(data_so_far);
        data_so_far = NULL;
      }
    }
    else if (offset >
             (data_so_far ? data_so_far->length : 0)) {
      /* Upload is not sequential - block missing */
      response->code = COAP_RESPONSE_CODE(408);
      return;
    }
    else if (offset <
             (data_so_far ? data_so_far->length : 0)) {
      /* Upload is not sequential - block duplicated */
      goto just_respond;
    }

    if (coap_get_data(request, &size, &data) && (size > 0)) {
      if (!data_so_far) {
        data_so_far = coap_new_binary(size);
        if (data_so_far)
          memcpy(data_so_far->s, data, size);
      }
      else {
        /* Add in new block to end of current data */
        data_so_far = coap_resize_binary(data_so_far, offset + size);
        if (data_so_far)
          memcpy(&data_so_far->s[offset], data, size);
      }
    }
    else if (!block1.m && block1.num == 0) {
      /* Empty first and only block */
      if (data_so_far) {
        coap_delete_binary(example_data_ptr);
      }
      data_so_far = coap_new_binary(0);
    }

    if (!block1.m) {
      /* all the data in - now update the resource */
      coap_delete_binary(example_data_ptr);
      example_data_ptr = data_so_far;
      coap_cache_set_app_data(cache_entry, NULL, NULL);
      if ((option = coap_check_option(request, COAP_OPTION_CONTENT_FORMAT,
                                      &opt_iter)) != NULL) {
        example_data_media_type =
            coap_decode_var_bytes (coap_opt_value (option),
                                   coap_opt_length (option));
      }
      else {
        example_data_media_type = COAP_MEDIATYPE_TEXT_PLAIN;
      }
      coap_resource_notify_observers(resource, NULL);
    }
    else {
      /* save the updated data for the next block */
      coap_cache_set_app_data(cache_entry,data_so_far, cache_free_app_data);
    }

just_respond:
    if (block1.m) {
      response->code = COAP_RESPONSE_CODE(231);
    }
    else {
      response->code = COAP_RESPONSE_CODE(204);
    }
    coap_add_option(response,
                    COAP_OPTION_BLOCK1,
                    coap_encode_var_safe(buf, sizeof(buf),
                                         ((block1.num << 4) |
                                          (block1.m << 3) |
                                          block1.szx)),
                    buf);
  }
  else if (coap_get_data(request, &size, &data) && (size > 0)) {
    /* Not a BLOCK1 with data */
    if (example_data_ptr) {
      coap_delete_binary(example_data_ptr);
    }
    example_data_ptr = coap_new_binary(size);
    if (example_data_ptr)
      memcpy (example_data_ptr->s, data, size);
    if ((option = coap_check_option(request, COAP_OPTION_CONTENT_FORMAT,
                                    &opt_iter)) != NULL) {
      example_data_media_type = coap_decode_var_bytes (coap_opt_value (option),
                                                      coap_opt_length (option));
    }
    else {
      example_data_media_type = COAP_MEDIATYPE_TEXT_PLAIN;
    }
    response->code = COAP_RESPONSE_CODE(204);
    coap_resource_notify_observers(resource, NULL);
  }
  else {
    /* Not a BLOCK1 and no data */
    if (example_data_ptr) {
      coap_delete_binary(example_data_ptr);
    }
    example_data_ptr = coap_new_binary(0);
    response->code = COAP_RESPONSE_CODE(204);
  }
}

#if SERVER_CAN_PROXY
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
      len = ainfo->ai_addrlen;
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

#define MAX_USER 128 /* Maximum length of a user name (i.e., PSK
                      * identity) in bytes. */
static unsigned char *user = NULL;
static ssize_t user_length = -1;

static coap_uri_t proxy = { {0, NULL}, 0, {0, NULL}, {0, NULL}, 0 };
static size_t proxy_host_name_count = 0;
static const char **proxy_host_name_list = NULL;

typedef struct proxy_list_t {
  coap_session_t *ongoing;   /* Ongoing session */
  coap_session_t *incoming;  /* Incoming session */
  uint8_t token[8];          /* Incoming token in case of gateway issues */
  size_t token_length;
} proxy_list_t;

static proxy_list_t *proxy_list = NULL;
static size_t proxy_list_count = 0;

static int
get_uri_proxy_scheme_info(coap_pdu_t *request,
                          coap_opt_t *opt,
                          coap_uri_t *uri,
                          coap_string_t **uri_path,
                          coap_string_t **uri_query) {

  const char *opt_val = (const char*)coap_opt_value(opt);
  int opt_len = coap_opt_length(opt);
  coap_opt_iterator_t opt_iter;

  if (opt_len == 9 &&
      strncasecmp(opt_val, "coaps+tcp", 9) == 0) {
    uri->scheme = COAP_URI_SCHEME_COAPS_TCP;
    uri->port = COAPS_DEFAULT_PORT;
  }
  else if (opt_len == 8 &&
      strncasecmp(opt_val, "coap+tcp", 8) == 0) {
    uri->scheme = COAP_URI_SCHEME_COAP_TCP;
    uri->port = COAP_DEFAULT_PORT;
  }
  else if (opt_len == 5 &&
      strncasecmp(opt_val, "coaps", 5) == 0) {
    uri->scheme = COAP_URI_SCHEME_COAPS;
    uri->port = COAPS_DEFAULT_PORT;
  }
  else if (opt_len == 4 &&
      strncasecmp(opt_val, "coap", 4) == 0) {
    uri->scheme = COAP_URI_SCHEME_COAP;
    uri->port = COAP_DEFAULT_PORT;
  }
  else {
    coap_log(LOG_WARNING, "Unsupported Proxy Scheme '%*.*s'\n",
             opt_len, opt_len, opt_val);
    return 0;
  }

  opt = coap_check_option(request, COAP_OPTION_URI_HOST, &opt_iter);
  if (opt) {
    uri->host.length = coap_opt_length(opt);
    uri->host.s = coap_opt_value(opt);
  }
  else {
    coap_log(LOG_WARNING, "Proxy Scheme requires Uri-Host\n");
    return 0;
  }
  opt = coap_check_option(request, COAP_OPTION_URI_PORT, &opt_iter);
  if (opt) {
    uri->port =
          coap_decode_var_bytes (coap_opt_value (opt),
                                 coap_opt_length (opt));
  }
  *uri_path = coap_get_uri_path(request);
  if (*uri_path) {
    uri->path.s = (*uri_path)->s;
    uri->path.length = (*uri_path)->length;
  }
  *uri_query = coap_get_query(request);
  if (*uri_query) {
    uri->query.s = (*uri_query)->s;
    uri->query.length = (*uri_query)->length;
  }
  return 1;
}

static int
verify_proxy_scheme_supported(coap_uri_scheme_t scheme) {

  /* Sanity check that the connection can be forwarded on */
  switch (scheme) {
  case COAP_URI_SCHEME_HTTP:
  case COAP_URI_SCHEME_HTTPS:
  coap_log(LOG_WARNING, "Proxy URI http or https not supported\n");
    return 0;
  case COAP_URI_SCHEME_COAP:
    break;
  case COAP_URI_SCHEME_COAPS:
    if (!coap_dtls_is_supported()) {
      coap_log(LOG_WARNING,
        "coaps URI scheme not supported for proxy\n");
      return 0;
    }
    break;
  case COAP_URI_SCHEME_COAP_TCP:
    if (!coap_tcp_is_supported()) {
      coap_log(LOG_WARNING,
        "coap+tcp URI scheme not supported for proxy\n");
      return 0;
    }
    break;
  case COAP_URI_SCHEME_COAPS_TCP:
    if (!coap_tls_is_supported()) {
      coap_log(LOG_WARNING,
        "coaps+tcp URI scheme not supported for proxy\n");
      return 0;
    }
    break;
  default:
      coap_log(LOG_WARNING,
        "%d URI scheme not supported\n", scheme);
    break;
  }
  return 1;
}

static coap_dtls_cpsk_t *
setup_cpsk(char *client_sni) {
  static coap_dtls_cpsk_t dtls_cpsk;

  memset (&dtls_cpsk, 0, sizeof(dtls_cpsk));
  dtls_cpsk.version = COAP_DTLS_CPSK_SETUP_VERSION;
  dtls_cpsk.client_sni = client_sni;
  dtls_cpsk.psk_info.identity.s = user;
  dtls_cpsk.psk_info.identity.length = user_length;
  dtls_cpsk.psk_info.key.s = key;
  dtls_cpsk.psk_info.key.length = key_length;
  return &dtls_cpsk;
}

static coap_session_t *
get_ongoing_proxy_session(coap_session_t *session, coap_pdu_t *response,
                          coap_binary_t *token, coap_uri_t *uri) {

  coap_session_t *ongoing = NULL;
  size_t i;
  coap_address_t dst;
  coap_uri_scheme_t scheme;
  static char client_sni[256];
  coap_str_const_t server;
  uint16_t port = COAP_DEFAULT_PORT;
  proxy_list_t *new_proxy_list;

  /* Locate existing forwarding relationship */
  for (i = 0; i < proxy_list_count; i++) {
    if (proxy_list[i].incoming == session) {
      return proxy_list[i].ongoing;
    }
  }

  /* Need to create a new forwarding mapping */
  new_proxy_list = realloc(proxy_list, (i+1)*sizeof(proxy_list[0]));

  if (new_proxy_list == NULL) {
    response->code = COAP_RESPONSE_CODE(500);
    return NULL;
  }
  proxy_list = new_proxy_list;
  proxy_list[i].incoming = session;
  proxy_list[i].token_length = token ? token->length : 0;
  if (proxy_list[i].token_length)
    memcpy(proxy_list[i].token, token->s, proxy_list[i].token_length);
  coap_address_init(&dst);

  if (proxy.host.length) {
    server = proxy.host;
    port = proxy.port;
    scheme = proxy.scheme;
  } else {
    server = uri->host;
    port = uri->port;
    scheme = uri->scheme;
  }
  if (resolve_address(&server, &dst.addr.sa) < 0) {
    response->code = COAP_RESPONSE_CODE(502);
    return NULL;
  }
  switch (dst.addr.sa.sa_family) {
  case AF_INET:
    dst.addr.sin.sin_port = ntohs(port);
    break;
  case AF_INET6:
    dst.addr.sin6.sin6_port = ntohs(port);
    break;
  default:
    break;
  }
  switch (scheme) {
  case COAP_URI_SCHEME_COAP:
  case COAP_URI_SCHEME_COAP_TCP:
    ongoing = proxy_list[i].ongoing =
       coap_new_client_session(session->context, NULL, &dst,
                               scheme == COAP_URI_SCHEME_COAP ?
                                COAP_PROTO_UDP : COAP_PROTO_TCP);
    break;
  case COAP_URI_SCHEME_COAPS:
  case COAP_URI_SCHEME_COAPS_TCP:
    memset(client_sni, 0, sizeof(client_sni));
    if ((server.length == 3 && memcmp(server.s, "::1", 3) != 0) ||
        (server.length == 9 && memcmp(server.s, "127.0.0.1", 9) != 0))
      memcpy(client_sni, server.s, min(server.length, sizeof(client_sni)-1));
    else
      memcpy(client_sni, "localhost", 9);

    if (!key_defined) {
      /* Use our defined PKI certs (or NULL)  */
      coap_dtls_pki_t *dtls_pki = setup_pki(session->context,
                                            COAP_DTLS_ROLE_CLIENT, client_sni);
      ongoing = proxy_list[i].ongoing =
           coap_new_client_session_pki(session->context, NULL, &dst,
                 scheme == COAP_URI_SCHEME_COAPS ?
                  COAP_PROTO_DTLS : COAP_PROTO_TLS,
                 dtls_pki);
    }
    else {
      /* Use our defined PSK */
      coap_dtls_cpsk_t *dtls_cpsk = setup_cpsk(client_sni);

      ongoing = proxy_list[i].ongoing =
           coap_new_client_session_psk2(session->context, NULL, &dst,
                 scheme == COAP_URI_SCHEME_COAPS ?
                  COAP_PROTO_DTLS : COAP_PROTO_TLS,
                 dtls_cpsk);
    }
    break;
  case COAP_URI_SCHEME_HTTP:
  case COAP_URI_SCHEME_HTTPS:
  default:
    assert(0);
    break;
  }
  if (proxy_list[i].ongoing == NULL) {
    response->code = COAP_RESPONSE_CODE(505);
    return NULL;
  }
  proxy_list_count++;
  return ongoing;
}

static void
hnd_proxy_uri(coap_context_t *ctx UNUSED_PARAM,
                struct coap_resource_t *resource UNUSED_PARAM,
                coap_session_t *session,
                coap_pdu_t *request,
                coap_binary_t *token,
                coap_string_t *query UNUSED_PARAM,
                coap_pdu_t *response) {
  coap_opt_iterator_t opt_iter;
  coap_opt_t *opt;
  coap_opt_t *proxy_uri;
  int proxy_scheme_option = 0;
  coap_uri_t uri;
  coap_string_t *uri_path = NULL;
  coap_string_t *uri_query = NULL;
  coap_session_t *ongoing = NULL;
  size_t size;
  uint8_t *data;
  coap_pdu_t *pdu;
  coap_optlist_t *optlist = NULL;
  coap_opt_t *option;
  unsigned char portbuf[2];
#define BUFSIZE 100
  unsigned char _buf[BUFSIZE];
  unsigned char *buf = _buf;
  size_t buflen;
  int res;

  memset(&uri, 0, sizeof(uri));
  /*
   * See if Proxy-Scheme
   */
  opt = coap_check_option(request, COAP_OPTION_PROXY_SCHEME, &opt_iter);
  if (opt) {
    if (!get_uri_proxy_scheme_info(request, opt, &uri, &uri_path,
                                   &uri_query)) {
      response->code = COAP_RESPONSE_CODE(505);
      goto cleanup;
    }
    proxy_scheme_option = 1;
  }
  /*
   * See if Proxy-Uri
   */
  proxy_uri = coap_check_option(request, COAP_OPTION_PROXY_URI, &opt_iter);
  if (proxy_uri) {
    coap_log(LOG_INFO, "Proxy URI '%.*s'\n",
             coap_opt_length(proxy_uri),
             (const char*)coap_opt_value(proxy_uri));
    if (coap_split_proxy_uri(coap_opt_value(proxy_uri),
                             coap_opt_length(proxy_uri),
                             &uri) < 0) {
      /* Need to return a 5.05 RFC7252 Section 5.7.2 */
      coap_log(LOG_WARNING, "Proxy URI not decodable\n");
      response->code = COAP_RESPONSE_CODE(505);
      goto cleanup;
    }
  }

  if (!(proxy_scheme_option || proxy_uri)) {
    response->code = COAP_RESPONSE_CODE(404);
    goto cleanup;
  }

  if (uri.host.length == 0) {
    /* Ongoing connection not well formed */
    response->code = COAP_RESPONSE_CODE(505);
    goto cleanup;
  }

  if (!verify_proxy_scheme_supported(uri.scheme)) {
    response->code = COAP_RESPONSE_CODE(505);
    goto cleanup;
  }

  /* Handle the CoAP forwarding mapping */
  if (uri.scheme == COAP_URI_SCHEME_COAP ||
      uri.scheme == COAP_URI_SCHEME_COAPS ||
      uri.scheme == COAP_URI_SCHEME_COAP_TCP ||
      uri.scheme == COAP_URI_SCHEME_COAPS_TCP) {

    ongoing = get_ongoing_proxy_session(session, response, token, &uri);
    if (!ongoing)
      goto cleanup;

    /*
     * Build up the ongoing PDU that we are going to send
     */
    pdu = coap_pdu_init(request->type, request->code,
                        coap_new_message_id(ongoing),
                        coap_session_max_pdu_size(session));
    if (!pdu) {
      response->code = COAP_RESPONSE_CODE(500);
      goto cleanup;
    }

    if (token && !coap_add_token(pdu, token->length, token->s)) {
      coap_log(LOG_DEBUG, "cannot add token to proxy request\n");
      response->code = COAP_RESPONSE_CODE(500);
      goto cleanup;
    }

    if (proxy.host.length) {   /* Use Proxy-Uri */
      coap_insert_optlist(&optlist,
                  coap_new_optlist(COAP_OPTION_PROXY_URI,
                  coap_opt_length(proxy_uri),
                  coap_opt_value(proxy_uri)));

    }
    else {      /* Use  Uri-Path and Uri-Query */
      if (uri.port != (coap_uri_scheme_is_secure(&uri) ?
           COAPS_DEFAULT_PORT : COAP_DEFAULT_PORT)) {
        coap_insert_optlist(&optlist,
                    coap_new_optlist(COAP_OPTION_URI_PORT,
                             coap_encode_var_safe(portbuf, sizeof(portbuf),
                                                  (uri.port & 0xffff)),
                    portbuf));
      }

      if (uri.path.length) {
        buflen = BUFSIZE;
        if (uri.path.length > BUFSIZE)
          coap_log(LOG_WARNING,
                   "URI path will be truncated (max buffer %d)\n", BUFSIZE);
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

    /* Copy the remaining options across */
    coap_option_iterator_init(request, &opt_iter, COAP_OPT_ALL);
    while ((option = coap_option_next(&opt_iter))) {
      switch (opt_iter.type) {
      case COAP_OPTION_PROXY_URI:
      case COAP_OPTION_PROXY_SCHEME:
      case COAP_OPTION_URI_PATH:
      case COAP_OPTION_URI_PORT:
      case COAP_OPTION_URI_QUERY:
        /* Skip those potentially already added */
        break;
      default:
        coap_insert_optlist(&optlist,
                    coap_new_optlist(opt_iter.type,
                    coap_opt_length(option),
                    coap_opt_value(option)));
        break;
      }
    }

    /* Update pdu with options */
    coap_add_optlist_pdu(pdu, &optlist);
    coap_delete_optlist(optlist);

    if (coap_get_data(request, &size, &data) && (size > 0)) {
      if (!coap_add_data(pdu, size, data)) {
      coap_log(LOG_DEBUG, "cannot add data to proxy request\n");
      }
    }

    if (coap_get_log_level() < LOG_DEBUG)
      coap_show_pdu(LOG_INFO, pdu);

    coap_send(ongoing, pdu);
    goto cleanup;
  }
  else {
    /* TODO http & https */
    coap_log(LOG_ERR, "Proxy-Uri scheme %d unknown\n", uri.scheme);
  }
cleanup:
  if (uri_path) coap_delete_string(uri_path);
  if (uri_query) coap_delete_string(uri_query);
}

#endif /* SERVER_CAN_PROXY */

typedef struct dynamic_resource_t {
  coap_string_t *uri_path;
  coap_binary_t *value;
  coap_resource_t *resource;
  int created;
  uint16_t media_type;
} dynamic_resource_t;

static int dynamic_count = 0;
static dynamic_resource_t *dynamic_entry = NULL;

/*
 * Regular DELETE handler - used by resources created by the
 * Unknown Resource PUT handler
 */

static void
hnd_delete(coap_context_t *ctx,
           coap_resource_t *resource,
           coap_session_t *session UNUSED_PARAM,
           coap_pdu_t *request,
           coap_binary_t *token UNUSED_PARAM,
           coap_string_t *query UNUSED_PARAM,
           coap_pdu_t *response
) {
  int i;
  coap_string_t *uri_path;

  /* get the uri_path */
  uri_path = coap_get_uri_path(request);
  if (!uri_path) {
    response->code = COAP_RESPONSE_CODE(404);
    return;
  }

  for (i = 0; i < dynamic_count; i++) {
    if (coap_string_equal(uri_path, dynamic_entry[i].uri_path)) {
      /* Dynamic entry no longer required - delete it */
      coap_delete_binary(dynamic_entry[i].value);
      if (dynamic_count-i > 1) {
         memmove (&dynamic_entry[i],
                  &dynamic_entry[i+1],
                 (dynamic_count-i-1) * sizeof (dynamic_entry[0]));
      }
      dynamic_count--;
      break;
    }
  }

  /* Dynamic resource no longer required - delete it */
  coap_delete_resource(ctx, resource);
  coap_delete_string(uri_path);
  response->code = COAP_RESPONSE_CODE(202);
}

/*
 * Regular GET handler - used by resources created by the
 * Unknown Resource PUT handler
 */

static void
hnd_get(coap_context_t *ctx UNUSED_PARAM,
        coap_resource_t *resource,
        coap_session_t *session,
        coap_pdu_t *request,
        coap_binary_t *token,
        coap_string_t *query UNUSED_PARAM,
        coap_pdu_t *response
) {
  coap_str_const_t *uri_path;
  int i;
  dynamic_resource_t *resource_entry = NULL;
  coap_bin_const_t value = { 0, NULL };
  /*
   * request will be NULL if an Observe triggered request, so the uri_path,
   * if needed, must be abstracted from the resource.
   * The uri_path string is a const pointer
   */

  uri_path = coap_resource_get_uri_path(resource);
  if (!uri_path) {
    response->code = COAP_RESPONSE_CODE(404);
    return;
  }

  for (i = 0; i < dynamic_count; i++) {
    if (coap_string_equal(uri_path, dynamic_entry[i].uri_path)) {
      break;
    }
  }
  if (i == dynamic_count) {
    response->code = COAP_RESPONSE_CODE(404);
    return;
  }

  resource_entry = &dynamic_entry[i];

  if (resource_entry->value) {
    value.length = resource_entry->value->length;
    value.s = resource_entry->value->s;
  }
  coap_add_data_blocked_response(resource, session, request, response, token,
                                 resource_entry->media_type, -1,
                                 value.length,
                                 value.s);
}

/*
 * Regular PUT handler - used by resources created by the
 * Unknown Resource PUT handler
 */

static void
hnd_put(coap_context_t *ctx UNUSED_PARAM,
        coap_resource_t *resource,
        coap_session_t *session,
        coap_pdu_t *request,
        coap_binary_t *token UNUSED_PARAM,
        coap_string_t *query UNUSED_PARAM,
        coap_pdu_t *response
) {
  coap_string_t *uri_path;
  int i;
  size_t size;
  uint8_t *data;
  coap_block_t block1;
  dynamic_resource_t *resource_entry = NULL;
  unsigned char buf[6];      /* space to hold encoded/decoded uints */
  coap_opt_iterator_t opt_iter;
  coap_opt_t *option;

  /* get the uri_path */
  uri_path = coap_get_uri_path(request);
  if (!uri_path) {
    response->code = COAP_RESPONSE_CODE(404);
    return;
  }

  /*
   * Locate the correct dynamic block for this request
   */
  for (i = 0; i < dynamic_count; i++) {
    if (coap_string_equal(uri_path, dynamic_entry[i].uri_path)) {
      break;
    }
  }
  if (i == dynamic_count) {
    if (dynamic_count >= support_dynamic) {
      /* Should have been caught in hnd_unknown_put() */
      response->code = COAP_RESPONSE_CODE(406);
      coap_delete_string(uri_path);
      return;
    }
    dynamic_count++;
    dynamic_entry = realloc (dynamic_entry,
                             dynamic_count * sizeof(dynamic_entry[0]));
    if (dynamic_entry) {
      dynamic_entry[i].uri_path = uri_path;
      dynamic_entry[i].value = NULL;
      dynamic_entry[i].resource = resource;
      dynamic_entry[i].created = 1;
      response->code = COAP_RESPONSE_CODE(201);
      if ((option = coap_check_option(request, COAP_OPTION_CONTENT_FORMAT,
                                      &opt_iter)) != NULL) {
        dynamic_entry[i].media_type =
            coap_decode_var_bytes (coap_opt_value (option),
                                   coap_opt_length (option));
      }
      else {
        dynamic_entry[i].media_type = COAP_MEDIATYPE_TEXT_PLAIN;
      }
      /* Store media type of new resource in ct. We can use buf here
       * as coap_add_attr() will copy the passed string. */
      memset(buf, 0, sizeof(buf));
      snprintf((char *)buf, sizeof(buf), "%d", dynamic_entry[i].media_type);
      /* ensure that buf is always zero-terminated */
      assert(buf[sizeof(buf) - 1] == '\0');
      buf[sizeof(buf) - 1] = '\0';
      coap_add_attr(resource,
                    coap_make_str_const("ct"),
                    coap_make_str_const((char*)buf),
                    0);
    } else {
      dynamic_count--;
      response->code = COAP_RESPONSE_CODE(500);
      coap_delete_string(uri_path);
      return;
    }
  } else {
    /* Need to do this as coap_get_uri_path() created it */
    coap_delete_string(uri_path);
    response->code = COAP_RESPONSE_CODE(204);
  }

  resource_entry = &dynamic_entry[i];

  if (coap_get_block(request, COAP_OPTION_BLOCK1, &block1)) {
    /* handle BLOCK1 */
    coap_cache_entry_t *cache_entry = coap_cache_get_by_pdu(session,
                                                            request,
                                                 COAP_CACHE_IS_SESSION_BASED);
    size_t offset = block1.num << (block1.szx + 4);
    coap_binary_t *data_so_far;

    if (!cache_entry && block1.num == 0) {
      cache_entry = coap_new_cache_entry(session, request,
                                         COAP_CACHE_NOT_RECORD_PDU,
                                         COAP_CACHE_IS_SESSION_BASED, 0);
    }
    if (!cache_entry) {
      if ( block1.num == 0) {
        coap_log(LOG_WARNING, "Unable to create a new cache entry\n");
      }
      else {
        coap_log(LOG_WARNING,
                 "No cache entry available for the non-first BLOCK1\n");
      }
      response->code = COAP_RESPONSE_CODE(500);
      return;
    }

    data_so_far = coap_cache_get_app_data(cache_entry);
    if (offset == 0) {
      if (data_so_far) {
        coap_delete_binary(data_so_far);
        data_so_far = NULL;
      }
    }
    else if (offset >
          (data_so_far ? data_so_far->length : 0)) {
      /* Upload is not sequential - block missing */
      response->code = COAP_RESPONSE_CODE(408);
      return;
    }
    else if (offset <
          (data_so_far ? data_so_far->length : 0)) {
      /* Upload is not sequential - block duplicated */
      goto just_respond;
    }

    if (coap_get_data(request, &size, &data) && (size > 0)) {
      if (!data_so_far) {
        data_so_far = coap_new_binary(size);
        if (data_so_far)
          memcpy(data_so_far->s, data, size);
      }
      else {
        /* Add in new block to end of current data */
        data_so_far = coap_resize_binary(data_so_far, offset + size);
        if (data_so_far)
          memcpy(&data_so_far->s[offset], data, size);
      }
    }

    if (!block1.m) {
      /* all the data in - now update the resource */
      coap_delete_binary(resource_entry->value);
      resource_entry->value = data_so_far;
      coap_cache_set_app_data(cache_entry, NULL, NULL);
      coap_resource_notify_observers(resource_entry->resource, NULL);
    }
    else {
      /* save the updated data for the next block */
      coap_cache_set_app_data(cache_entry, data_so_far, cache_free_app_data);
    }

just_respond:
    if (block1.m) {
      response->code = COAP_RESPONSE_CODE(231);
    }
    else if (resource_entry->created) {
      response->code = COAP_RESPONSE_CODE(201);
      resource_entry->created = 0;
    }
    else {
      response->code = COAP_RESPONSE_CODE(204);
    }
    coap_add_option(response,
                    COAP_OPTION_BLOCK1,
                    coap_encode_var_safe(buf, sizeof(buf),
                                         ((block1.num << 4) |
                                          (block1.m << 3) |
                                          block1.szx)),
                    buf);
  }
  else if (coap_get_data(request, &size, &data) && (size > 0)) {
    /* Not a BLOCK1 with data */
    if (resource_entry->value) {
      coap_delete_binary(resource_entry->value);
    }
    resource_entry->value = coap_new_binary(size);
    if (resource_entry->value)
      memcpy (resource_entry->value->s, data, size);
    if ((option = coap_check_option(request, COAP_OPTION_CONTENT_FORMAT,
                                    &opt_iter)) != NULL) {
      resource_entry->media_type = coap_decode_var_bytes (coap_opt_value (option),
                                                      coap_opt_length (option));
    }
    else {
      resource_entry->media_type = COAP_MEDIATYPE_TEXT_PLAIN;
    }
    coap_resource_notify_observers(resource_entry->resource, NULL);
    resource_entry->created = 0;
  }
  else {
    /* Not a BLOCK1 and no data */
    if (resource_entry->value) {
      coap_delete_binary(resource_entry->value);
      resource_entry->value = NULL;
    }
    resource_entry->created = 0;
  }
}

/*
 * Unknown Resource PUT handler
 */

static void
hnd_unknown_put(coap_context_t *ctx,
                coap_resource_t *resource UNUSED_PARAM,
                coap_session_t *session,
                coap_pdu_t *request,
                coap_binary_t *token,
                coap_string_t *query,
                coap_pdu_t *response
) {
  coap_resource_t *r;
  coap_string_t *uri_path;

  /* check if creating a new resource is allowed */
  if (dynamic_count >= support_dynamic) {
    response->code = COAP_RESPONSE_CODE(406);
    return;
  }

  /* get the uri_path - will get used by coap_resource_init() */
  uri_path = coap_get_uri_path(request);
  if (!uri_path) {
    response->code = COAP_RESPONSE_CODE(404);
    return;
  }

  /*
   * Create a resource to handle the new URI
   * uri_path will get deleted when the resource is removed
   */
  r = coap_resource_init((coap_str_const_t*)uri_path,
        COAP_RESOURCE_FLAGS_RELEASE_URI | resource_flags);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"Dynamic\""), 0);
  coap_register_handler(r, COAP_REQUEST_PUT, hnd_put);
  coap_register_handler(r, COAP_REQUEST_DELETE, hnd_delete);
  /* We possibly want to Observe the GETs */
  coap_resource_set_get_observable(r, 1);
  coap_register_handler(r, COAP_REQUEST_GET, hnd_get);
  coap_add_resource(ctx, r);

  /* Do the PUT for this first call */
  hnd_put(ctx, r, session, request, token, query, response);
}

#if SERVER_CAN_PROXY

static void
remove_proxy_association(coap_session_t *session, int send_failure) {

  size_t i;

  for (i = 0; i < proxy_list_count; i++) {
    if (proxy_list[i].incoming == session) {
      coap_session_release(proxy_list[i].ongoing);
      break;
    }
    if (proxy_list[i].ongoing == session && send_failure) {
      coap_pdu_t *response;

      coap_session_release(proxy_list[i].ongoing);

      /* Need to send back a gateway failure */
      response = coap_pdu_init(COAP_MESSAGE_NON,
                               COAP_RESPONSE_CODE(502),
                               coap_new_message_id(proxy_list[i].incoming),
                          coap_session_max_pdu_size(proxy_list[i].incoming));
      if (!response) {
        coap_log(LOG_INFO, "PDU creation issue\n");
        return;
      }

      if (proxy_list[i].token_length &&
          !coap_add_token(response, proxy_list[i].token_length,
                          proxy_list[i].token)) {
        coap_log(LOG_DEBUG,
                       "Cannot add token to incoming proxy response PDU\n");
      }

      if (coap_send(proxy_list[i].incoming, response) == COAP_INVALID_TID) {
        coap_log(LOG_INFO, "Failed to send PDU with 5.02 gateway issue\n");
      }
      break;
    }
  }
  if (i != proxy_list_count) {
    if (proxy_list_count-i > 1) {
       memmove (&proxy_list[i],
                &proxy_list[i+1],
               (proxy_list_count-i-1) * sizeof (proxy_list[0]));
    }
    proxy_list_count--;
  }
}

static int
event_handler(coap_context_t *ctx UNUSED_PARAM,
              coap_event_t event,
              struct coap_session_t *session) {

  switch(event) {
  case COAP_EVENT_DTLS_CLOSED:
  case COAP_EVENT_TCP_CLOSED:
  case COAP_EVENT_SESSION_CLOSED:
    /* Need to remove any proxy associations */
    remove_proxy_association(session, 0);
    break;
  default:
    break;
  }
  return 0;
}

static void
message_handler(struct coap_context_t *ctx UNUSED_PARAM,
                coap_session_t *session,
                coap_pdu_t *sent UNUSED_PARAM,
                coap_pdu_t *received,
                const coap_tid_t id UNUSED_PARAM) {

  coap_pdu_t *pdu = NULL;
  coap_session_t *incoming = NULL;
  size_t i;
  size_t size;
  uint8_t *data;
  coap_optlist_t *optlist = NULL;
  coap_opt_t *option;
  coap_opt_iterator_t opt_iter;

  for (i = 0; i < proxy_list_count; i++) {
    if (proxy_list[i].ongoing == session) {
      incoming = proxy_list[i].incoming;
      break;
    }
  }
  if (i == proxy_list_count) {
    coap_log(LOG_DEBUG, "Unknown proxy ongoing session response received\n");
    return;
  }

  coap_log(LOG_DEBUG, "** process incoming %d.%02d response:\n",
           COAP_RESPONSE_CLASS(received->code), received->code & 0x1F);
  if (coap_get_log_level() < LOG_DEBUG)
    coap_show_pdu(LOG_INFO, received);

  /*
   * Build up the ongoing PDU that we are going to send to proxy originator
   */
  pdu = coap_pdu_init(received->type, received->code,
                      coap_new_message_id(incoming),
                      coap_session_max_pdu_size(incoming));
  if (!pdu) {
    coap_log(LOG_DEBUG, "Failed to create ongoing proxy response PDU\n");
    return;
  }

  if (!coap_add_token(pdu, received->token_length, received->token)) {
    coap_log(LOG_DEBUG, "cannot add token to ongoing proxy response PDU\n");
  }

  /* Copy the remaining options across */
  coap_option_iterator_init(received, &opt_iter, COAP_OPT_ALL);
  while ((option = coap_option_next(&opt_iter))) {
    switch (opt_iter.type) {
    /* In case any options need to be dropped in the future */
    default:
      coap_insert_optlist(&optlist,
                  coap_new_optlist(opt_iter.type,
                  coap_opt_length(option),
                  coap_opt_value(option)));
      break;
    }
  }
  coap_add_optlist_pdu(pdu, &optlist);
  coap_delete_optlist(optlist);

  if (coap_get_data(received, &size, &data) && (size > 0)) {
    if (!coap_add_data(pdu, size, data)) {
      coap_log(LOG_DEBUG, "cannot add data to proxy response\n");
    }
  }

  if (coap_get_log_level() < LOG_DEBUG)
    coap_show_pdu(LOG_INFO, pdu);

  coap_send(incoming, pdu);
  return;
}

static void
nack_handler(coap_context_t *context UNUSED_PARAM,
             coap_session_t *session,
             coap_pdu_t *sent UNUSED_PARAM,
             coap_nack_reason_t reason,
             const coap_tid_t id UNUSED_PARAM) {

  switch(reason) {
  case COAP_NACK_TOO_MANY_RETRIES:
  case COAP_NACK_NOT_DELIVERABLE:
  case COAP_NACK_RST:
  case COAP_NACK_TLS_FAILED:
    /* Need to remove any proxy associations */
    remove_proxy_association(session, 1);
    break;
  case COAP_NACK_ICMP_ISSUE:
  default:
    break;
  }
  return;
}

#endif /* SERVER_CAN_PROXY */

static void
init_resources(coap_context_t *ctx) {
  coap_resource_t *r;

  r = coap_resource_init(NULL, 0);
  coap_register_handler(r, COAP_REQUEST_GET, hnd_get_index);

  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("0"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"General Info\""), 0);
  coap_add_resource(ctx, r);

  /* store clock base to use in /time */
  my_clock_base = clock_offset;

  r = coap_resource_init(coap_make_str_const("time"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_GET, hnd_get_time);
  coap_register_handler(r, COAP_REQUEST_PUT, hnd_put_time);
  coap_register_handler(r, COAP_REQUEST_DELETE, hnd_delete_time);
  coap_resource_set_get_observable(r, 1);

  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("0"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"Internal Clock\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"ticks\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"clock\""), 0);

  coap_add_resource(ctx, r);
  time_resource = r;

  if (support_dynamic > 0) {
    /* Create a resource to handle PUTs to unknown URIs */
    r = coap_resource_unknown_init(hnd_unknown_put);
    coap_add_resource(ctx, r);
  }
#ifndef WITHOUT_ASYNC
  r = coap_resource_init(coap_make_str_const("async"), 0);
  coap_register_handler(r, COAP_REQUEST_GET, hnd_get_async);

  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("0"), 0);
  coap_add_resource(ctx, r);
#endif /* WITHOUT_ASYNC */
  r = coap_resource_init(coap_make_str_const("example_data"), 0);
  coap_register_handler(r, COAP_REQUEST_GET, hnd_get_example_data);
  coap_register_handler(r, COAP_REQUEST_PUT, hnd_put_example_data);
  coap_resource_set_get_observable(r, 1);

  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("0"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"Example Data\""), 0);
  coap_add_resource(ctx, r);

#ifdef SERVER_CAN_PROXY
  if (proxy_host_name_count) {
    r = coap_resource_proxy_uri_init(hnd_proxy_uri, proxy_host_name_count,
                                     proxy_host_name_list);
    coap_add_resource(ctx, r);
    coap_register_event_handler(ctx, event_handler);
    coap_register_response_handler(ctx, message_handler);
    coap_register_nack_handler(ctx, nack_handler);
  }
#endif /* SERVER_CAN_PROXY */
}

static int
verify_cn_callback(const char *cn,
                   const uint8_t *asn1_public_cert UNUSED_PARAM,
                   size_t asn1_length UNUSED_PARAM,
                   coap_session_t *session UNUSED_PARAM,
                   unsigned depth,
                   int validated UNUSED_PARAM,
                   void *arg
) {
  coap_dtls_role_t role = (coap_dtls_role_t)arg;

  coap_log(LOG_INFO, "CN '%s' presented by %s (%s)\n",
           cn, role == COAP_DTLS_ROLE_SERVER ? "client" : "server",
           depth ? "CA" : "Certificate");
  return 1;
}

static uint8_t *read_file_mem(const char* file, size_t *length) {
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

static coap_dtls_key_t *
verify_pki_sni_callback(const char *sni,
                    void *arg UNUSED_PARAM
) {
  static coap_dtls_key_t dtls_key;

  /* Preset with the defined keys */
  memset (&dtls_key, 0, sizeof(dtls_key));
  if (!use_pem_buf) {
    if ((key_file && strncasecmp (key_file, "pkcs11:", 7) == 0) ||
        (cert_file && strncasecmp (cert_file, "pkcs11:", 7) == 0) ||
        (ca_file && strncasecmp (ca_file, "pkcs11:", 7) == 0)) {
      dtls_key.key_type = COAP_PKI_KEY_PKCS11;
      dtls_key.key.pkcs11.public_cert = cert_file;
      dtls_key.key.pkcs11.private_key = key_file ? key_file : cert_file;
      dtls_key.key.pkcs11.ca = ca_file;
      dtls_key.key.pkcs11.user_pin = pkcs11_pin;
    }
    else {
      dtls_key.key_type = COAP_PKI_KEY_PEM;
      dtls_key.key.pem.public_cert = cert_file;
      dtls_key.key.pem.private_key = key_file ? key_file : cert_file;
      dtls_key.key.pem.ca_file = ca_file;
    }
  }
  else {
    dtls_key.key_type = COAP_PKI_KEY_PEM_BUF;
    dtls_key.key.pem_buf.ca_cert = ca_mem;
    dtls_key.key.pem_buf.public_cert = cert_mem;
    dtls_key.key.pem_buf.private_key = cert_mem;
    dtls_key.key.pem_buf.ca_cert_len = ca_mem_len;
    dtls_key.key.pem_buf.public_cert_len = cert_mem_len;
    dtls_key.key.pem_buf.private_key_len = cert_mem_len;
  }
  if (sni[0]) {
    size_t i;
    coap_log(LOG_INFO, "SNI '%s' requested\n", sni);
    for (i = 0; i < valid_pki_snis.count; i++) {
      /* Test for SNI to change cert + ca */
      if (strcasecmp(sni, valid_pki_snis.pki_sni_list[i].sni_match) == 0) {
        coap_log(LOG_INFO, "Switching to using cert '%s' + ca '%s'\n",
                 valid_pki_snis.pki_sni_list[i].new_cert,
                 valid_pki_snis.pki_sni_list[i].new_ca);
        dtls_key.key_type = COAP_PKI_KEY_PEM;
        dtls_key.key.pem.public_cert = valid_pki_snis.pki_sni_list[i].new_cert;
        dtls_key.key.pem.private_key = valid_pki_snis.pki_sni_list[i].new_cert;
        dtls_key.key.pem.ca_file = valid_pki_snis.pki_sni_list[i].new_ca;
        break;
      }
    }
  }
  else {
    coap_log(LOG_DEBUG, "SNI not requested\n");
  }
  return &dtls_key;
}

static const coap_dtls_spsk_info_t *
verify_psk_sni_callback(const char *sni,
                    coap_session_t *c_session UNUSED_PARAM,
                    void *arg UNUSED_PARAM
) {
  static coap_dtls_spsk_info_t psk_info;

  /* Preset with the defined keys */
  memset (&psk_info, 0, sizeof(psk_info));
  psk_info.hint.s = (const uint8_t *)hint;
  psk_info.hint.length = hint ? strlen(hint) : 0;
  psk_info.key.s = key;
  psk_info.key.length = key_length;
  if (sni) {
    size_t i;
    coap_log(LOG_INFO, "SNI '%s' requested\n", sni);
    for (i = 0; i < valid_psk_snis.count; i++) {
      /* Test for identity match to change key */
      if (strcasecmp(sni,
                 valid_psk_snis.psk_sni_list[i].sni_match) == 0) {
        coap_log(LOG_INFO, "Switching to using '%.*s' hint + '%.*s' key\n",
                 (int)valid_psk_snis.psk_sni_list[i].new_hint->length,
                 valid_psk_snis.psk_sni_list[i].new_hint->s,
                 (int)valid_psk_snis.psk_sni_list[i].new_key->length,
                 valid_psk_snis.psk_sni_list[i].new_key->s);
        psk_info.hint = *valid_psk_snis.psk_sni_list[i].new_hint;
        psk_info.key = *valid_psk_snis.psk_sni_list[i].new_key;
        break;
      }
    }
  }
  else {
    coap_log(LOG_DEBUG, "SNI not requested\n");
  }
  return &psk_info;
}

static const coap_bin_const_t *
verify_id_callback(coap_bin_const_t *identity,
                   coap_session_t *c_session,
                   void *arg UNUSED_PARAM
) {
  static coap_bin_const_t psk_key;
  size_t i;

  coap_log(LOG_INFO, "Identity '%.*s' requested, current hint '%.*s'\n", (int)identity->length,
           identity->s,
           c_session->psk_hint ? (int)c_session->psk_hint->length : 0,
           c_session->psk_hint ? (const char *)c_session->psk_hint->s : "");

  for (i = 0; i < valid_ids.count; i++) {
    /* Check for hint match */
    if (c_session->psk_hint &&
        strcmp((const char *)c_session->psk_hint->s,
               valid_ids.id_list[i].hint_match)) {
      continue;
    }
    /* Test for identity match to change key */
    if (coap_binary_equal(identity, valid_ids.id_list[i].identity_match)) {
      coap_log(LOG_INFO, "Switching to using '%.*s' key\n",
               (int)valid_ids.id_list[i].new_key->length,
               valid_ids.id_list[i].new_key->s);
      return valid_ids.id_list[i].new_key;
    }
  }

  if (c_session->psk_key) {
    /* Been updated by SNI callback */
    psk_key = *c_session->psk_key;
    return &psk_key;
  }

  /* Just use the defined keys for now */
  psk_key.s = key;
  psk_key.length = key_length;
  return &psk_key;
}

static coap_dtls_pki_t *
setup_pki(coap_context_t *ctx, coap_dtls_role_t role, char *client_sni) {
  static coap_dtls_pki_t dtls_pki;

  /* If general root CAs are defined */
  if (role == COAP_DTLS_ROLE_SERVER && root_ca_file) {
    struct stat stbuf;
    if ((stat(root_ca_file, &stbuf) == 0) && S_ISDIR(stbuf.st_mode)) {
      coap_context_set_pki_root_cas(ctx, NULL, root_ca_file);
    } else {
      coap_context_set_pki_root_cas(ctx, root_ca_file, NULL);
    }
  }

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
    dtls_pki.allow_self_signed       = 1;
    dtls_pki.allow_expired_certs     = 1;
    dtls_pki.cert_chain_validation   = 1;
    dtls_pki.cert_chain_verify_depth = 2;
    dtls_pki.check_cert_revocation   = 1;
    dtls_pki.allow_no_crl            = 1;
    dtls_pki.allow_expired_crl       = 1;
    dtls_pki.validate_cn_call_back   = verify_cn_callback;
    dtls_pki.cn_call_back_arg        = (void*)role;
    dtls_pki.validate_sni_call_back  = role == COAP_DTLS_ROLE_SERVER ?
                                       verify_pki_sni_callback : NULL;
    dtls_pki.sni_call_back_arg       = NULL;
  }
  dtls_pki.require_peer_cert = require_peer_cert;
  dtls_pki.is_rpk_not_cert   = is_rpk_not_cert;

  if (role == COAP_DTLS_ROLE_CLIENT) {
    dtls_pki.client_sni = client_sni;
  }

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
  else if (!use_pem_buf && !is_rpk_not_cert) {
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

static coap_dtls_spsk_t *
setup_spsk(void) {
  static coap_dtls_spsk_t dtls_spsk;

  memset (&dtls_spsk, 0, sizeof(dtls_spsk));
  dtls_spsk.version = COAP_DTLS_SPSK_SETUP_VERSION;
  dtls_spsk.validate_id_call_back = valid_ids.count ?
                                    verify_id_callback : NULL;
  dtls_spsk.validate_sni_call_back = valid_psk_snis.count ?
                                     verify_psk_sni_callback : NULL;
  dtls_spsk.psk_info.hint.s = (const uint8_t *)hint;
  dtls_spsk.psk_info.hint.length = hint ? strlen(hint) : 0;
  dtls_spsk.psk_info.key.s = key;
  dtls_spsk.psk_info.key.length = key_length;
  return &dtls_spsk;
}

static void
fill_keystore(coap_context_t *ctx) {

  if (cert_file == NULL && key_defined == 0) {
    if (coap_dtls_is_supported() || coap_tls_is_supported()) {
      coap_log(LOG_DEBUG,
               "(D)TLS not enabled as neither -k or -c options specified\n");
    }
    return;
  }
  if (cert_file) {
    coap_dtls_pki_t *dtls_pki = setup_pki(ctx,
                                          COAP_DTLS_ROLE_SERVER, NULL);
    if (!coap_context_set_pki(ctx, dtls_pki)) {
      coap_log(LOG_INFO, "Unable to set up %s keys\n",
               is_rpk_not_cert ? "RPK" : "PKI");
      /* So we do not set up DTLS */
      cert_file = NULL;
    }
  }
  if (key_defined) {
    coap_dtls_spsk_t *dtls_spsk = setup_spsk();

    coap_context_set_psk2(ctx, dtls_spsk);
  }
}

static void
usage( const char *program, const char *version) {
  const char *p;
  char buffer[64];

  p = strrchr( program, '/' );
  if ( p )
    program = ++p;

  fprintf( stderr, "%s v%s -- a small CoAP implementation\n"
     "(c) 2010,2011,2015-2020 Olaf Bergmann <bergmann@tzi.org> and others\n\n"
     "%s\n\n"
     "Usage: %s [-d max] [-g group] [-l loss] [-p port] [-v num]\n"
     "\t\t[-A address] [-N] [-P scheme://address[:port],name1[,name2..]]\n"
     "\t\t[[-h hint] [-i match_identity_file] [-k key]\n"
     "\t\t[-s match_psk_sni_file] [-u user]]\n"
     "\t\t[[-c certfile] [-j keyfile] [-m] [-n] [-C cafile] [-J pkcs11_pin]\n"
     "\t\t[-M rpk_file] [-R root_cafile] [-S match_pki_sni_file]]\n"
     "General Options\n"
     "\t-d max \t\tAllow dynamic creation of up to a total of max\n"
     "\t       \t\tresources. If max is reached, a 4.06 code is returned\n"
     "\t       \t\tuntil one of the dynamic resources has been deleted\n"
     "\t-g group\tJoin the given multicast group\n"
     "\t-l list\t\tFail to send some datagrams specified by a comma\n"
     "\t       \t\tseparated list of numbers or number ranges\n"
     "\t       \t\t(for debugging only)\n"
     "\t-l loss%%\tRandomly fail to send datagrams with the specified\n"
     "\t       \t\tprobability - 100%% all datagrams, 0%% no datagrams\n"
     "\t       \t\t(for debugging only)\n"
     "\t-p port\t\tListen on specified port for UDP and TCP. If (D)TLS is\n"
     "\t       \t\tenabled, then the coap-server will also listen on\n"
     "\t       \t\t 'port'+1 for DTLS and TLS.  The default port is 5683\n"
     "\t-v num \t\tVerbosity level (default 3, maximum is 9). Above 7,\n"
     "\t       \t\tthere is increased verbosity in GnuTLS and OpenSSL logging\n"
     "\t-A address\tInterface address to bind to\n"
     "\t-N     \t\tMake \"observe\" responses NON-confirmable. Even if set\n"
     "\t       \t\tevery fifth response will still be sent as a confirmable\n"
     "\t       \t\tresponse (RFC 7641 requirement)\n"
    , program, version, coap_string_tls_version(buffer, sizeof(buffer)),
    program);
  fprintf( stderr,
     "\t-P scheme://address[:port],name1[,name2[,name3..]]\tScheme, address,\n"
     "\t       \t\toptional port of how to connect to the next proxy server\n"
     "\t       \t\tand one or more names (comma separated) that this proxy\n"
     "\t       \t\tserver is known by. If the hostname of the incoming proxy\n"
     "\t       \t\trequest matches one of these names, then this server is\n"
     "\t       \t\tconsidered to be the final endpoint. If\n"
     "\t       \t\tscheme://address[:port] is not defined before the leading\n"
     "\t       \t\t, (comma) of the first name, then the ongoing connection\n"
     "\t       \t\twill be a direct connection.\n"
     "\t       \t\tScheme is one of coap, coaps, coap+tcp and coaps+tcp\n"
     "PSK Options (if supported by underlying (D)TLS library)\n"
     "\t-h hint\t\tIdentity Hint. Default is CoAP. Zero length is no hint\n"
     "\t-i match_identity_file\n"
     "\t       \t\tThis option denotes a file that contains one or more lines\n"
     "\t       \t\tof client Hints and (user) Identities to match for a new\n"
     "\t       \t\tPre-Shared Key (PSK) (comma separated) to be used. E.g.,\n"
     "\t       \t\tper line\n"
     "\t       \t\t hint_to_match,identity_to_match,new_key\n"
     "\t       \t\tNote: -k still needs to be defined for the default case\n"
     "\t-k key \t\tPre-Shared Key. This argument requires (D)TLS with PSK\n"
     "\t       \t\tto be available. This cannot be empty if defined.\n"
     "\t       \t\tNote that both -c and -k need to be defined\n"
     "\t       \t\tfor both PSK and PKI to be concurrently supported\n"
     "\t-s match_psk_sni_file\n"
     "\t       \t\tThis is a file that contains one or more lines of Subject\n"
     "\t       \t\tName Identifiers (SNI) to match for new Identity Hint and\n"
     "\t       \t\tnew Pre-Shared Key (PSK) (comma separated) to be used.\n"
     "\t       \t\tE.g., per line\n"
     "\t       \t\t sni_to_match,new_hint,new_key\n"
     "\t       \t\tNote: -k still needs to be defined for the default case\n"
     "\t       \t\tNote: the new Pre-Shared Key will get updated if there is\n"
     "\t       \t\talso a -i match\n"
     "\t-u user\t\tUser identity for pre-shared key mode (only used if option P\n"
     "\t       \t\t is set)\n"
     );
  fprintf(stderr,
     "PKI Options (if supported by underlying (D)TLS library)\n"
     "\tNote: If any one of '-c certfile', '-j keyfile' or '-C cafile' is in\n"
     "\tPKCS11 URI naming format (pkcs11: prefix), then any remaining non\n"
     "\tPKCS11 URI file definitions have to be in DER, not PEM, format.\n"
     "\tOtherwise all of '-c certfile', '-j keyfile' or '-C cafile' are in\n"
     "\tPEM format.\n\n"
     "\t-c certfile\tPEM file or PKCS11 URI for the certificate. The private\n"
     "\t       \t\tkey can be in the PEM file, or use the same PKCS11 URI.\n"
     "\t       \t\tIf not, the private key is defined by '-j keyfile'\n"
     "\t       \t\tNote that both -c and -k need to be defined\n"
     "\t       \t\tfor both PSK and PKI to be concurrently supported\n"
     "\t-j keyfile\tPEM file or PKCS11 URI for the private key for the\n"
     "\t       \t\tcertificate in '-c certfile' if the parameter is different\n"
     "\t       \t\tfrom certfile in '-c certfile'\n"
     "\t-m     \t\tUse COAP_PKI_KEY_PEM_BUF instead of COAP_PKI_KEY_PEM i/f\n"
     "\t       \t\tby reading into memory the Cert / CA file (for testing)\n"
     "\t-n     \t\tDisable the requirement for clients to have defined\n"
     "\t       \t\tclient certificates\n"
     "\t-C cafile\tPEM file or PKCS11 URI for the CA certificate that was\n"
     "\t       \t\tused to sign the certfile. If defined, then the client\n"
     "\t       \t\twill be given this CA certificate during the TLS set up.\n"
     "\t       \t\tFurthermore, this will trigger the validation of the\n"
     "\t       \t\tclient certificate.  If certfile is self-signed (as\n"
     "\t       \t\tdefined by '-c certfile'), then you need to have on the\n"
     "\t       \t\tcommand line the same filename for both the certfile and\n"
     "\t       \t\tcafile (as in  '-c certfile -C certfile') to trigger\n"
     "\t       \t\tvalidation\n"
     "\t-J pkcs11_pin\tThe user pin to unlock access to the PKCS11 token\n"
     "\t-M rpk_file\tRaw Public Key (RPK) PEM file that contains both\n"
     "\t       \t\tPUBLIC KEY and PRIVATE KEY or just EC PRIVATE KEY.\n"
     "\t       \t\t(GnuTLS and TinyDTLS support only) '-C cafile' not required\n"
     "\t-R root_cafile\tPEM file containing the set of trusted root CAs that\n"
     "\t       \t\tare to be used to validate the client certificate.\n"
     "\t       \t\tThe '-C cafile' does not have to be in this list and is\n"
     "\t       \t\t'trusted' for the verification.\n"
     "\t       \t\tAlternatively, this can point to a directory containing\n"
     "\t       \t\ta set of CA PEM files\n"
     "\t-S match_pki_sni_file\n"
     "\t       \t\tThis option denotes a file that contains one or more lines\n"
     "\t       \t\tof Subject Name Identifier (SNI) to match for new Cert\n"
     "\t       \t\tfile and new CA file (comma separated) to be used.\n"
     "\t       \t\tE.g., per line\n"
     "\t       \t\t sni_to_match,new_cert_file,new_ca_file\n"
     "\t       \t\tNote: -c and -C still needs to be defined for the default case\n"
    );
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
  /* Need PKI/RPK/PSK set up before we set up (D)TLS endpoints */
  fill_keystore(ctx);

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
  hints.ai_socktype = SOCK_DGRAM; /* Coap uses UDP */
  hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

  s = getaddrinfo(node, port, &hints, &result);
  if ( s != 0 ) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
    coap_free_context(ctx);
    return NULL;
  }

  /* iterate through results until success */
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    coap_address_t addr, addrs;
    coap_endpoint_t *ep_udp = NULL, *ep_dtls = NULL;

    if (rp->ai_addrlen <= (socklen_t)sizeof(addr.addr)) {
      coap_address_init(&addr);
      addr.size = (socklen_t)rp->ai_addrlen;
      memcpy(&addr.addr, rp->ai_addr, rp->ai_addrlen);
      addrs = addr;
      if (addr.addr.sa.sa_family == AF_INET) {
        uint16_t temp = ntohs(addr.addr.sin.sin_port) + 1;
        addrs.addr.sin.sin_port = htons(temp);
      } else if (addr.addr.sa.sa_family == AF_INET6) {
        uint16_t temp = ntohs(addr.addr.sin6.sin6_port) + 1;
        addrs.addr.sin6.sin6_port = htons(temp);
      } else {
        goto finish;
      }

      ep_udp = coap_new_endpoint(ctx, &addr, COAP_PROTO_UDP);
      if (ep_udp) {
        if (coap_dtls_is_supported() && (key_defined || cert_file)) {
          ep_dtls = coap_new_endpoint(ctx, &addrs, COAP_PROTO_DTLS);
          if (!ep_dtls)
            coap_log(LOG_CRIT, "cannot create DTLS endpoint\n");
        }
      } else {
        coap_log(LOG_CRIT, "cannot create UDP endpoint\n");
        continue;
      }
      if (coap_tcp_is_supported()) {
        coap_endpoint_t *ep_tcp;
        ep_tcp = coap_new_endpoint(ctx, &addr, COAP_PROTO_TCP);
        if (ep_tcp) {
          if (coap_tls_is_supported() && (key_defined || cert_file)) {
            coap_endpoint_t *ep_tls;
            ep_tls = coap_new_endpoint(ctx, &addrs, COAP_PROTO_TLS);
            if (!ep_tls)
              coap_log(LOG_CRIT, "cannot create TLS endpoint\n");
          }
        } else {
          coap_log(LOG_CRIT, "cannot create TCP endpoint\n");
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

#if SERVER_CAN_PROXY
static int
cmdline_proxy(char *arg) {
  char *host_start = strchr(arg, ',');
  char *next_name = host_start;
  size_t ofs;

  if (!host_start) {
    coap_log(LOG_WARNING, "One or more proxy host names not defined\n");
    return 0;
  }
  *host_start = '\000';

  if (host_start != arg) {
    /* Next upstream proxy is defined */
    if (coap_split_uri((unsigned char *)arg, strlen(arg), &proxy) < 0 ||
        proxy.path.length != 0 || proxy.query.length != 0) {
      coap_log(LOG_ERR, "invalid CoAP Proxy definition\n");
      return 0;
    }
  }
  proxy_host_name_count = 0;
  while (next_name) {
    proxy_host_name_count++;
    next_name = strchr(next_name+1, ',');
  }
  proxy_host_name_list = coap_malloc(proxy_host_name_count * sizeof(char*));
  next_name = host_start;
  ofs = 0;
  while (next_name) {
    proxy_host_name_list[ofs++] = next_name+1;
    next_name = strchr(next_name+1, ',');
    if (next_name)
      *next_name = '\000';
  }
  return 1;
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
#endif /* SERVER_CAN_PROXY */

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

static int cmdline_read_psk_sni_check(char *arg) {
  FILE *fp = fopen(arg, "r");
  static char tmpbuf[256];
  if (fp == NULL) {
    coap_log(LOG_ERR, "SNI file: %s: Unable to open\n", arg);
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
      psk_sni_def_t *new_psk_sni_list;
      new_psk_sni_list = realloc(valid_psk_snis.psk_sni_list,
              (valid_psk_snis.count + 1)*sizeof (valid_psk_snis.psk_sni_list[0]));
      if (new_psk_sni_list == NULL) {
        break;
      }
      valid_psk_snis.psk_sni_list = new_psk_sni_list;
      valid_psk_snis.psk_sni_list[valid_psk_snis.count].sni_match = strndup(cp, tcp-cp);
      cp = tcp+1;
      tcp = strchr(cp, ',');
      if (tcp) {
        valid_psk_snis.psk_sni_list[valid_psk_snis.count].new_hint =
                             coap_new_bin_const((const uint8_t *)cp, tcp-cp);
        cp = tcp+1;
        valid_psk_snis.psk_sni_list[valid_psk_snis.count].new_key =
                             coap_new_bin_const((const uint8_t *)cp, strlen(cp));
        valid_psk_snis.count++;
      }
      else {
        free(valid_psk_snis.psk_sni_list[valid_psk_snis.count].sni_match);
      }
    }
  }
  fclose(fp);
  return valid_psk_snis.count > 0;
}

static int cmdline_read_identity_check(char *arg) {
  FILE *fp = fopen(arg, "r");
  static char tmpbuf[256];
  if (fp == NULL) {
    coap_log(LOG_ERR, "Identity file: %s: Unable to open\n", arg);
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
      id_def_t *new_id_list;
      new_id_list = realloc(valid_ids.id_list,
                          (valid_ids.count + 1)*sizeof (valid_ids.id_list[0]));
      if (new_id_list == NULL) {
        break;
      }
      valid_ids.id_list = new_id_list;
      valid_ids.id_list[valid_ids.count].hint_match = strndup(cp, tcp-cp);
      cp = tcp+1;
      tcp = strchr(cp, ',');
      if (tcp) {
        valid_ids.id_list[valid_ids.count].identity_match =
                               coap_new_bin_const((const uint8_t *)cp, tcp-cp);
        cp = tcp+1;
        valid_ids.id_list[valid_ids.count].new_key =
                           coap_new_bin_const((const uint8_t *)cp, strlen(cp));
        valid_ids.count++;
      }
      else {
        free(valid_ids.id_list[valid_ids.count].hint_match);
      }
    }
  }
  fclose(fp);
  return valid_ids.count > 0;
}

static int cmdline_read_pki_sni_check(char *arg) {
  FILE *fp = fopen(arg, "r");
  static char tmpbuf[256];
  if (fp == NULL) {
    coap_log(LOG_ERR, "SNI file: %s: Unable to open\n", arg);
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
      pki_sni_def_t *new_pki_sni_list;
      new_pki_sni_list = realloc(valid_pki_snis.pki_sni_list,
            (valid_pki_snis.count + 1)*sizeof (valid_pki_snis.pki_sni_list[0]));
      if (new_pki_sni_list == NULL) {
        break;
      }
      valid_pki_snis.pki_sni_list = new_pki_sni_list;
      valid_pki_snis.pki_sni_list[valid_pki_snis.count].sni_match =
                                                           strndup(cp, tcp-cp);
      cp = tcp+1;
      tcp = strchr(cp, ',');
      if (tcp) {
        int fail = 0;
        valid_pki_snis.pki_sni_list[valid_pki_snis.count].new_cert =
                             strndup(cp, tcp-cp);
        cp = tcp+1;
        valid_pki_snis.pki_sni_list[valid_pki_snis.count].new_ca =
                             strndup(cp, strlen(cp));
        if (access(valid_pki_snis.pki_sni_list[valid_pki_snis.count].new_cert,
            R_OK)) {
          coap_log(LOG_ERR, "SNI file: Cert File: %s: Unable to access\n",
                   valid_pki_snis.pki_sni_list[valid_pki_snis.count].new_cert);
          fail = 1;
        }
        if (access(valid_pki_snis.pki_sni_list[valid_pki_snis.count].new_ca,
            R_OK)) {
          coap_log(LOG_ERR, "SNI file: CA File: %s: Unable to access\n",
                   valid_pki_snis.pki_sni_list[valid_pki_snis.count].new_ca);
          fail = 1;
        }
        if (fail) {
          free(valid_pki_snis.pki_sni_list[valid_pki_snis.count].sni_match);
          free(valid_pki_snis.pki_sni_list[valid_pki_snis.count].new_cert);
          free(valid_pki_snis.pki_sni_list[valid_pki_snis.count].new_ca);
        }
        else {
          valid_pki_snis.count++;
        }
      }
      else {
        coap_log(LOG_ERR,
                "SNI file: SNI_match,Use_Cert_file,Use_CA_file not defined\n");
        free(valid_pki_snis.pki_sni_list[valid_pki_snis.count].sni_match);
      }
    }
  }
  fclose(fp);
  return valid_pki_snis.count > 0;
}

int
main(int argc, char **argv) {
  coap_context_t  *ctx;
  char *group = NULL;
  coap_tick_t now;
  char addr_str[NI_MAXHOST] = "::";
  char port_str[NI_MAXSERV] = "5683";
  int opt;
  coap_log_t log_level = LOG_WARNING;
  unsigned wait_ms;
  coap_time_t t_last = 0;
  int coap_fd;
  fd_set m_readfds;
  int nfds = 0;
  size_t i;
  uint16_t cache_ignore_options[] = { COAP_OPTION_BLOCK1,
                                      COAP_OPTION_BLOCK2,
                    /* See https://tools.ietf.org/html/rfc7959#section-2.10 */
                                      COAP_OPTION_MAXAGE,
                    /* See https://tools.ietf.org/html/rfc7959#section-2.10 */
                                      COAP_OPTION_IF_NONE_MATCH };
#ifndef _WIN32
  struct sigaction sa;
#endif

  clock_offset = time(NULL);

  while ((opt = getopt(argc, argv, "c:d:g:h:i:j:J:k:l:mnp:s:u:v:A:C:M:NP:R:S:")) != -1) {
    switch (opt) {
    case 'A' :
      strncpy(addr_str, optarg, NI_MAXHOST-1);
      addr_str[NI_MAXHOST - 1] = '\0';
      break;
    case 'c' :
      cert_file = optarg;
      break;
    case 'C' :
      ca_file = optarg;
      break;
    case 'd' :
      support_dynamic = atoi(optarg);
      break;
    case 'g' :
      group = optarg;
      break;
    case 'h' :
      if (!optarg[0]) {
        hint = NULL;
        break;
      }
      hint = optarg;
      break;
    case 'i':
      if (!cmdline_read_identity_check(optarg)) {
        usage(argv[0], LIBCOAP_PACKAGE_VERSION);
        exit(1);
      }
      break;
    case 'j' :
      key_file = optarg;
      break;
    case 'J' :
      pkcs11_pin = optarg;
      break;
    case 'k' :
      key_length = cmdline_read_key(optarg, &key, MAX_KEY);
      if (key_length < 0) {
        break;
      }
      key_defined = 1;
      break;
    case 'l':
      if (!coap_debug_set_packet_loss(optarg)) {
        usage(argv[0], LIBCOAP_PACKAGE_VERSION);
        exit(1);
      }
      break;
    case 'm':
      use_pem_buf = 1;
      break;
    case 'M':
      cert_file = optarg;
      is_rpk_not_cert = 1;
      break;
    case 'n':
      require_peer_cert = 0;
      break;
    case 'N':
      resource_flags = COAP_RESOURCE_FLAGS_NOTIFY_NON;
      break;
    case 'p' :
      strncpy(port_str, optarg, NI_MAXSERV-1);
      port_str[NI_MAXSERV - 1] = '\0';
      break;
#if SERVER_CAN_PROXY
    case 'P':
      if (!cmdline_proxy(optarg)) {
        fprintf(stderr, "error specifying proxy address or host names\n");
        exit(-1);
      }
      break;
#endif /* SERVER_CAN_PROXY */
    case 'R' :
      root_ca_file = optarg;
      break;
    case 's':
      if (!cmdline_read_psk_sni_check(optarg)) {
        usage(argv[0], LIBCOAP_PACKAGE_VERSION);
        exit(1);
      }
      break;
    case 'S':
      if (!cmdline_read_pki_sni_check(optarg)) {
        usage(argv[0], LIBCOAP_PACKAGE_VERSION);
        exit(1);
      }
      break;
#if SERVER_CAN_PROXY
    case 'u':
      user_length = cmdline_read_user(optarg, &user, MAX_USER);
      break;
#endif /* SERVER_CAN_PROXY */
    case 'v' :
      log_level = strtol(optarg, NULL, 10);
      break;
    default:
      usage( argv[0], LIBCOAP_PACKAGE_VERSION );
      exit( 1 );
    }
  }

  coap_startup();
  coap_dtls_set_log_level(log_level);
  coap_set_log_level(log_level);

  ctx = get_context(addr_str, port_str);
  if (!ctx)
    return -1;

  init_resources(ctx);

  /* Define the options to ignore when setting up cache-keys */
  coap_cache_ignore_options(ctx, cache_ignore_options,
             sizeof(cache_ignore_options)/sizeof(cache_ignore_options[0]));
  /* join multicast group if requested at command line */
  if (group)
    coap_join_mcast_group(ctx, group);

  coap_fd = coap_context_get_coap_fd(ctx);
  if (coap_fd != -1) {
    /* if coap_fd is -1, then epoll is not supported within libcoap */
    FD_ZERO(&m_readfds);
    FD_SET(coap_fd, &m_readfds);
    nfds = coap_fd + 1;
  }

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

  wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;

  while ( !quit ) {
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
      result = select (nfds, &readfds, NULL, NULL, &tv);
      if (result == -1) {
        if (errno != EAGAIN) {
          coap_log(LOG_DEBUG, "select: %s (%d)\n", coap_socket_strerror(), errno);
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
    }
    else {
      /*
       * epoll is not supported within libcoap
       *
       * result is time spent in coap_io_process()
       */
      result = coap_io_process( ctx, wait_ms );
    }
    if ( result < 0 ) {
      break;
    } else if ( result && (unsigned)result < wait_ms ) {
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
    if (time_resource) {
      coap_time_t t_now;
      unsigned int next_sec_ms;

      coap_ticks(&now);
      t_now = coap_ticks_to_rt(now);
      if (t_last != t_now) {
        /* Happens once per second */
        t_last = t_now;
        coap_resource_notify_observers(time_resource, NULL);
      }
      /* need to wait until next second starts if wait_ms is too large */
      next_sec_ms = 1000 - (now % COAP_TICKS_PER_SECOND) *
                           1000 / COAP_TICKS_PER_SECOND;
      if (next_sec_ms && next_sec_ms < wait_ms)
        wait_ms = next_sec_ms;
    }

#ifndef WITHOUT_ASYNC
    /* check if we have to send asynchronous responses */
    coap_ticks( &now );
    check_async(ctx, now);
#endif /* WITHOUT_ASYNC */
  }

  coap_free(ca_mem);
  coap_free(cert_mem);
  coap_free(key_mem);
  for (i = 0; i < valid_psk_snis.count; i++) {
    free(valid_psk_snis.psk_sni_list[i].sni_match);
    coap_delete_bin_const(valid_psk_snis.psk_sni_list[i].new_hint);
    coap_delete_bin_const(valid_psk_snis.psk_sni_list[i].new_key);
  }
  if (valid_psk_snis.count)
    free(valid_psk_snis.psk_sni_list);

  for (i = 0; i < valid_ids.count; i++) {
    free(valid_ids.id_list[i].hint_match);
    coap_delete_bin_const(valid_ids.id_list[i].identity_match);
    coap_delete_bin_const(valid_ids.id_list[i].new_key);
  }
  if (valid_ids.count)
    free(valid_ids.id_list);

  for (i = 0; i < valid_pki_snis.count; i++) {
    free(valid_pki_snis.pki_sni_list[i].sni_match);
    free(valid_pki_snis.pki_sni_list[i].new_cert);
    free(valid_pki_snis.pki_sni_list[i].new_ca);
  }
  if (valid_pki_snis.count)
    free(valid_pki_snis.pki_sni_list);

  for (i = 0; i < (size_t)dynamic_count; i++) {
    coap_delete_string(dynamic_entry[i].uri_path);
    coap_delete_binary(dynamic_entry[i].value);
  }
  if (dynamic_entry) free(dynamic_entry);
  if (example_data_ptr) coap_delete_binary(example_data_ptr);
#if SERVER_CAN_PROXY
  free(proxy_list);
  proxy_list = NULL;
  proxy_list_count = 0;
  if (proxy_host_name_list)
    coap_free(proxy_host_name_list);
#endif /* SERVER_CAN_PROXY */

  coap_free_context(ctx);
  coap_cleanup();

  return 0;
}
