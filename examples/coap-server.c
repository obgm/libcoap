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

static int resource_flags = COAP_RESOURCE_FLAGS_NOTIFY_CON;

static char *cert_file = NULL; /* Combined certificate and private key in PEM */
static char *ca_file = NULL;   /* CA for cert_file - for cert checking in PEM */
static char *root_ca_file = NULL; /* List of trusted Root CAs in PEM */
static int use_pem_buf = 0; /* Map these cert/key files into memory to test
                               PEM_BUF logic if set */
static uint8_t *cert_mem = NULL; /* certificate and private key in PEM_BUF */
static uint8_t *ca_mem = NULL;   /* CA for cert checking in PEM_BUF */
static size_t cert_mem_len = 0;
static size_t ca_mem_len = 0;
static int require_peer_cert = 1; /* By default require peer cert */
#define MAX_KEY   64 /* Maximum length of a pre-shared key in bytes. */
static uint8_t key[MAX_KEY];
static ssize_t key_length = 0;
int key_defined = 0;
static const char *hint = "CoAP";
static int support_dynamic = 0;

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

typedef struct dynamic_resource_t {
  coap_string_t *uri_path;
  coap_string_t *value;
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
           coap_pdu_t *request UNUSED_PARAM,
           coap_binary_t *token UNUSED_PARAM,
           coap_string_t *query UNUSED_PARAM,
           coap_pdu_t *response UNUSED_PARAM
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
      coap_delete_string(dynamic_entry[i].value);
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
  response->code = COAP_RESPONSE_CODE(202);
  return;
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
  coap_str_const_t value = { 0, NULL };
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
  return;
}

/*
 * Regular PUT handler - used by resources created by the
 * Unknown Resource PUT handler
 */

static void
hnd_put(coap_context_t *ctx UNUSED_PARAM,
        coap_resource_t *resource,
        coap_session_t *session UNUSED_PARAM,
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
    dynamic_entry = realloc (dynamic_entry, dynamic_count * sizeof(dynamic_entry[0]));
    if (dynamic_entry) {
      dynamic_entry[i].uri_path = uri_path;
      dynamic_entry[i].value = NULL;
      dynamic_entry[i].resource = resource;
      dynamic_entry[i].created = 1;
      response->code = COAP_RESPONSE_CODE(201);
      if ((option = coap_check_option(request, COAP_OPTION_CONTENT_TYPE, &opt_iter)) != NULL) {
        dynamic_entry[i].media_type =
            coap_decode_var_bytes (coap_opt_value (option), coap_opt_length (option));
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
      return;
    }
  } else {
    /* Need to do this as coap_get_uri_path() created it */
    coap_delete_string(uri_path);
    response->code = COAP_RESPONSE_CODE(204);
    dynamic_entry[i].created = 0;
    coap_resource_notify_observers(dynamic_entry[i].resource, NULL);
  }

  resource_entry = &dynamic_entry[i];

  if (coap_get_block(request, COAP_OPTION_BLOCK1, &block1)) {
    /* handle BLOCK1 */
    if (coap_get_data(request, &size, &data) && (size > 0)) {
      size_t offset = block1.num << (block1.szx + 4);
      coap_string_t *value = resource_entry->value;
      if (offset == 0) {
        if (value) {
          coap_delete_string(value);
          value = NULL;
        }
      }
      else if (offset >
            (resource_entry->value ? resource_entry->value->length : 0)) {
        /* Upload is not sequential - block missing */
        response->code = COAP_RESPONSE_CODE(408);
        return;
      }
      else if (offset <
            (resource_entry->value ? resource_entry->value->length : 0)) {
        /* Upload is not sequential - block duplicated */
        goto just_respond;
      }
      /* Add in new block to end of current data */
      resource_entry->value = coap_new_string(offset + size);
      memcpy (&resource_entry->value->s[offset], data, size);
      resource_entry->value->length = offset + size;
      if (value) {
        memcpy (resource_entry->value->s, value->s, value->length);
        coap_delete_string(value);
      }
    }
just_respond:
    if (block1.m) {
      response->code = COAP_RESPONSE_CODE(231);
    }
    else if (resource_entry->created) {
      response->code = COAP_RESPONSE_CODE(201);
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
      coap_delete_string(resource_entry->value);
      resource_entry->value = NULL;
    }
    resource_entry->value = coap_new_string(size);
    memcpy (resource_entry->value->s, data, size);
    resource_entry->value->length = size;
  }
  else {
    /* Not a BLOCK1 and no data */
    if (resource_entry->value) {
      coap_delete_string(resource_entry->value);
      resource_entry->value = NULL;
    }
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

  /* get the uri_path - will will get used by coap_resource_init() */
  uri_path = coap_get_uri_path(request);
  if (!uri_path) {
    response->code = COAP_RESPONSE_CODE(404);
    return;
  }

  if (dynamic_count >= support_dynamic) {
    response->code = COAP_RESPONSE_CODE(406);
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

  return;
}

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
  coap_log(LOG_INFO, "CN '%s' presented by client (%s)\n",
           cn, depth ? "CA" : "Certificate");
  return 1;
}

static uint8_t *read_file_mem(const char* file, size_t *length) {
  FILE *f = fopen(file, "r");
  uint8_t *buf;
  struct stat statbuf;

  *length = 0;
  if (!f)
    return NULL;

  if (fstat(fileno(f), &statbuf) == -1) {
    fclose(f);
    return NULL;
  }

  buf = malloc(statbuf.st_size+1);
  if (!buf)
    return NULL;

  if (fread(buf, 1, statbuf.st_size, f) != (size_t)statbuf.st_size) {
    fclose(f);
    free(buf);
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
    dtls_key.key_type = COAP_PKI_KEY_PEM;
    dtls_key.key.pem.public_cert = cert_file;
    dtls_key.key.pem.private_key = cert_file;
    dtls_key.key.pem.ca_file = ca_file;
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

static void
fill_keystore(coap_context_t *ctx) {
  if (cert_file == NULL && key_defined == 0) {
    if (coap_dtls_is_supported() || coap_tls_is_supported()) {
      coap_log(LOG_DEBUG,
               "(D)TLS not enabled as neither -k or -c options specified\n");
    }
  }
  if (cert_file) {
    coap_dtls_pki_t dtls_pki;
    memset (&dtls_pki, 0, sizeof(dtls_pki));
    dtls_pki.version = COAP_DTLS_PKI_SETUP_VERSION;
    if (ca_file) {
      /*
       * Add in additional certificate checking.
       * This list of enabled can be tuned for the specific
       * requirements - see 'man coap_encryption'.
       */
      dtls_pki.verify_peer_cert        = 1;
      dtls_pki.require_peer_cert       = require_peer_cert;
      dtls_pki.allow_self_signed       = 1;
      dtls_pki.allow_expired_certs     = 1;
      dtls_pki.cert_chain_validation   = 1;
      dtls_pki.cert_chain_verify_depth = 2;
      dtls_pki.check_cert_revocation   = 1;
      dtls_pki.allow_no_crl            = 1;
      dtls_pki.allow_expired_crl       = 1;
      dtls_pki.validate_cn_call_back   = verify_cn_callback;
      dtls_pki.cn_call_back_arg        = NULL;
      dtls_pki.validate_sni_call_back  = verify_pki_sni_callback;
      dtls_pki.sni_call_back_arg       = NULL;
    }
    if (!use_pem_buf) {
      dtls_pki.pki_key.key_type = COAP_PKI_KEY_PEM;
      dtls_pki.pki_key.key.pem.public_cert = cert_file;
      dtls_pki.pki_key.key.pem.private_key = cert_file;
      dtls_pki.pki_key.key.pem.ca_file = ca_file;
    }
    else {
      ca_mem = read_file_mem(ca_file, &ca_mem_len);
      cert_mem = read_file_mem(cert_file, &cert_mem_len);
      dtls_pki.pki_key.key_type = COAP_PKI_KEY_PEM_BUF;
      dtls_pki.pki_key.key.pem_buf.ca_cert = ca_mem;
      dtls_pki.pki_key.key.pem_buf.public_cert = cert_mem;
      dtls_pki.pki_key.key.pem_buf.private_key = cert_mem;
      dtls_pki.pki_key.key.pem_buf.ca_cert_len = ca_mem_len;
      dtls_pki.pki_key.key.pem_buf.public_cert_len = cert_mem_len;
      dtls_pki.pki_key.key.pem_buf.private_key_len = cert_mem_len;
    }

    /* If general root CAs are defined */
    if (root_ca_file) {
      struct stat stbuf;
      if ((stat(root_ca_file, &stbuf) == 0) && S_ISDIR(stbuf.st_mode)) {
        coap_context_set_pki_root_cas(ctx, NULL, root_ca_file);
      } else {
        coap_context_set_pki_root_cas(ctx, root_ca_file, NULL);
      }
    }
    coap_context_set_pki(ctx, &dtls_pki);
  }
  if (key_defined) {
    coap_dtls_spsk_t dtls_psk;
    memset (&dtls_psk, 0, sizeof(dtls_psk));
    dtls_psk.version = COAP_DTLS_SPSK_SETUP_VERSION;
    dtls_psk.validate_id_call_back = valid_ids.count ?
                                      verify_id_callback : NULL;
    dtls_psk.validate_sni_call_back = valid_psk_snis.count ?
                                       verify_psk_sni_callback : NULL;
    dtls_psk.psk_info.hint.s = (const uint8_t *)hint;
    dtls_psk.psk_info.hint.length = hint ? strlen(hint) : 0;
    dtls_psk.psk_info.key.s = key;
    dtls_psk.psk_info.key.length = key_length;
    coap_context_set_psk2(ctx, &dtls_psk);
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
     "\t\t[-A address] [-N]\n"
     "\t\t[[-h hint] [-i match_identity_file] [-k key]\n"
     "\t\t[-s match_psk_sni_file]]\n"
     "\t\t[[-c certfile] [-C cafile] [-m] [-n] [-R root_cafile]]\n"
     "\t\t[-S match_pki_sni_file]]\n"
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
     "\t-p port\t\tListen on specified port\n"
     "\t-v num \t\tVerbosity level (default 3, maximum is 9). Above 7,\n"
     "\t       \t\tthere is increased verbosity in GnuTLS and OpenSSL logging\n"
     "\t-A address\tInterface address to bind to\n"
     "\t-N     \t\tMake \"observe\" responses NON-confirmable. Even if set\n"
     "\t       \t\tevery fifth response will still be sent as a confirmable\n"
     "\t       \t\tresponse (RFC 7641 requirement)\n"
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
     "PKI Options (if supported by underlying (D)TLS library)\n"
     "\t-c certfile\tPEM file containing both CERTIFICATE and PRIVATE KEY\n"
     "\t       \t\tThis argument requires (D)TLS with PKI to be available\n"
     "\t-m     \t\tUse COAP_PKI_KEY_PEM_BUF instead of COAP_PKI_KEY_PEM i/f\n"
     "\t       \t\tby reading in the Cert / CA file (for testing)\n"
     "\t-n     \t\tDisable the requirement for clients to have defined\n"
     "\t       \t\tclient certificates\n"
     "\t-C cafile\tPEM file containing the CA Certificate that was used to\n"
     "\t       \t\tsign the certfile. If defined, then the client will be\n"
     "\t       \t\tgiven this CA Certificate during the TLS set up.\n"
     "\t       \t\tFurthermore, this will trigger the validation of the\n"
     "\t       \t\tclient certificate.  If certfile is self-signed (as\n"
     "\t       \t\tdefined by '-c certfile'), then you need to have on the\n"
     "\t       \t\tcommand line the same filename for both the certfile and\n"
     "\t       \t\tcafile (as in  '-c certfile -C certfile') to trigger\n"
     "\t       \t\tvalidation\n"
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
    , program, version, coap_string_tls_version(buffer, sizeof(buffer)),
    program);
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
  /* Need PSK set up before we set up (D)TLS endpoints */
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

    if (rp->ai_addrlen <= sizeof(addr.addr)) {
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

static ssize_t
cmdline_read_key(char *arg, unsigned char *buf, size_t maxlen) {
  size_t len = strnlen(arg, maxlen);
  if (len) {
    memcpy(buf, arg, len);
    return len;
  }
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
#ifndef _WIN32
  struct sigaction sa;
#endif

  clock_offset = time(NULL);

  while ((opt = getopt(argc, argv, "A:d:c:C:g:h:i:k:l:mnNp:R:s:S:v:")) != -1) {
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
    case 'k' :
      key_length = cmdline_read_key(optarg, key, MAX_KEY);
      if (key_length < 0) {
        coap_log( LOG_CRIT, "Invalid Pre-Shared Key specified\n" );
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

  if (ca_mem)
    free(ca_mem);
  if (cert_mem)
    free(cert_mem);
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

  coap_free_context(ctx);
  coap_cleanup();

  return 0;
}
