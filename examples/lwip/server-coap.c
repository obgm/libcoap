/*
 * server-coap.c -- LwIP example
 *
 * Copyright (C) 2013-2016 Christian Amsüss <chrysn@fsfe.org>
 * Copyright (C) 2018-2024 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#include "coap_config.h"

#if COAP_THREAD_SAFE
/*
 * Unfortunately, this needs to be set so that locking mapping of coap_
 * functions does not take place in this file.  coap.h includes coap_mem.h which
 * includes lwip headers (lwippools.h) which includes coap_internal.h which
 * includes coap_threadsafe_internal.h which does the mapping unless
 * COAP_THREAD_IGNORE_LOCKED_MAPPING is set.
 */
#define COAP_THREAD_IGNORE_LOCKED_MAPPING
#endif

#include <coap3/coap.h>
#include "server-coap.h"

coap_context_t *main_coap_context;

static coap_time_t clock_offset;
/* changeable clock base (see handle_put_time()) */
static coap_time_t my_clock_base = 0;
static coap_resource_t *time_resource = NULL; /* just for testing */

#ifndef min
# define min(a,b) ((a) < (b) ? (a) : (b))
#endif

void
hnd_get_time(coap_resource_t *resource, coap_session_t  *session,
             const coap_pdu_t *request, const coap_string_t *query,
             coap_pdu_t *response) {
  unsigned char buf[40];
  size_t len;
  coap_tick_t now;
  coap_tick_t t;

  (void)resource;
  (void)session;
  (void)request;
  /* FIXME: return time, e.g. in human-readable by default and ticks
   * when query ?ticks is given. */

  /* if my_clock_base was deleted, we pretend to have no such resource */
  coap_pdu_set_code(response, my_clock_base ? COAP_RESPONSE_CODE(205) : COAP_RESPONSE_CODE(404));

  if (my_clock_base)
    coap_add_option(response, COAP_OPTION_CONTENT_FORMAT,
                    coap_encode_var_safe(buf, sizeof(buf),
                                         COAP_MEDIATYPE_TEXT_PLAIN),
                    buf);

  coap_add_option(response, COAP_OPTION_MAXAGE,
                  coap_encode_var_safe(buf, sizeof(buf), 0x01), buf);

  if (my_clock_base) {

    /* calculate current time */
    coap_ticks(&t);
    now = my_clock_base + (t / COAP_TICKS_PER_SECOND);


    if (query != NULL
        && coap_string_equal(query, coap_make_str_const("ticks"))) {
      /* output ticks */
      len = snprintf((char *)buf, sizeof(buf), "%u", (unsigned int)now);
      coap_add_data(response, len, buf);
    }
  }
}

void
init_coap_resources(coap_context_t *ctx) {
  coap_resource_t *r;
#if 0
  r = coap_resource_init(NULL, 0, 0);
  coap_register_handler(r, COAP_REQUEST_GET, hnd_get_index);

  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("0"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"General Info\""), 0);
  coap_add_resource(ctx, r);
#endif
  /* store clock base to use in /time */
  my_clock_base = clock_offset;

  r = coap_resource_init(coap_make_str_const("time"), 0);
  if (!r)
    goto error;

  coap_resource_set_get_observable(r, 1);
  time_resource = r;
  coap_register_handler(r, COAP_REQUEST_GET, hnd_get_time);
#if 0
  coap_register_handler(r, COAP_REQUEST_PUT, hnd_put_time);
  coap_register_handler(r, COAP_REQUEST_DELETE, hnd_delete_time);
#endif
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("0"), 0);
  /* coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"Internal Clock\""), 0); */
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"ticks\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"clock\""), 0);

  coap_add_resource(ctx, r);
#if 0
  if (coap_async_is_supported()) {
    r = coap_resource_init(coap_make_str_const("async"), 0);
    coap_register_handler(r, COAP_REQUEST_GET, hnd_get_async);

    coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("0"), 0);
    coap_add_resource(ctx, r);
  }
#endif

  return;
error:
  coap_log_crit("cannot create resource\n");
}

void
server_coap_init(coap_lwip_input_wait_handler_t input_wait,
                 void *input_arg, int argc, char **argv) {
  int opt;
  coap_log_t log_level = COAP_LOG_WARN;
  coap_log_t dtls_log_level = COAP_LOG_ERR;
  const char *use_psk = "secretPSK";
  uint32_t scheme_hint_bits = 0;
  coap_addr_info_t *info = NULL;
  coap_addr_info_t *info_list = NULL;
  int have_ep = 0;
  coap_str_const_t node;

  /* Initialize libcoap library */
  coap_startup();

  while ((opt = getopt(argc, argv, ":k:v:V:")) != -1) {
    switch (opt) {
    case 'k':
      use_psk = optarg;
      break;
    case 'v':
      log_level = atoi(optarg);
      break;
    case 'V':
      dtls_log_level = atoi(optarg);
      break;
    default:
      printf("%s [-k PSK] [-v level] [ -V level]\n", argv[0]);
      exit(1);
    }
  }

  coap_startup();
  coap_set_log_level(log_level);
  coap_dtls_set_log_level(dtls_log_level);

  main_coap_context = coap_new_context(NULL);
  LWIP_ASSERT("Failed to initialize context", main_coap_context != NULL);

  if (coap_dtls_is_supported()) {
    coap_dtls_spsk_t setup_data;

    memset(&setup_data, 0, sizeof(setup_data));
    setup_data.version = COAP_DTLS_SPSK_SETUP_VERSION;
    setup_data.psk_info.key.s = (const uint8_t *)use_psk;
    setup_data.psk_info.key.length = strlen(use_psk);
    coap_context_set_psk2(main_coap_context, &setup_data);
  }

  node.s = (const uint8_t *)"::";
  node.length = 2;
  scheme_hint_bits =
      coap_get_available_scheme_hint_bits(use_psk[0],
                                          0, COAP_PROTO_NONE);
  info_list = coap_resolve_address_info(&node, 0, 0,
                                        0, 0,
                                        0,
                                        scheme_hint_bits,
                                        COAP_RESOLVE_TYPE_LOCAL);
  for (info = info_list; info != NULL; info = info->next) {
    coap_endpoint_t *ep;

    ep = coap_new_endpoint(main_coap_context, &info->addr, info->proto);
    if (!ep) {
      coap_log_warn("cannot create endpoint for proto %u\n",
                    info->proto);
    } else {
      have_ep = 1;
    }
  }
  coap_free_address_info(info_list);
  LWIP_ASSERT("Failed to initialize context", have_ep != 0);

  /* Limit the number of idle sessions to save RAM (MEMP_NUM_COAPSESSION) */
  LWIP_ASSERT("Need a minimum of 2 for MEMP_NUM_COAPSESSION", MEMP_NUM_COAPSESSION > 1);
  coap_context_set_max_idle_sessions(main_coap_context, MEMP_NUM_COAPSESSION -1);
  clock_offset = 1; /* Need a non-zero value */
  init_coap_resources(main_coap_context);
  coap_lwip_set_input_wait_handler(main_coap_context, input_wait, input_arg);
}

void
server_coap_finished(void) {
  coap_free_context(main_coap_context);
  main_coap_context = NULL;
  coap_cleanup();
}

void
server_coap_poll(void) {
  static coap_time_t last_time = 0;
  coap_tick_t ticks_now;
  coap_time_t time_now;

  coap_io_process(main_coap_context, 1000);
  coap_ticks(&ticks_now);
  time_now = coap_ticks_to_rt(ticks_now);

  if (last_time != time_now) {
    /* This takes place once a second */
    last_time = time_now;
    coap_resource_notify_observers(time_resource, NULL);
  }
  coap_check_notify(main_coap_context);
}
