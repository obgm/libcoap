/* coap-server.c -- Example CoAP server using Contiki and libcoap
 *
 * Copyright (C) 2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

#include "contiki-net.h"
#include "coap3/coap.h"

static coap_context_t *coap_context;

static clock_time_t clock_offset;
/* changeable clock base (see handle_put_time()) */
static clock_time_t my_clock_base = 0;
static coap_resource_t *time_resource = NULL; /* just for testing */

PROCESS(coap_server_process, "CoAP server process");
AUTOSTART_PROCESSES(&coap_server_process);
/*---------------------------------------------------------------------------*/
void
init_coap_server(coap_context_t **ctx) {
  uip_ds6_addr_t *my_address;
  coap_address_t listen_addr;

  assert(ctx);

  my_address = uip_ds6_get_global(ADDR_PREFERRED);
  uip_ipaddr_copy(&listen_addr.addr, &my_address->ipaddr);
  coap_address_set_port(&listen_addr, COAP_DEFAULT_PORT);

  *ctx = coap_new_context(&listen_addr);

  if (!*ctx) {
    coap_log_crit("cannot create CoAP context\r\n");
  }
  coap_context_set_max_idle_sessions(*ctx, 2);
}

/*---------------------------------------------------------------------------*/
#ifndef min
# define min(a,b) ((a) < (b) ? (a) : (b))
#endif

void
hnd_get_time(coap_resource_t *resource, coap_session_t *session,
             const coap_pdu_t *request, const coap_string_t *query,
             coap_pdu_t *response) {
  unsigned char buf[40];
  size_t len;
  coap_tick_t now;
  coap_tick_t t;

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
      time_t tnow = now;
      tmp = gmtime(&tnow);
      if (!tmp) {
        /* If 'tnow' is not valid */
        coap_pdu_set_code(response, COAP_RESPONSE_CODE_NOT_FOUND);
        return;
      } else {
        len = strftime((char *)buf, sizeof(buf), "%b %d %H:%M:%S", tmp);
      }
    }
    coap_add_data_blocked_response(request, response,
                                   COAP_MEDIATYPE_TEXT_PLAIN, 1,
                                   len,
                                   buf);
  } else {
    /* if my_clock_base was deleted, we pretend to have no such resource */
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_NOT_FOUND);
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

/* struct etimer notify_timer; */
struct etimer dirty_timer;

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(coap_server_process, ev, data) {
  PROCESS_BEGIN();

  /* Initialize libcoap library */
  coap_startup();

  clock_offset = clock_time();
  init_coap_server(&coap_context);

  if (!coap_context) {
    coap_log_emerg("cannot create context\n");
    PROCESS_EXIT();
  }

  init_coap_resources(coap_context);

  /* etimer_set(&notify_timer, 5 * CLOCK_SECOND); */
  etimer_set(&dirty_timer, 30 * CLOCK_SECOND);

  while (1) {
    PROCESS_YIELD();
    if (ev == PROCESS_EVENT_TIMER && etimer_expired(&dirty_timer)) {
      coap_resource_notify_observers(time_resource, NULL);
      etimer_reset(&dirty_timer);
    }
  }
  coap_cleanup();

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
