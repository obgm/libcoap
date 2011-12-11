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

#include "config.h"
#include "net/uip-debug.h"

#include <string.h>

#include "debug.h"
#include "coap.h"

static coap_context_t *coap_context;

/* changeable clock base (see handle_put_time()) */
static clock_time_t my_clock_base = 0;

PROCESS(coap_server_process, "CoAP server process");
AUTOSTART_PROCESSES(&coap_server_process);
/*---------------------------------------------------------------------------*/
void
init_coap() {
  coap_address_t listen_addr;
  
  coap_address_init(&listen_addr);
  listen_addr.port = UIP_HTONS(COAP_DEFAULT_PORT);

  coap_context = coap_new_context(&listen_addr);

  coap_set_log_level(LOG_DEBUG);

  if (!coap_context)
    coap_log(LOG_CRIT, "cannot create CoAP context\r\n");
}

/*---------------------------------------------------------------------------*/
#ifndef min
# define min(a,b) ((a) < (b) ? (a) : (b))
#endif

void 
hnd_get_time(coap_context_t  *ctx, struct coap_resource_t *resource, 
	     coap_address_t *peer, coap_pdu_t *request, coap_tid_t id) {
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
#if 0
      response->length += snprintf((char *)response->data, 
				   response->max_size - response->length,
				   "%u", (unsigned int)now);
#endif

    } else {			/* @todo: output human-readable time */
    }
  }

  if (coap_send(ctx, peer, response) == COAP_INVALID_TID) {
    debug("hnd_get_time: cannot send response for message %d\n", 
	  request->hdr->id);
    coap_delete_pdu(response);
  }
}

void
init_resources(coap_context_t *ctx) {
  coap_resource_t *r;
#if 0
  r = coap_resource_init(NULL, 0);
  coap_register_handler(r, COAP_REQUEST_GET, hnd_get_index);

  coap_add_attr(r, (unsigned char *)"ct", 2, (unsigned char *)"0", 1);
  coap_add_attr(r, (unsigned char *)"title", 5, (unsigned char *)"\"General Info\"", 14);
  coap_add_resource(ctx, r);
#endif
  /* store clock base to use in /time */
  my_clock_base = clock_offset;

  r = coap_resource_init((unsigned char *)"time", 4);
  coap_register_handler(r, COAP_REQUEST_GET, hnd_get_time);
#if 0
  coap_register_handler(r, COAP_REQUEST_PUT, hnd_put_time);
  coap_register_handler(r, COAP_REQUEST_DELETE, hnd_delete_time);
#endif
  coap_add_attr(r, (unsigned char *)"ct", 2, (unsigned char *)"0", 1);
  coap_add_attr(r, (unsigned char *)"title", 5, (unsigned char *)"\"Internal Clock\"", 16);
  coap_add_attr(r, (unsigned char *)"rt", 2, (unsigned char *)"\"Ticks\"", 7);
  /* coap_add_attr(r, (unsigned char *)"obs", 3, NULL, 0, 0); */
  coap_add_attr(r, (unsigned char *)"if", 2, (unsigned char *)"\"clock\"", 7);

  coap_add_resource(ctx, r);
#if 0
#ifndef WITHOUT_ASYNC
  r = coap_resource_init((unsigned char *)"async", 5);
  coap_register_handler(r, COAP_REQUEST_GET, hnd_get_async);

  coap_add_attr(r, (unsigned char *)"ct", 2, (unsigned char *)"0", 1);
  coap_add_resource(ctx, r);
#endif /* WITHOUT_ASYNC */
#endif
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(coap_server_process, ev, data)
{
  PROCESS_BEGIN();

  init_coap();
  init_resources(coap_context);

  if (!coap_context) {
    coap_log(LOG_EMERG, "cannot create context\n");
    PROCESS_EXIT();
  }

  while(1) {
    PROCESS_YIELD();
    if(ev == tcpip_event) {
      coap_read(coap_context);	/* read received data */
      coap_dispatch(coap_context); /* and dispatch PDUs from receivequeue */
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
