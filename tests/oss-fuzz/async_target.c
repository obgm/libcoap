#include "coap3/coap_internal.h"
#include "coap_fuzz_helper.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

static int
fuzz_event_handler(coap_session_t *session, const coap_event_t event) {
  (void)session;
  (void)event;
  return 0;
}

static void
async_handler(coap_resource_t *resource, coap_session_t *session,
              const coap_pdu_t *request, const coap_string_t *query,
              coap_pdu_t *response) {
  (void)resource;
  (void)query;

  size_t len;
  const uint8_t *databuf;
  coap_bin_const_t token = coap_pdu_get_token(request);
  coap_async_t *async = coap_find_async(session, token);

  if (async) {
    response->code = COAP_RESPONSE_CODE(205);
    if (coap_get_data(request, &len, &databuf) && len > 0) {
      coap_add_data(response, len, databuf);
    }
    coap_free_async(session, async);
  } else {
    response->code = COAP_RESPONSE_CODE(400);
    if (coap_get_data(request, &len, &databuf) && len > 0) {
      async = coap_register_async(session, request,
                                  (coap_tick_t)len * COAP_TICKS_PER_SECOND / 100);
      if (async && len > 1) {
        uint8_t *app_data = malloc(len);
        if (app_data) {
          memcpy(app_data, databuf, len);
          coap_async_set_app_data2(async, app_data, free);
          response->code = COAP_RESPONSE_CODE(0);
        }
      }
    }
  }
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  coap_context_t *ctx = NULL;
  coap_session_t *session = NULL;
  coap_resource_t *resource = NULL;
  coap_address_t addr;
  coap_pdu_t *pdu = NULL;

  if (size < 16)
    return 0;

  coap_startup();
  coap_set_log_level(COAP_LOG_EMERG);
  coap_debug_set_packet_loss("50%");
  coap_debug_set_packet_fail("100%");

  ctx = coap_new_context(NULL);
  if (!ctx)
    goto cleanup;
  coap_register_event_handler(ctx, fuzz_event_handler);

  resource = coap_resource_init(coap_make_str_const("async"), 0);
  if (resource) {
    coap_register_request_handler(resource, COAP_REQUEST_GET, async_handler);
    coap_register_request_handler(resource, COAP_REQUEST_POST, async_handler);
    coap_add_resource(ctx, resource);
  }

  coap_address_init(&addr);
  addr.addr.sin.sin_family = AF_INET;
  addr.addr.sin.sin_port = htons(5683);
  addr.addr.sin.sin_addr.s_addr = htonl(0x7F000001);

  session = coap_new_client_session(ctx, NULL, &addr, COAP_PROTO_UDP);
  if (!session)
    goto cleanup;
  session->state = COAP_SESSION_STATE_ESTABLISHED;

  /* Direct async API testing */
  size_t token_len = (size > 8) ? 8 : size;
  pdu = coap_pdu_init(COAP_MESSAGE_CON, COAP_REQUEST_CODE_GET,
                      coap_new_message_id(session), 128);
  if (pdu) {
    coap_add_token(pdu, token_len, data);
    coap_add_option(pdu, COAP_OPTION_URI_PATH, 5, (const uint8_t *)"async");

    coap_async_t *async = coap_register_async(session, pdu,
                                              COAP_TICKS_PER_SECOND);
    if (async) {
      coap_bin_const_t token = {.length = token_len, .s = data};
      coap_async_t *found = coap_find_async(session, token);

      if (found && size > token_len) {
        coap_async_set_delay(async, COAP_TICKS_PER_SECOND / 10);
        coap_async_trigger(async);

        /* Test app data operations */
        coap_async_get_app_data(async);
      }

      coap_free_async(session, async);
    }
    coap_delete_pdu(pdu);

    /* Test registration failure path */
    if (size > 32) {
      pdu = coap_pdu_init(COAP_MESSAGE_CON, COAP_REQUEST_CODE_POST,
                          coap_new_message_id(session), 64);
      if (pdu) {
        coap_add_token(pdu, 4, &data[16]);
        coap_async_t *async2 = coap_register_async(session, pdu, 0);
        if (async2) {
          coap_async_set_delay(async2, COAP_TICKS_PER_SECOND * 2);
          coap_free_async(session, async2);
        }
        coap_delete_pdu(pdu);
      }
    }
  }

  /* Dispatch with programmatic PDU and raw wire format */
  coap_fuzz_dispatch(ctx, session, data, size, (const uint8_t *)"async", 5);

cleanup:
  if (session)
    coap_session_release(session);
  if (ctx)
    coap_free_context(ctx);
  coap_cleanup();
  return 0;
}
