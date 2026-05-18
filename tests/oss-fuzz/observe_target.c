#include "coap3/coap_internal.h"
#include "coap_fuzz_helper.h"
#include <stdint.h>
#include <string.h>

static int
fuzz_event_handler(coap_session_t *session, const coap_event_t event) {
  (void)session;
  (void)event;
  return 0;
}

static void
fuzz_handler(coap_resource_t *resource, coap_session_t *session,
             const coap_pdu_t *request, const coap_string_t *query,
             coap_pdu_t *response) {
  (void)resource;
  (void)session;
  (void)request;
  (void)query;
  response->code = COAP_RESPONSE_CODE(205);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1)
    return 0;

  coap_startup();
  coap_set_log_level(COAP_LOG_EMERG);
  coap_debug_set_packet_loss("50%");
  coap_debug_set_packet_fail("100%");

  coap_context_t *ctx = coap_new_context(NULL);
  if (!ctx)
    goto cleanup;
  coap_register_event_handler(ctx, fuzz_event_handler);

  coap_resource_t *res = coap_resource_init(coap_make_str_const("obs"), 0);
  if (!res)
    goto cleanup;
  res->observable = 1;
  coap_register_request_handler(res, COAP_REQUEST_GET, fuzz_handler);
  coap_add_resource(ctx, res);

  coap_address_t addr;
  coap_address_init(&addr);
  addr.addr.sa.sa_family = AF_INET;
  coap_session_t *sess = coap_new_client_session(ctx, NULL, &addr, COAP_PROTO_UDP);
  if (!sess)
    goto cleanup;
  sess->state = COAP_SESSION_STATE_ESTABLISHED;

  /* Test observer functions with fuzzed data */
  size_t offset = 0;
  int iterations = 0;
  while (offset + 1 < size && iterations++ < 5) {
    coap_pdu_t *pdu = coap_pdu_init(COAP_MESSAGE_CON, COAP_REQUEST_CODE_GET, 1, 128);
    if (!pdu)
      break;

    /* Fuzzed token */
    size_t tok_len = (data[offset] % 8) + 1;
    if (offset + tok_len < size) {
      coap_add_token(pdu, tok_len, data + offset);
      offset += tok_len;
    }

    /* Add Observe option */
    uint8_t obs_val = 0;
    coap_insert_option(pdu, COAP_OPTION_OBSERVE, 1, &obs_val);
    coap_add_option(pdu, COAP_OPTION_URI_PATH, 3, (const uint8_t *)"obs");

    /* Test coap_add_observer */
    coap_lock_lock(goto cleanup);
    coap_subscription_t *sub = coap_add_observer(res, sess, &pdu->actual_token, pdu);
    coap_lock_unlock();

    if (sub) {
      /* Test coap_find_observer */
      coap_find_observer(res, sess, &pdu->actual_token);

      /* Test coap_touch_observer */
      coap_touch_observer(ctx, sess, &pdu->actual_token);

      /* Test coap_resource_notify_observers*/
      coap_resource_notify_observers(res, NULL);

      /* Test coap_delete_observer */
      coap_lock_lock(goto cleanup);
      coap_delete_observer(res, sess, &pdu->actual_token);
      coap_lock_unlock();
    }

    coap_delete_pdu(pdu);
    offset += 8;
  }

  /* Dispatch GET+OBSERVE to exercise subscription paths in handle_request */
  {
    uint8_t obs_val;
    for (obs_val = 0; obs_val <= 1; obs_val++) {
      coap_pdu_t *op = coap_pdu_init(COAP_MESSAGE_CON, COAP_REQUEST_CODE_GET,
                                     coap_new_message_id(sess), 128);
      if (op) {
        coap_add_option(op, COAP_OPTION_OBSERVE, 1, &obs_val);
        coap_add_option(op, COAP_OPTION_URI_PATH, 3, (const uint8_t *)"obs");
        coap_lock_lock(goto cleanup);
        coap_dispatch(ctx, sess, op);
        coap_lock_unlock();
        coap_delete_pdu(op);
      }
    }
  }

  /* Dispatch with programmatic PDU and raw wire format */
  coap_fuzz_dispatch(ctx, sess, data, size, (const uint8_t *)"obs", 3);

cleanup:
  if (ctx)
    coap_free_context(ctx);
  coap_cleanup();
  return 0;
}
