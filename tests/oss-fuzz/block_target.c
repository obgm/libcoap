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

/* Resource handler - exercises coap_add_data_large_response() */
static void
block_handler(coap_resource_t *resource, coap_session_t *session,
              const coap_pdu_t *request, const coap_string_t *query,
              coap_pdu_t *response) {
  (void)query;
  size_t len;
  const uint8_t *databuf;

  response->code = COAP_RESPONSE_CODE(205);

  if (coap_get_data(request, &len, &databuf) && len > 64) {
    /* Large payload - use block transfer API */
    coap_add_data_large_response(resource, session, request, response,
                                 query, COAP_MEDIATYPE_TEXT_PLAIN, -1, 0,
                                 len, databuf, NULL, NULL);
  } else if (len > 0) {
    coap_add_data(response, len, databuf);
  } else {
    /* Generate 256-byte response to trigger BLOCK2 */
    static const uint8_t large_data[256] = {
      '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F',
      '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F',
      '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F',
      '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F',
      '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F',
      '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F',
      '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F',
      '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F',
      '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F',
      '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F',
      '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F',
      '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F',
      '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F',
      '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F',
      '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F',
      '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'
    };
    coap_add_data_large_response(resource, session, request, response,
                                 query, COAP_MEDIATYPE_TEXT_PLAIN, -1, 0,
                                 sizeof(large_data), large_data, NULL,
                                 NULL);
  }
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  coap_context_t *ctx = NULL;
  coap_session_t *session = NULL;
  coap_resource_t *resource = NULL;
  coap_address_t addr;

  if (size < 8)
    return 0;

  coap_startup();
  coap_set_log_level(COAP_LOG_EMERG);
  coap_debug_set_packet_loss("50%");
  coap_debug_set_packet_fail("100%");

  ctx = coap_new_context(NULL);
  if (!ctx)
    goto cleanup;
  coap_register_event_handler(ctx, fuzz_event_handler);

  /* Configure block mode and max block size */
  uint32_t block_mode = ((uint32_t)data[0] << 8) | data[1];
  coap_context_set_block_mode(ctx, block_mode & 0x0F);

  uint16_t max_block = ((uint16_t)data[2] << 8) | data[3];
  if (max_block >= 16 && max_block <= 1024) {
    coap_context_set_max_block_size(ctx, max_block);
  }

  /* Create resource with type and interface attributes */
  resource = coap_resource_init(coap_make_str_const("data"), 0);
  if (resource) {
    coap_register_request_handler(resource, COAP_REQUEST_GET, block_handler);
    coap_register_request_handler(resource, COAP_REQUEST_PUT, block_handler);
    coap_register_request_handler(resource, COAP_REQUEST_POST, block_handler);
    coap_add_attr(resource, coap_make_str_const("rt"),
                  coap_make_str_const("\"test\""), 0);
    coap_add_attr(resource, coap_make_str_const("if"),
                  coap_make_str_const("\"block\""), 0);
    coap_add_resource(ctx, resource);
  }

  /* Create session */
  coap_address_init(&addr);
  addr.addr.sa.sa_family = AF_INET;
  session = coap_new_client_session(ctx, NULL, &addr, COAP_PROTO_UDP);
  if (!session)
    goto cleanup;
  session->state = COAP_SESSION_STATE_ESTABLISHED;

  /* Dispatch with programmatic PDU and raw wire format */
  coap_fuzz_dispatch(ctx, session, data, size, (const uint8_t *)"data", 4);

  /* Probe .well-known/core with a fuzz-derived query filter */
  {
    coap_pdu_t *wk = coap_pdu_init(COAP_MESSAGE_CON, COAP_REQUEST_CODE_GET,
                                   coap_new_message_id(session),
                                   coap_session_max_pdu_size(session));
    if (wk) {
      coap_add_option(wk, COAP_OPTION_URI_PATH, 11,
                      (const uint8_t *)".well-known");
      coap_add_option(wk, COAP_OPTION_URI_PATH, 4,
                      (const uint8_t *)"core");
      uint8_t qlen = (data[4] % 16) + 1;
      if ((size_t)5 + qlen <= size)
        coap_add_option(wk, COAP_OPTION_URI_QUERY, qlen, data + 5);
      coap_dispatch(ctx, session, wk);
      coap_delete_pdu(wk);
    }
  }

cleanup:
  if (session)
    coap_session_release(session);
  if (ctx)
    coap_free_context(ctx);
  coap_cleanup();
  return 0;
}
