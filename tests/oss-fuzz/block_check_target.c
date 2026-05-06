#include "coap3/coap_internal.h"
#include <stdint.h>
#include <string.h>

static int
fuzz_event_handler(coap_session_t *session, const coap_event_t event) {
  (void)session;
  (void)event;
  return 0;
}

static uint8_t test_data[4096];

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 20) {
    return 0;
  }

  for (size_t i = 0; i < sizeof(test_data); i++) {
    test_data[i] = (uint8_t)(i & 0xFF);
  }

  coap_startup();
  coap_set_log_level(COAP_LOG_EMERG);
  coap_dtls_set_log_level(COAP_LOG_EMERG);
  coap_debug_set_packet_loss("50%");
  coap_debug_set_packet_fail("100%");

  coap_context_t *ctx = coap_new_context(NULL);
  if (!ctx) {
    return 0;
  }
  coap_register_event_handler(ctx, fuzz_event_handler);

  if (data[0] & 0x01) {
    ctx->block_mode |= COAP_BLOCK_USE_LIBCOAP;
  }
  if (data[0] & 0x04) {
    ctx->block_mode |= (COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_HAS_Q_BLOCK);
  }

  coap_address_t addr;
  coap_address_init(&addr);
  addr.addr.sa.sa_family = AF_INET;

  coap_endpoint_t *ep = coap_new_endpoint(ctx, &addr, COAP_PROTO_UDP);
  if (!ep) {
    coap_free_context(ctx);
    return 0;
  }

  coap_session_t *session = coap_new_client_session(ctx, NULL, &addr,
                                                    COAP_PROTO_UDP);
  if (!session) {
    coap_free_context(ctx);
    return 0;
  }

  coap_str_const_t *uri = coap_make_str_const("test");
  coap_resource_t *resource = coap_resource_init(uri, 0);
  if (resource) {
    coap_add_resource(ctx, resource);
  }

  unsigned int block_szx = (size > 1) ? (data[1] % 7) : 2;
  size_t data_len = ((data[2] % 32) + 1) * 64;
  if (data_len > sizeof(test_data)) {
    data_len = sizeof(test_data);
  }
  uint32_t block_num = (size > 4) ? (data[4] % 16) : 0;

  /* Populate lg_xmit so timeout functions iterate a non-empty list */
  {
    uint32_t saved_mode = session->block_mode;
    session->block_mode |= COAP_BLOCK_USE_LIBCOAP;
    coap_pdu_t *setup_pdu = coap_pdu_init(COAP_MESSAGE_CON, COAP_REQUEST_CODE_PUT,
                                          coap_new_message_id(session),
                                          coap_session_max_pdu_size(session));
    if (setup_pdu) {
      coap_add_option(setup_pdu, COAP_OPTION_URI_PATH, 4, (const uint8_t *)"test");
      coap_add_data_large_request_lkd(session, setup_pdu, sizeof(test_data),
                                      test_data, NULL, NULL);
      coap_delete_pdu(setup_pdu);
    }
    session->block_mode = saved_mode;
  }

  coap_tick_t now, tim_rem;
  coap_ticks(&now);

  /* Timeout handlers */
  coap_block_check_lg_xmit_timeouts(session, now, &tim_rem);
  coap_block_check_lg_crcv_timeouts(session, now, &tim_rem);
  coap_block_check_lg_srcv_timeouts(session, now, &tim_rem);
  coap_block_check_q_block1_xmit(session, now, &tim_rem);
  coap_block_check_q_block2_xmit(session, now, &tim_rem);

  /* Low-level block encoding */
  coap_pdu_t *pdu = coap_pdu_init(COAP_MESSAGE_CON, COAP_REQUEST_CODE_PUT,
                                  coap_new_message_id(session),
                                  coap_session_max_pdu_size(session));
  if (pdu) {
    coap_add_option(pdu, COAP_OPTION_URI_PATH, 4, (const uint8_t *)"test");

    if (coap_add_block(pdu, data_len, test_data, block_num, block_szx)) {
      coap_block_t block;
      memset(&block, 0, sizeof(block));
      block.num = block_num;
      block.szx = block_szx;
      block.m = (size > 5) ? (data[5] & 0x01) : 0;
      coap_write_block_opt(&block, COAP_OPTION_BLOCK1, pdu, data_len);
    }

    coap_block_t block_read;
    if (coap_get_block(pdu, COAP_OPTION_BLOCK1, &block_read)) {
      (void)block_read.num;
    }
    coap_delete_pdu(pdu);
  }

  /* BERT block encoding */
  pdu = coap_pdu_init(COAP_MESSAGE_CON, COAP_REQUEST_CODE_PUT,
                      coap_new_message_id(session),
                      coap_session_max_pdu_size(session));
  if (pdu) {
    coap_block_b_t block_b;
    memset(&block_b, 0, sizeof(block_b));
    block_b.num = (size > 6) ? (data[6] % 32) : 0;
    block_b.szx = block_szx;
    block_b.m = (size > 7) ? (data[7] & 0x01) : 0;
    block_b.aszx = block_szx;
    coap_write_block_b_opt(session, &block_b, COAP_OPTION_BLOCK1, pdu,
                           data_len);

    coap_pdu_t *resp = coap_pdu_init(COAP_MESSAGE_ACK, COAP_RESPONSE_CODE(205),
                                     coap_new_message_id(session), 1152);
    if (resp) {
      coap_add_block_b_data(resp, data_len, test_data, &block_b);
      coap_delete_pdu(resp);
    }
    coap_delete_pdu(pdu);
  }

  /* Large data transfer APIs */
  pdu = coap_pdu_init(COAP_MESSAGE_CON, COAP_REQUEST_CODE_GET,
                      coap_new_message_id(session),
                      coap_session_max_pdu_size(session));
  if (pdu && resource) {
    coap_add_option(pdu, COAP_OPTION_URI_PATH, 4, (const uint8_t *)"test");

    coap_pdu_t *resp = coap_pdu_init(COAP_MESSAGE_ACK, COAP_RESPONSE_CODE(205),
                                     coap_new_message_id(session),
                                     coap_session_max_pdu_size(session));
    if (resp) {
      coap_add_data_large_response(resource, session, pdu, resp,
                                   NULL, COAP_MEDIATYPE_TEXT_PLAIN, -1, 0,
                                   data_len, test_data, NULL, NULL);

      coap_pdu_t *resp2 = coap_pdu_init(COAP_MESSAGE_ACK,
                                        COAP_RESPONSE_CODE(205),
                                        coap_new_message_id(session), 1152);
      if (resp2) {
        coap_add_data_blocked_response(pdu, resp2, COAP_MEDIATYPE_TEXT_PLAIN,
                                       -1, data_len, test_data);
        coap_delete_pdu(resp2);
      }
      coap_delete_pdu(resp);
    }
    coap_delete_pdu(pdu);
  }

  /* Large request with lock */
  pdu = coap_pdu_init(COAP_MESSAGE_CON, COAP_REQUEST_CODE_PUT,
                      coap_new_message_id(session),
                      coap_session_max_pdu_size(session));
  if (pdu) {
    coap_add_option(pdu, COAP_OPTION_URI_PATH, 4, (const uint8_t *)"test");
    coap_add_data_large_request_lkd(session, pdu, data_len, test_data, NULL,
                                    NULL);
    coap_delete_pdu(pdu);
  }

  /* Q-Block support check */
  (void)coap_q_block_is_supported();

  /* Observe cancellation */
  pdu = coap_pdu_init(COAP_MESSAGE_CON, COAP_REQUEST_CODE_GET,
                      coap_new_message_id(session),
                      coap_session_max_pdu_size(session));
  if (pdu) {
    coap_add_option(pdu, COAP_OPTION_OBSERVE, 0, NULL);

    uint8_t token_buf[8];
    coap_binary_t token;
    token.length = (size > 8) ? ((data[8] % 8) + 1) : 1;
    if (token.length > sizeof(token_buf)) {
      token.length = sizeof(token_buf);
    }
    memcpy(token_buf, (size > 16) ? (data + 12) : data, token.length);
    token.s = token_buf;

    coap_cancel_observe(session, &token, COAP_MESSAGE_CON);
    coap_cancel_observe_lkd(session, &token, COAP_MESSAGE_CON);
    coap_delete_pdu(pdu);
  }

  /* Lifecycle cleanup */
  coap_block_delete_lg_crcv(session, NULL);
  coap_block_delete_lg_xmit(session, NULL);
  coap_register_block_data_handler(ctx, NULL);

  coap_io_process(ctx, 1);
  coap_free_context(ctx);
  coap_cleanup();

  return 0;
}
