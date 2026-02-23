#include "coap3/coap_internal.h"


/* Helper to test block_t write/add operations */
static void
test_block_write_add(coap_block_t block, const uint8_t *data, size_t size) {
  coap_pdu_t *response = coap_pdu_init(0, 0, 0, 1024);
  if (!response) {
    return;
  }

  coap_write_block_opt(&block, COAP_OPTION_BLOCK1, response, 128);
  coap_add_block(response, size, data, block.num, block.szx);
  coap_delete_pdu(response);
}

/* Helper to test blocked response generation */
static void
test_blocked_response(coap_pdu_t *request, const uint8_t *data, size_t size) {
  coap_pdu_t *response = coap_pdu_init(0, 0, 0, 1024);
  if (!response) {
    return;
  }

  /* Test coap_add_data_blocked_response with various parameters */
  coap_add_data_blocked_response(request, response,
                                 COAP_MEDIATYPE_TEXT_PLAIN,
                                 60, /* maxage */
                                 size, data);
  coap_delete_pdu(response);
}

/* Helper to test block_b_t write/add operations */
static void
test_block_b_write_add(coap_session_t *session, coap_block_b_t block_b,
                       const uint8_t *data, size_t size) {
  coap_pdu_t *response = coap_pdu_init(0, 0, 0, 1024);
  if (!response) {
    return;
  }

  coap_write_block_b_opt(session, &block_b, COAP_OPTION_BLOCK2, response, 128);
  coap_add_block_b_data(response, size, data, &block_b);
  coap_delete_pdu(response);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  coap_context_t *ctx = NULL;
  coap_session_t *session = NULL;
  coap_pdu_t *pdu = NULL;
  coap_address_t addr;

  coap_startup();
  coap_set_log_level(COAP_LOG_EMERG);

  /* Setup session context for _b variants */
  ctx = coap_new_context(NULL);
  if (!ctx) {
    goto cleanup;
  }

  /* Test block mode configuration with fuzzer input */
  if (size >= 4) {
    uint32_t block_mode = ((uint32_t)data[0] << 24) |
                          ((uint32_t)data[1] << 16) |
                          ((uint32_t)data[2] << 8) |
                          data[3];
    coap_context_set_block_mode(ctx, block_mode);

    /* Test max block size configuration */
    if (size >= 6) {
      size_t max_block_size = ((size_t)data[4] << 8) | data[5];
      coap_context_set_max_block_size(ctx, max_block_size);
    }
  }

  coap_address_init(&addr);
  addr.addr.sa.sa_family = AF_INET;

  session = coap_new_client_session(ctx, NULL, &addr, COAP_PROTO_UDP);
  if (!session) {
    goto cleanup;
  }

  pdu = coap_pdu_init(0, 0, 0, size);
  if (!pdu) {
    goto cleanup;
  }

  /* Parse PDU and test session-based block tracking */
  if (!coap_pdu_parse(COAP_PROTO_UDP, data, size, pdu)) {
    goto cleanup;
  }

  /* Test coap_get_block with all block options */
  coap_block_t block;
  if (coap_get_block(pdu, COAP_OPTION_BLOCK1, &block)) {
    test_block_write_add(block, data, size);
  }
  if (coap_get_block(pdu, COAP_OPTION_BLOCK2, &block)) {
    test_block_write_add(block, data, size);
  }

  /* Test coap_opt_block_num on block options if present */
  coap_opt_iterator_t opt_iter;
  coap_opt_t *option;
  if (coap_option_iterator_init(pdu, &opt_iter, COAP_OPT_ALL)) {
    while ((option = coap_option_next(&opt_iter))) {
      if (opt_iter.number == COAP_OPTION_BLOCK1 ||
          opt_iter.number == COAP_OPTION_BLOCK2 ||
          opt_iter.number == COAP_OPTION_Q_BLOCK1 ||
          opt_iter.number == COAP_OPTION_Q_BLOCK2) {
        /* Test extracting block number from option */
        coap_opt_block_num(option);
      }
    }
  }

  /* Test blocked response generation */
  test_blocked_response(pdu, data, size);

  /* Test coap_get_block_b with all block options */
  coap_block_b_t block_b;
  if (coap_get_block_b(session, pdu, COAP_OPTION_BLOCK1, &block_b)) {
    test_block_b_write_add(session, block_b, data, size);
  }
  if (coap_get_block_b(session, pdu, COAP_OPTION_BLOCK2, &block_b)) {
    test_block_b_write_add(session, block_b, data, size);
  }
  if (coap_get_block_b(session, pdu, COAP_OPTION_Q_BLOCK1, &block_b)) {
    test_block_b_write_add(session, block_b, data, size);
  }
  if (coap_get_block_b(session, pdu, COAP_OPTION_Q_BLOCK2, &block_b)) {
    test_block_b_write_add(session, block_b, data, size);
  }

cleanup:
  if (pdu)
    coap_delete_pdu(pdu);
  if (session)
    coap_session_release(session);
  if (ctx)
    coap_free_context(ctx);
  coap_cleanup();
  return 0;
}
