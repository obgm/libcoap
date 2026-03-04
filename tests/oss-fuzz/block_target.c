#include "coap3/coap_internal.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  coap_context_t *ctx = NULL;
  coap_session_t *session = NULL;
  coap_pdu_t *pdu = NULL;
  coap_address_t addr;

  coap_startup();
  coap_set_log_level(COAP_LOG_EMERG);

  ctx = coap_new_context(NULL);
  if (!ctx) {
    goto cleanup;
  }

  uint32_t block_mode = ((uint32_t)data[0] << 24) |
                        ((uint32_t)data[1] << 16) |
                        ((uint32_t)data[2] << 8) |
                        data[3];
  coap_context_set_block_mode(ctx, block_mode);

  coap_address_init(&addr);
  addr.addr.sa.sa_family = AF_INET;
  session = coap_new_client_session(ctx, NULL, &addr, COAP_PROTO_UDP);
  if (!session) {
    goto cleanup;
  }

  /* Test 1: Parse input as PDU and test block option extraction */
  pdu = coap_pdu_init(0, 0, 0, size);
  if (pdu) {
    if (coap_pdu_parse(COAP_PROTO_UDP, data, size, pdu)) {
      coap_block_t block;
      coap_block_b_t block_b;
      coap_opt_iterator_t opt_iter;
      coap_opt_t *option;

      /* Test coap_get_block() and coap_write_block_opt() */
      if (coap_get_block(pdu, COAP_OPTION_BLOCK1, &block)) {
        coap_write_block_opt(&block, COAP_OPTION_BLOCK1, pdu, size);
        coap_add_block(pdu, size, data, block.num, block.szx);
      }
      if (coap_get_block(pdu, COAP_OPTION_BLOCK2, &block)) {
        coap_write_block_opt(&block, COAP_OPTION_BLOCK2, pdu, size);
        coap_add_block(pdu, size, data, block.num, block.szx);
      }

      /* Test coap_get_block_b() and coap_write_block_b_opt() */
      if (coap_get_block_b(session, pdu, COAP_OPTION_BLOCK1, &block_b)) {
        coap_write_block_b_opt(session, &block_b, COAP_OPTION_BLOCK1, pdu, size);
        coap_add_block_b_data(pdu, size, data, &block_b);
      }
      if (coap_get_block_b(session, pdu, COAP_OPTION_BLOCK2, &block_b)) {
        coap_write_block_b_opt(session, &block_b, COAP_OPTION_BLOCK2, pdu, size);
        coap_add_block_b_data(pdu, size, data, &block_b);
      }
      if (coap_get_block_b(session, pdu, COAP_OPTION_Q_BLOCK1, &block_b)) {
        coap_write_block_b_opt(session, &block_b, COAP_OPTION_Q_BLOCK1, pdu, size);
        coap_add_block_b_data(pdu, size, data, &block_b);
      }
      if (coap_get_block_b(session, pdu, COAP_OPTION_Q_BLOCK2, &block_b)) {
        coap_write_block_b_opt(session, &block_b, COAP_OPTION_Q_BLOCK2, pdu, size);
        coap_add_block_b_data(pdu, size, data, &block_b);
      }

      /* Test coap_opt_block_num() on all block options */
      if (coap_option_iterator_init(pdu, &opt_iter, COAP_OPT_ALL)) {
        while ((option = coap_option_next(&opt_iter))) {
          if (opt_iter.number == COAP_OPTION_BLOCK1 ||
              opt_iter.number == COAP_OPTION_BLOCK2 ||
              opt_iter.number == COAP_OPTION_Q_BLOCK1 ||
              opt_iter.number == COAP_OPTION_Q_BLOCK2) {
            coap_opt_block_num(option);
          }
        }
      }

      /* Test 2: Generate blocked response with fuzzer-controlled parameters */
      coap_pdu_t *response = coap_pdu_init(COAP_MESSAGE_ACK,
                                           COAP_RESPONSE_CODE(205),
                                           0, 1152);
      if (response) {
        /* Use fuzzer input to control response parameters */
        uint16_t media_type = ((uint16_t)data[4] << 8) | data[5];
        int maxage = (int)data[6];
        size_t resp_len = (size > 8) ? (size - 8) : 0;
        const uint8_t *resp_data = (size > 8) ? &data[8] : data;

        /* Test coap_add_data_blocked_response() */
        coap_add_data_blocked_response(pdu, response,
                                       media_type, maxage,
                                       resp_len, resp_data);
        coap_delete_pdu(response);
      }
    }
    coap_delete_pdu(pdu);
  }

cleanup:
  if (session)
    coap_session_release(session);
  if (ctx)
    coap_free_context(ctx);
  coap_cleanup();
  return 0;
}
