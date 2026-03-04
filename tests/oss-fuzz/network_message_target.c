#include "coap3/coap_internal.h"
#include <stdlib.h>
#include <string.h>

/* Test message parsing and processing functions from coap_net.c */
static void
test_message_processing(coap_context_t *ctx, coap_session_t *session,
                        uint8_t *data, size_t size) {
  if (!ctx || !session || !data || size < 4) {
    return;
  }

  coap_pdu_t *pdu = coap_pdu_init(0, 0, 0, size);
  if (!pdu) {
    return;
  }

  /* Parse raw message data as CoAP PDU */
  if (coap_pdu_parse(session->proto, data, size, pdu) > 0) {
    /* Successfully parsed - exercise PDU accessor functions */
    coap_pdu_get_type(pdu);
    coap_pdu_get_code(pdu);
    coap_pdu_get_mid(pdu);

    /* Iterate through PDU options */
    coap_opt_iterator_t opt_iter;
    coap_option_iterator_init(pdu, &opt_iter, COAP_OPT_ALL);
    while (coap_option_next(&opt_iter)) {
    }

    /* Access payload data */
    size_t payload_len;
    const uint8_t *payload;
    if (coap_get_data(pdu, &payload_len, &payload)) {
    }
  }

  coap_delete_pdu(pdu);
}

/* Test message sending functions from coap_net.c */
static void
test_send_functions(coap_session_t *session, coap_pdu_t *pdu) {
  if (!session || !pdu) {
    return;
  }

  /* Test ACK and RST sending */
  coap_send_ack(session, pdu);
  coap_send_rst(session, pdu);

  /* Test error response generation */
  if (COAP_PDU_IS_REQUEST(pdu)) {
    coap_send_error(session, pdu, COAP_RESPONSE_CODE(400), NULL);
    coap_send_error(session, pdu, COAP_RESPONSE_CODE(404), NULL);
    coap_send_error(session, pdu, COAP_RESPONSE_CODE(500), NULL);
  }
}

/* Test message queue operations from coap_net.c */
static void
test_queue_operations(coap_context_t *ctx) {
  if (!ctx) {
    return;
  }

  /* Test queue management functions */
  coap_queue_t *node = coap_new_node();
  if (node) {
    /* peek_next and pop_next exercise queue code paths */
    (void)coap_peek_next(ctx);
    (void)coap_pop_next(ctx);
    coap_delete_node(node);
  }
}

/* Test context configuration with fuzzer input */
static void
test_context_config(coap_context_t *ctx, const uint8_t *data, size_t size) {
  if (!ctx || size < 16) {
    return;
  }

  /* Use fuzz data to configure various context parameters */
  coap_context_set_keepalive(ctx, data[0]);
  coap_context_set_max_idle_sessions(ctx, data[1]);
  coap_context_set_max_handshake_sessions(ctx, data[2]);
  coap_context_set_session_timeout(ctx, data[3]);
  /* Valid token size range is 8-4096 */
  size_t token_size = 8 + (data[4] % 256);
  coap_context_set_max_token_size(ctx, token_size);

  if (size >= 20) {
    size_t csm_max_message_size = (data[16] << 24) | (data[17] << 16) |
                                  (data[18] << 8) | data[19];
    /* CSM max message size must be >= 64 per spec */
    if (csm_max_message_size >= 64) {
      coap_context_set_csm_max_message_size(ctx, csm_max_message_size);
    }

    uint32_t timeout = (data[12] << 24) | (data[13] << 16) |
                       (data[14] << 8) | data[15];
    coap_context_set_csm_timeout_ms(ctx, timeout);
  }
}

/* Test PSK (Pre-Shared Key) configuration */
static void
test_psk_config(coap_context_t *ctx, const uint8_t *data, size_t size) {
  if (!ctx || size < 32) {
    return;
  }

  /* Extract key and hint lengths from fuzz data */
  size_t key_len = (data[0] % 16) + 1;
  size_t hint_len = (data[1] % 16) + 1;

  if (size >= 32 + key_len + hint_len) {
    /* Create null-terminated hint string (required by API contract) */
    char *hint = malloc(hint_len + 1);
    if (!hint) {
      return;
    }
    memcpy(hint, &data[2], hint_len);
    hint[hint_len] = '\0';

    const uint8_t *key = &data[2 + hint_len];
    coap_context_set_psk(ctx, hint, key, key_len);

    free(hint);
  }
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  coap_context_t *ctx = NULL;
  coap_session_t *session = NULL;
  coap_address_t local_addr, remote_addr;
  uint8_t *data_copy = NULL;

  /* Require minimum size for meaningful testing */
  if (size < 8) {
    return 0;
  }

  /* Create writable copy of input data */
  data_copy = malloc(size);
  if (!data_copy) {
    return 0;
  }
  memcpy(data_copy, data, size);

  /* Initialize CoAP library */
  coap_startup();
  coap_set_log_level(COAP_LOG_DEBUG);

  /* Setup local address */
  coap_address_init(&local_addr);
  local_addr.addr.sa.sa_family = AF_INET;

  /* Create CoAP context */
  ctx = coap_new_context(NULL);
  if (!ctx) {
    goto cleanup;
  }

  /* Test context configuration if enough data */
  if (size >= 16) {
    test_context_config(ctx, data, size);
  }

  /* Test PSK configuration conditionally */
  if (size >= 32) {
    test_psk_config(ctx, data, size);
  }

  /* Setup remote address for session creation */
  coap_address_init(&remote_addr);
  remote_addr.addr.sa.sa_family = AF_INET;
  memcpy(&remote_addr.addr.sin.sin_addr.s_addr,
         &data[size > 4 ? size - 4 : 0],
         size > 4 ? 4 : size);
  remote_addr.addr.sin.sin_port = htons(5683);

  /* Create client session for testing */
  session = coap_new_client_session(ctx, NULL, &remote_addr, COAP_PROTO_UDP);
  if (!session) {
    goto cleanup;
  }

  /* Partition fuzz input for different test scenarios */
  size_t msg_offset = 0;

  /* Test 1: Message processing with full input */
  if (size >= msg_offset + 4) {
    size_t msg_len = size - msg_offset;
    if (msg_len > 4) {
      test_message_processing(ctx, session, data_copy + msg_offset, msg_len);
    }
  }

  /* Test 2: Send functions if we can parse as valid PDU */
  if (size >= 4) {
    coap_pdu_t *pdu = coap_pdu_init(0, 0, 0, size);
    if (pdu) {
      if (coap_pdu_parse(COAP_PROTO_UDP, data_copy, size, pdu)) {
        test_send_functions(session, pdu);
      }
      coap_delete_pdu(pdu);
    }
  }

  /* Test 3: Queue operations */
  test_queue_operations(ctx);

  /* Test 4: Message processing with alternative data slice */
  if (size >= 16) {
    size_t alt_offset = size / 2;
    size_t alt_len = size - alt_offset;
    if (alt_len >= 4) {
      test_message_processing(ctx, session, data_copy + alt_offset, alt_len);
    }
  }

cleanup:
  if (session) {
    coap_session_release(session);
  }
  if (ctx) {
    coap_free_context(ctx);
  }
  if (data_copy) {
    free(data_copy);
  }
  coap_cleanup();

  return 0;
}
