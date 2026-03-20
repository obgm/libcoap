#include "coap3/coap_internal.h"
#include <stdlib.h>
#include <string.h>

/* Test UDP datagram dispatch and message handling */
static void
test_dgram_dispatch(coap_context_t *ctx, coap_session_t *session,
                    uint8_t *data, size_t size) {
  if (!ctx || !session || !data || size < 4) {
    return;
  }

  session->state = COAP_SESSION_STATE_ESTABLISHED;
  coap_handle_dgram(ctx, session, data, size);
}

/* Test retransmission queue operations (coap_wait_ack, peek_next, pop_next) */
static void
test_queue_operations(coap_context_t *ctx, coap_session_t *session,
                      const uint8_t *data, size_t size) {
  if (!ctx || !session || size < 8) {
    return;
  }

  coap_pdu_t *pdu = coap_pdu_init(COAP_MESSAGE_CON,
                                  COAP_REQUEST_CODE_GET,
                                  coap_new_message_id(session),
                                  64);
  if (!pdu) {
    return;
  }

  size_t token_len = (data[0] % 8) + 1;
  if (token_len <= size) {
    coap_add_token(pdu, token_len, data);
  }

  coap_queue_t *node = coap_new_node();
  if (node) {
    node->session = session;
    node->pdu = pdu;
    node->id = pdu->mid;
    node->timeout = 1000;

    coap_wait_ack(ctx, session, node);

    coap_queue_t *peek = coap_peek_next(ctx);
    if (peek) {
      (void)peek;
    }

    coap_queue_t *popped = coap_pop_next(ctx);
    if (popped) {
      coap_delete_node(popped);
    }
  } else {
    coap_delete_pdu(pdu);
  }
}

/* Test TCP transport and CSM signaling */
static void
test_reliable_transport(coap_context_t *ctx, coap_session_t *session,
                        uint8_t *data, size_t size) {
  if (!ctx || !session || !data || size < 8) {
    return;
  }

  session->proto = COAP_PROTO_TCP;
  session->state = COAP_SESSION_STATE_ESTABLISHED;
  session->type = COAP_SESSION_TYPE_CLIENT;

  coap_pdu_t *pdu = coap_pdu_init(COAP_MESSAGE_CON,
                                  COAP_SIGNALING_CODE_CSM,
                                  0,
                                  64);
  if (!pdu) {
    return;
  }

  if (size >= 4) {
    uint32_t max_msg_size = ((uint32_t)data[0] << 24) |
                            ((uint32_t)data[1] << 16) |
                            ((uint32_t)data[2] << 8) |
                            (uint32_t)data[3];
    if (max_msg_size >= 64) {
      uint8_t buf[4];
      coap_insert_option(pdu, COAP_SIGNALING_OPTION_MAX_MESSAGE_SIZE,
                         coap_encode_var_safe(buf, sizeof(buf), max_msg_size),
                         buf);
    }
  }

  coap_dispatch(ctx, session, pdu);

  coap_delete_pdu(pdu);
}

/* Test session state transitions and send operations */
static void
test_session_operations(coap_context_t *ctx, coap_session_t *session,
                        const uint8_t *data, size_t size) {
  if (!ctx || !session || !data || size < 16) {
    return;
  }

  coap_session_state_t states[] = {
    COAP_SESSION_STATE_NONE,
    COAP_SESSION_STATE_CONNECTING,
    COAP_SESSION_STATE_HANDSHAKE,
    COAP_SESSION_STATE_CSM,
    COAP_SESSION_STATE_ESTABLISHED
  };

  session->state = states[data[0] % 5];

  coap_pdu_t *pdu = coap_pdu_init(COAP_MESSAGE_CON,
                                  COAP_REQUEST_CODE_GET,
                                  coap_new_message_id(session),
                                  128);
  if (!pdu) {
    return;
  }

  size_t token_len = (data[1] % 8) + 1;
  if (token_len + 2 <= size) {
    coap_add_token(pdu, token_len, &data[2]);
  }

  if (size >= token_len + 10) {
    size_t path_len = (data[token_len + 2] % 16) + 1;
    if (token_len + 2 + path_len + 1 <= size) {
      coap_add_option(pdu, COAP_OPTION_URI_PATH, path_len,
                      &data[token_len + 3]);
    }
  }

  if (session->state == COAP_SESSION_STATE_ESTABLISHED) {
    coap_send_ack(session, pdu);
    coap_send_rst(session, pdu);

    if (COAP_PDU_IS_REQUEST(pdu)) {
      coap_send_error(session, pdu, COAP_RESPONSE_CODE(400), NULL);
      coap_send_error(session, pdu, COAP_RESPONSE_CODE(404), NULL);
      coap_send_error(session, pdu, COAP_RESPONSE_CODE(500), NULL);
    }
  }

  coap_delete_pdu(pdu);
}

/* Test context configuration */
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
  size_t token_size = 8 + (data[4] % 256);
  coap_context_set_max_token_size(ctx, token_size);

  if (size >= 20) {
    size_t csm_max_message_size = ((uint32_t)data[16] << 24) | (data[17] << 16) |
                                  (data[18] << 8) | data[19];
    if (csm_max_message_size >= 64) {
      coap_context_set_csm_max_message_size(ctx, csm_max_message_size);
    }

    uint32_t timeout = ((uint32_t)data[12] << 24) | (data[13] << 16) |
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
  coap_set_log_level(COAP_LOG_EMERG);
  coap_debug_set_packet_loss("50%");
  coap_debug_set_packet_fail("100%");

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

  /* Create client session for testing */
  coap_address_init(&remote_addr);
  remote_addr.addr.sa.sa_family = AF_INET;
  memcpy(&remote_addr.addr.sin.sin_addr.s_addr,
         &data[size > 4 ? size - 4 : 0],
         size > 4 ? 4 : size);
  remote_addr.addr.sin.sin_port = htons(5683);

  coap_proto_t proto = COAP_PROTO_UDP;
  if (size >= 2) {
    if (data[0] & 0x10) {
      proto = COAP_PROTO_TCP;
#if !COAP_DISABLE_TCP
    } else if (data[0] & 0x08) {
      proto = COAP_PROTO_DTLS;
#endif
    }
  }

  session = coap_new_client_session(ctx, NULL, &remote_addr, proto);
  if (!session) {
    goto cleanup;
  }

  if (size >= 8 && session->proto == COAP_PROTO_UDP) {
    size_t msg_offset = size >= 16 ? 8 : 4;
    size_t msg_len = size - msg_offset;
    if (msg_len >= 4) {
      test_dgram_dispatch(ctx, session, data_copy + msg_offset, msg_len);
    }
  }

  if (size >= 16) {
    test_queue_operations(ctx, session, data + 1, size - 1);
  }

#if !COAP_DISABLE_TCP
  if (size >= 16) {
    test_reliable_transport(ctx, session, data_copy + 4, size - 4);
  }
#endif

  if (size >= 16) {
    test_session_operations(ctx, session, data, size);
  }

  if (size >= 32) {
    test_psk_config(ctx, data, size);
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
