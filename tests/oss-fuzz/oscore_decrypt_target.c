#include "coap3/coap_internal.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  coap_context_t *ctx;
  coap_session_t *session = NULL;
  coap_pdu_t *pdu = NULL, *decrypted = NULL;
  coap_address_t addr;
  size_t opt_len, encrypted_len;
  uint16_t partial_iv_len, kid_context_len, kid_len;
  uint8_t oscore_option[256];
  static const char oscore_conf_str[] =
      "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
      "master_salt,hex,\"9e7ca92223786340\"\n"
      "sender_id,hex,\"\"\n"
      "rfc8613_b_1_2,bool,false\n"
      "recipient_id,hex,\"01\"\n";

  if (size < 2)
    return 0;

  /* Initialize libcoap with OSCORE support */
  coap_startup();
  coap_set_log_level(COAP_LOG_ERR);
  coap_str_const_t conf = { sizeof(oscore_conf_str) - 1, (const uint8_t *)oscore_conf_str };
  coap_oscore_conf_t *oscore_conf = coap_new_oscore_conf(conf, NULL, NULL, 0);

  /* Stop transmission of any error packets */
  coap_debug_set_packet_loss("1-10");

  /* Set up OSCORE context */
  ctx = coap_new_context(NULL);
  if (ctx && oscore_conf) {
    if (coap_context_oscore_server(ctx, oscore_conf)) {
      /* Create a new client session */
      coap_address_init(&addr);
      addr.size = sizeof(struct sockaddr_in);
      addr.addr.sin.sin_family = AF_INET;
      addr.addr.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      addr.addr.sin.sin_port = htons(5683);

      session = coap_new_client_session(ctx, NULL, &addr, COAP_PROTO_UDP);

      /* Build PDU with OSCORE option and encrypted data from fuzzer data */
      if (session) {
        /* Calculate OSCORE option length based on RFC 8613 Section 6.1 */
        partial_iv_len = data[0] & 0x7;
        if (1UL + partial_iv_len > size)
          goto cleanup;

        kid_context_len = data[0] & 0x10 ? 1 + data[1 + partial_iv_len] : 0;
        /* 1s are byte 0 and kid length to be added */
        if (1UL + partial_iv_len + kid_context_len + 1 > size)
          goto cleanup;

        /* Build option with KID forced to one byte to match recipient_id in oscore_conf_str */
        kid_len = 1;
        opt_len = 1 + partial_iv_len + kid_context_len + kid_len;
        memcpy(oscore_option, data, opt_len - 1);
        oscore_option[opt_len - 1] = 0x01;

        pdu = coap_pdu_init(COAP_MESSAGE_NON, COAP_REQUEST_CODE_GET,
                            coap_new_message_id(session), 256);

        if (pdu) {
          /* Add OSCORE option with KID fixed to 0x01 */
          if (coap_add_option(pdu, COAP_OPTION_OSCORE, opt_len, oscore_option)) {
            /* Add remaining data as encrypted payload (from after original option) */
            encrypted_len = size - opt_len;
            if (encrypted_len > 0) {
              coap_add_data(pdu, encrypted_len, &data[opt_len]);
            }

            /* Test OSCORE decryption */
            decrypted = coap_oscore_decrypt_pdu(session, pdu);
            if (decrypted) {
              coap_show_pdu(COAP_LOG_ERR, decrypted);
              coap_delete_pdu(decrypted);
            }
          }
          coap_delete_pdu(pdu);
        }
cleanup:
        coap_session_release(session);
      }
    } else {
      /* coap_context_oscore_server failed, oscore_conf not consumed */
      coap_delete_oscore_conf(oscore_conf);
    }
  } else if (oscore_conf) {
    /* ctx creation failed, need to free oscore_conf */
    coap_delete_oscore_conf(oscore_conf);
  }

  if (ctx)
    coap_free_context(ctx);

  coap_cleanup();
  return 0;
}
