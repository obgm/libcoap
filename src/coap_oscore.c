/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/*
 * coap_oscore.c -- Object Security for Constrained RESTful Environments
 *                  (OSCORE) support for libcoap
 *
 * Copyright (C) 2019-2021 Olaf Bergmann <bergmann@tzi.org>
 * Copyright (C) 2021-2024 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_oscore.c
 * @brief CoAP OSCORE handling
 */

#include "coap3/coap_internal.h"

#if COAP_OSCORE_SUPPORT
#include <ctype.h>

#define AAD_BUF_LEN 200 /* length of aad_buffer */

static oscore_ctx_t *coap_oscore_init(coap_context_t *c_context,
                                      coap_oscore_conf_t *oscore_conf);

#if COAP_CLIENT_SUPPORT

int
coap_oscore_initiate(coap_session_t *session, coap_oscore_conf_t *oscore_conf) {
  if (oscore_conf) {
    oscore_ctx_t *osc_ctx;

    if (oscore_conf->recipient_id_count == 0) {
      coap_log_warn("OSCORE: Recipient ID must be defined for a client\n");
      return 0;
    }
    if (oscore_conf->rfc8613_b_2) {
      /* Need to replace id_context with random value */
      coap_binary_t *id_context = coap_new_binary(8);

      if (id_context == NULL)
        return 0;
      coap_delete_bin_const(oscore_conf->id_context);
      coap_prng(id_context->s, id_context->length);
      oscore_conf->id_context = (coap_bin_const_t *)id_context;
      session->b_2_step = COAP_OSCORE_B_2_STEP_1;
      coap_log_oscore("Appendix B.2 client step 1 (Generated ID1)\n");
    }

    osc_ctx = coap_oscore_init(session->context, oscore_conf);
    if (osc_ctx == NULL) {
      return 0;
    }
    session->recipient_ctx = osc_ctx->recipient_chain;
    session->oscore_encryption = 1;
  }
  return 1;
}

coap_session_t *
coap_new_client_session_oscore(coap_context_t *ctx,
                               const coap_address_t *local_if,
                               const coap_address_t *server,
                               coap_proto_t proto,
                               coap_oscore_conf_t *oscore_conf) {
  coap_session_t *session =
      coap_new_client_session(ctx, local_if, server, proto);

  if (!session)
    return NULL;

  if (coap_oscore_initiate(session, oscore_conf) == 0) {
    coap_session_release(session);
    return NULL;
  }
  return session;
}

coap_session_t *
coap_new_client_session_oscore_psk(coap_context_t *ctx,
                                   const coap_address_t *local_if,
                                   const coap_address_t *server,
                                   coap_proto_t proto,
                                   coap_dtls_cpsk_t *psk_data,
                                   coap_oscore_conf_t *oscore_conf) {
  coap_session_t *session;

  coap_lock_check_locked(ctx);
  session = coap_new_client_session_psk2(ctx, local_if, server, proto, psk_data);

  if (!session)
    return NULL;

  if (coap_oscore_initiate(session, oscore_conf) == 0) {
    coap_session_release(session);
    return NULL;
  }
  return session;
}

coap_session_t *
coap_new_client_session_oscore_pki(coap_context_t *ctx,
                                   const coap_address_t *local_if,
                                   const coap_address_t *server,
                                   coap_proto_t proto,
                                   coap_dtls_pki_t *pki_data,
                                   coap_oscore_conf_t *oscore_conf) {
  coap_session_t *session;

  coap_lock_check_locked(ctx);
  session = coap_new_client_session_pki(ctx, local_if, server, proto, pki_data);

  if (!session)
    return NULL;

  if (coap_oscore_initiate(session, oscore_conf) == 0) {
    coap_session_release(session);
    return NULL;
  }
  return session;
}
#endif /* COAP_CLIENT_SUPPORT */
#if COAP_SERVER_SUPPORT

int
coap_context_oscore_server(coap_context_t *context,
                           coap_oscore_conf_t *oscore_conf) {
  oscore_ctx_t *osc_ctx;

  coap_lock_check_locked(context);
  osc_ctx = coap_oscore_init(context, oscore_conf);
  /* osc_ctx already added to context->osc_ctx */
  if (osc_ctx)
    return 1;
  return 0;
}

#endif /* COAP_SERVER_SUPPORT */

int
coap_rebuild_pdu_for_proxy(coap_pdu_t *pdu) {
  coap_uri_t uri;
  coap_opt_iterator_t opt_iter;
  coap_opt_t *option;
  uint8_t option_value_buffer[15];
  uint8_t *keep_proxy_uri = NULL;

  if ((option =
           coap_check_option(pdu, COAP_OPTION_PROXY_URI, &opt_iter)) == NULL)
    return 1;

  /* Need to break down into the component parts, but keep data safe */
  memset(&uri, 0, sizeof(uri));
  keep_proxy_uri = coap_malloc_type(COAP_STRING, coap_opt_length(option));
  if (keep_proxy_uri == NULL)
    goto error;
  memcpy(keep_proxy_uri, coap_opt_value(option), coap_opt_length(option));

  if (coap_split_proxy_uri(keep_proxy_uri,
                           coap_opt_length(option),
                           &uri) < 0 || uri.scheme >= COAP_URI_SCHEME_LAST) {
    coap_log_warn("Proxy URI '%.*s' not decodable\n",
                  coap_opt_length(option),
                  (const char *)coap_opt_value(option));
    goto error;
  }
  if (!coap_remove_option(pdu, COAP_OPTION_PROXY_URI))
    goto error;

  if (!coap_insert_option(pdu,
                          COAP_OPTION_URI_HOST,
                          uri.host.length,
                          uri.host.s))
    goto error;
  if (uri.port != (coap_uri_scheme_is_secure(&uri) ? COAPS_DEFAULT_PORT : COAP_DEFAULT_PORT) &&
      !coap_insert_option(pdu,
                          COAP_OPTION_URI_PORT,
                          coap_encode_var_safe(option_value_buffer,
                                               sizeof(option_value_buffer),
                                               uri.port & 0xffff),
                          option_value_buffer))
    goto error;
  if (uri.path.length) {
    uint8_t *buf;
    uint8_t *kbuf;
    size_t buflen = uri.path.length + 1;
    int res;

    kbuf = buf = coap_malloc_type(COAP_STRING, uri.path.length + 1);
    if (buf) {
      res = coap_split_path(uri.path.s, uri.path.length, buf, &buflen);
      while (res--) {
        if (!coap_insert_option(pdu,
                                COAP_OPTION_URI_PATH,
                                coap_opt_length(buf),
                                coap_opt_value(buf))) {
          coap_free_type(COAP_STRING, buf);
          goto error;
        }
        buf += coap_opt_size(buf);
      }
    }
    coap_free_type(COAP_STRING, kbuf);
  }
  if (uri.query.length) {
    uint8_t *buf;
    size_t buflen = uri.query.length + 1;
    int res;

    buf = coap_malloc_type(COAP_STRING, uri.query.length + 1);
    if (buf) {
      res = coap_split_query(uri.query.s, uri.query.length, buf, &buflen);
      while (res--) {
        if (!coap_insert_option(pdu,
                                COAP_OPTION_URI_QUERY,
                                coap_opt_length(buf),
                                coap_opt_value(buf))) {
          coap_free_type(COAP_STRING, buf);
          goto error;
        }

        buf += coap_opt_size(buf);
      }
      coap_free_type(COAP_STRING, buf);
    }
  }
  if (!coap_insert_option(pdu,
                          COAP_OPTION_PROXY_SCHEME,
                          strlen(coap_uri_scheme[uri.scheme].name),
                          (const uint8_t *)coap_uri_scheme[uri.scheme].name))
    goto error;
  coap_free_type(COAP_STRING, keep_proxy_uri);
  return 1;

error:
  coap_free_type(COAP_STRING, keep_proxy_uri);
  return 0;
}

static void
dump_cose(cose_encrypt0_t *cose, const char *message) {
#if COAP_MAX_LOGGING_LEVEL < _COAP_LOG_OSCORE
  (void)cose;
  (void)message;
#else /* COAP_MAX_LOGGING_LEVEL >= _COAP_LOG_OSCORE */
  if (coap_get_log_level() >= COAP_LOG_OSCORE) {
    char buffer[30];

    coap_log_oscore("%s Cose information\n", message);
    oscore_log_char_value(COAP_LOG_OSCORE, "alg",
                          cose_get_alg_name(cose->alg, buffer, sizeof(buffer)));
    oscore_log_hex_value(COAP_LOG_OSCORE, "key", &cose->key);
    oscore_log_hex_value(COAP_LOG_OSCORE, "partial_iv", &cose->partial_iv);
    oscore_log_hex_value(COAP_LOG_OSCORE, "key_id", &cose->key_id);
    oscore_log_hex_value(COAP_LOG_OSCORE, "kid_context", &cose->kid_context);
    oscore_log_hex_value(COAP_LOG_OSCORE,
                         "oscore_option",
                         &cose->oscore_option);
    oscore_log_hex_value(COAP_LOG_OSCORE, "nonce", &cose->nonce);
    oscore_log_hex_value(COAP_LOG_OSCORE, "external_aad", &cose->external_aad);
    oscore_log_hex_value(COAP_LOG_OSCORE, "aad", &cose->aad);
  }
#endif /* COAP_MAX_LOGGING_LEVEL >= _COAP_LOG_OSCORE */
}

/*
 * Take current PDU, create a new one approriately separated as per RFC8613
 * and then encrypt / integrity check the OSCORE data
 */
coap_pdu_t *
coap_oscore_new_pdu_encrypted(coap_session_t *session,
                              coap_pdu_t *pdu,
                              coap_bin_const_t *kid_context,
                              oscore_partial_iv_t send_partial_iv) {
  uint8_t coap_request = COAP_PDU_IS_REQUEST(pdu) || COAP_PDU_IS_PING(pdu);
  coap_pdu_code_t code =
      coap_request ? COAP_REQUEST_CODE_POST : COAP_RESPONSE_CODE(204);
  coap_pdu_t *osc_pdu;
  coap_pdu_t *plain_pdu = NULL;
  coap_bin_const_t pdu_token;
  coap_opt_iterator_t opt_iter;
  coap_opt_t *option;
  uint8_t pdu_code = pdu->code;
  size_t length;
  const uint8_t *data;
  uint8_t *ciphertext_buffer = NULL;
  size_t ciphertext_len = 0;
  uint8_t aad_buffer[AAD_BUF_LEN];
  uint8_t nonce_buffer[13];
  coap_bin_const_t aad;
  coap_bin_const_t nonce;
  oscore_recipient_ctx_t *rcp_ctx = session->recipient_ctx;
  oscore_ctx_t *osc_ctx = rcp_ctx ? rcp_ctx->osc_ctx : NULL;
  cose_encrypt0_t cose[1];
  uint8_t group_flag = 0;
  int show_pdu = 0;
  int doing_observe = 0;
  uint32_t observe_value = 0;
  oscore_association_t *association = NULL;
  oscore_sender_ctx_t *snd_ctx = osc_ctx ? osc_ctx->sender_context : NULL;
  uint8_t external_aad_buffer[200];
  coap_bin_const_t external_aad;
  uint8_t oscore_option[48];
  size_t oscore_option_len;

  /* Check that OSCORE has not already been done */
  if (coap_check_option(pdu, COAP_OPTION_OSCORE, &opt_iter))
    return NULL;

  if (coap_check_option(pdu, COAP_OPTION_OBSERVE, &opt_iter))
    doing_observe = 1;

  coap_log_debug("PDU to encrypt\n");
  coap_show_pdu(COAP_LOG_DEBUG, pdu);
  osc_pdu = coap_pdu_init(pdu->type == COAP_MESSAGE_NON &&
                          session->b_2_step != COAP_OSCORE_B_2_NONE ?
                          COAP_MESSAGE_CON : pdu->type,
                          code,
                          pdu->mid,
                          pdu->used_size + coap_oscore_overhead(session, pdu));
  if (osc_pdu == NULL)
    return NULL;

  cose_encrypt0_init(cose); /* clears cose memory */
  pdu_token = coap_pdu_get_token(pdu);
  if (coap_request) {
    /*
     * RFC8613 8.1 Step 1. Protecting the client's request
     * Get the Sender Context
     */
    rcp_ctx = session->recipient_ctx;
    if (rcp_ctx == NULL)
      goto error;
    osc_ctx = rcp_ctx->osc_ctx;
    snd_ctx = osc_ctx->sender_context;
  } else {
    /*
     * RFC8613 8.3 Step 1. Protecting the server's response
     * Get the Sender Context
     */
    association = oscore_find_association(session, &pdu_token);
    if (association == NULL)
      goto error;

    rcp_ctx = association->recipient_ctx;
    osc_ctx = rcp_ctx->osc_ctx;
    snd_ctx = osc_ctx->sender_context;
    cose_encrypt0_set_partial_iv(cose, association->partial_iv);
    cose_encrypt0_set_aad(cose, association->aad);
  }

  cose_encrypt0_set_alg(cose, osc_ctx->aead_alg);

  if (coap_request || doing_observe ||
      send_partial_iv == OSCORE_SEND_PARTIAL_IV) {
    uint8_t partial_iv_buffer[8];
    size_t partial_iv_len;
    coap_bin_const_t partial_iv;
    partial_iv_len = coap_encode_var_safe8(partial_iv_buffer,
                                           sizeof(partial_iv_buffer),
                                           snd_ctx->seq);
    if (snd_ctx->seq == 0) {
      /* Need to special case */
      partial_iv_buffer[0] = '\000';
      partial_iv_len = 1;
    }
    partial_iv.s = partial_iv_buffer;
    partial_iv.length = partial_iv_len;
    cose_encrypt0_set_partial_iv(cose, &partial_iv);
  }

  if (coap_request)
    cose_encrypt0_set_kid_context(cose, osc_ctx->id_context);

  cose_encrypt0_set_key_id(cose, snd_ctx->sender_id);

  /* nonce (needs to have sender information correctly set up) */

  if (coap_request || doing_observe ||
      send_partial_iv == OSCORE_SEND_PARTIAL_IV) {
    /*
     *  8.1 Step 3 or RFC8613 8.3.1 Step A
     * Compose the AEAD nonce
     *
     * Requires in COSE object as appropriate
     *   key_id (kid) (sender)
     *   partial_iv   (sender)
     *   common_iv    (already in osc_ctx)
     */
    nonce.s = nonce_buffer;
    nonce.length = 13;
    oscore_generate_nonce(cose, osc_ctx, nonce_buffer, 13);
    cose_encrypt0_set_nonce(cose, &nonce);
    if (!oscore_increment_sender_seq(osc_ctx))
      goto error;
    if (osc_ctx->save_seq_num_func) {
      if (osc_ctx->sender_context->seq > osc_ctx->sender_context->next_seq) {
        /* Only update at ssn_freq rate */
        osc_ctx->sender_context->next_seq += osc_ctx->ssn_freq;
        osc_ctx->save_seq_num_func(osc_ctx->sender_context->next_seq,
                                   osc_ctx->save_seq_num_func_param);
      }
    }
  } else {
    /*
     * 8.3 Step 3.
     * Use nonce from request
     */
    cose_encrypt0_set_nonce(cose, association->nonce);
  }

  /* OSCORE_option (needs to be before AAD as included in AAD if group) */

  /* cose is modified for encode option in response message */
  if (!coap_request) {
    /* no kid on response */
    cose_encrypt0_set_key_id(cose, NULL);
    if (!doing_observe && send_partial_iv == OSCORE_SEND_NO_IV)
      cose_encrypt0_set_partial_iv(cose, NULL);
  }
  if (kid_context) {
    cose_encrypt0_set_kid_context(cose, kid_context);
  }
  oscore_option_len =
      oscore_encode_option_value(oscore_option, sizeof(oscore_option), cose,
                                 group_flag,
                                 session->b_2_step != COAP_OSCORE_B_2_NONE);
  if (!coap_request) {
    /* Reset what was just unset as appropriate for AAD */
    cose_encrypt0_set_key_id(cose, rcp_ctx->recipient_id);
    cose_encrypt0_set_partial_iv(cose, association->partial_iv);
  }
  if (kid_context)
    cose_encrypt0_set_kid_context(cose, osc_ctx->id_context);

  /*
   * RFC8613 8.1/8.3 Step 2(a) (5.4).
   * Compose the External AAD and then AAD
   *
   * OSCORE_option requires
   *  partial_iv                  (cose partial_iv)
   *  kid_context                 (cose kid_context)
   *  key_id                      (cose key_id)
   *  group_flag
   *
   * Non Group (based on osc_tx->mode) requires the following
   *   aead_alg                   (osc_ctx)
   *   request_kid                (request key_id using cose)
   *   request_piv                (request partial_iv using cose)
   *   options                    (none at present)
   * Group (based on osc_tx->mode) requires the following
   *   aead_alg                   (osc_ctx) (pairwise mode)
   *   sign_enc_alg               (osc_ctx) (group mode)
   *   sign_alg                   (osc_ctx) (group mode)
   *   alg_pairwise_key_agreement (osc_ctx) (pairwise mode)
   *   request_kid                (request key_id using cose)
   *   request_piv                (request partial_iv using cose)
   *   options                    (none at present)
   *   request_kid_context        (osc_ctx id_context)
   *   OSCORE_option              (parameter)
   *   test_gs_public_key         (osc_ctx sender_context public_key)
   *   gm_public_key              (osc_ctx gm_public_key)
   *
   * Note: No I options at present
   */
  if (coap_request || osc_ctx->mode != OSCORE_MODE_SINGLE ||
      send_partial_iv == OSCORE_SEND_PARTIAL_IV) {
    /* External AAD */
    external_aad.s = external_aad_buffer;
    external_aad.length = oscore_prepare_e_aad(osc_ctx,
                                               cose,
                                               NULL,
                                               0,
                                               NULL,
                                               external_aad_buffer,
                                               sizeof(external_aad_buffer));
    cose_encrypt0_set_external_aad(cose, &external_aad);

    /* AAD */
    aad.s = aad_buffer;
    aad.length = oscore_prepare_aad(external_aad_buffer,
                                    external_aad.length,
                                    aad_buffer,
                                    sizeof(aad_buffer));
    assert(aad.length < AAD_BUF_LEN);
    cose_encrypt0_set_aad(cose, &aad);
  }

  /*
   * RFC8613 8.1/8.3 Step 2(b) (5.3).
   *
   * Set up temp plaintext pdu, the data including token, options and
   * optional payload will get encrypted as COSE ciphertext.
   */
  plain_pdu = coap_pdu_init(pdu->type,
                            pdu->code,
                            pdu->mid,
                            pdu->used_size + 1 /* pseudo-token with actual code */);
  if (plain_pdu == NULL)
    goto error;

  coap_add_token(osc_pdu, pdu_token.length, pdu_token.s);

  /* First byte of plain is real CoAP code.  Pretend it is token */
  coap_add_token(plain_pdu, 1, &pdu_code);

  /* Copy across the Outer/Inner Options to respective PDUs */
  coap_option_iterator_init(pdu, &opt_iter, COAP_OPT_ALL);
  while ((option = coap_option_next(&opt_iter))) {
    switch (opt_iter.number) {
    case COAP_OPTION_URI_HOST:
    case COAP_OPTION_URI_PORT:
    case COAP_OPTION_PROXY_SCHEME:
    case COAP_OPTION_HOP_LIMIT:
      /* Outer only */
      if (!coap_insert_option(osc_pdu,
                              opt_iter.number,
                              coap_opt_length(option),
                              coap_opt_value(option)))
        goto error;
      break;
    case COAP_OPTION_OBSERVE:
      /* Make as Outer option as-is */
      if (!coap_insert_option(osc_pdu,
                              opt_iter.number,
                              coap_opt_length(option),
                              coap_opt_value(option)))
        goto error;
      if (coap_request) {
        /* Make as Inner option (unchanged) */
        if (!coap_insert_option(plain_pdu,
                                opt_iter.number,
                                coap_opt_length(option),
                                coap_opt_value(option)))
          goto error;
        osc_pdu->code = COAP_REQUEST_CODE_FETCH;
      } else {
        /* Make as Inner option but empty */
        if (!coap_insert_option(plain_pdu, opt_iter.number, 0, NULL))
          goto error;
        osc_pdu->code = COAP_RESPONSE_CODE(205);
      }
      show_pdu = 1;
      doing_observe = 1;
      observe_value = coap_decode_var_bytes(coap_opt_value(option),
                                            coap_opt_length(option));
      break;
    case COAP_OPTION_PROXY_URI:
      /*
       * Should have already been caught by doing
       * coap_rebuild_pdu_for_proxy() before calling
       * coap_oscore_new_pdu_encrypted()
       */
      assert(0);
      break;
    default:
      /* Make as Inner option */
      if (!coap_insert_option(plain_pdu,
                              opt_iter.number,
                              coap_opt_length(option),
                              coap_opt_value(option)))
        goto error;
      break;
    }
  }
  /* Add in data to plain */
  if (coap_get_data(pdu, &length, &data)) {
    if (!coap_add_data(plain_pdu, length, data))
      goto error;
  }
  if (show_pdu) {
    coap_log_oscore("OSCORE payload\n");
    coap_show_pdu(COAP_LOG_OSCORE, plain_pdu);
  }

  /*
   * 8.1/8.3 Step 4.
   * Encrypt the COSE object.
   *
   * Requires in COSE object as appropriate
   *   alg   (already set)
   *   key   (sender key)
   *   nonce (already set)
   *   aad   (already set)
   *   plaintext
   */
  cose_encrypt0_set_key(cose, snd_ctx->sender_key);
  cose_encrypt0_set_plaintext(cose, plain_pdu->token, plain_pdu->used_size);
  dump_cose(cose, "Pre encrypt");
  ciphertext_buffer =
      coap_malloc_type(COAP_OSCORE_BUF, OSCORE_CRYPTO_BUFFER_SIZE);
  if (ciphertext_buffer == NULL)
    goto error;
  ciphertext_len = cose_encrypt0_encrypt(cose,
                                         ciphertext_buffer,
                                         plain_pdu->used_size + AES_CCM_TAG);
  if ((int)ciphertext_len <= 0) {
    coap_log_warn("OSCORE: Encryption Failure, result code: %d \n",
                  (int)ciphertext_len);
    goto error;
  }
  assert(ciphertext_len < OSCORE_CRYPTO_BUFFER_SIZE);

  /* Add in OSCORE option (previously computed) */
  if (!coap_insert_option(osc_pdu,
                          COAP_OPTION_OSCORE,
                          oscore_option_len,
                          oscore_option))
    goto error;

  /* Add now encrypted payload */
  if (!coap_add_data(osc_pdu, ciphertext_len, ciphertext_buffer))
    goto error;

  coap_free_type(COAP_OSCORE_BUF, ciphertext_buffer);
  ciphertext_buffer = NULL;

  coap_delete_pdu(plain_pdu);
  plain_pdu = NULL;

  if (association && association->is_observe == 0)
    oscore_delete_association(session, association);
  association = NULL;

  /*
   * If this is a response ACK with data, make it a separate response
   * by sending an Empty ACK and changing osc_pdu's MID and type.  This
   * then allows lost response ACK with data to be recovered.
   */
  if (coap_request == 0 && osc_pdu->type == COAP_MESSAGE_ACK &&
      COAP_PROTO_NOT_RELIABLE(session->proto)) {
    coap_pdu_t *empty = coap_pdu_init(COAP_MESSAGE_ACK,
                                      0,
                                      osc_pdu->mid,
                                      0);
    if (empty) {
      if (coap_send_internal(session, empty) != COAP_INVALID_MID) {
        osc_pdu->mid = coap_new_message_id(session);
        osc_pdu->type = COAP_MESSAGE_CON;
      }
    }
  }

  if (!coap_pdu_encode_header(osc_pdu, session->proto)) {
    goto error;
  }

  /*
   * Set up an association for handling a response if this is a request
   */
  if (coap_request) {
    association = oscore_find_association(session, &pdu_token);
    if (association) {
      if (doing_observe && observe_value == 1) {
        association->is_observe = 0;
      }
      /* Refresh the association */
      coap_delete_bin_const(association->nonce);
      association->nonce =
          coap_new_bin_const(cose->nonce.s, cose->nonce.length);
      if (association->nonce == NULL)
        goto error;
      coap_delete_bin_const(association->aad);
      association->aad = coap_new_bin_const(cose->aad.s, cose->aad.length);
      if (association->aad == NULL)
        goto error;
      coap_delete_bin_const(association->partial_iv);
      association->partial_iv =
          coap_new_bin_const(cose->partial_iv.s, cose->partial_iv.length);
      if (association->partial_iv == NULL)
        goto error;
      association->recipient_ctx = rcp_ctx;
      coap_delete_pdu(association->sent_pdu);
      if (session->b_2_step != COAP_OSCORE_B_2_NONE) {
        size_t size;

        association->sent_pdu = coap_pdu_duplicate(pdu, session,
                                                   pdu_token.length,
                                                   pdu_token.s, NULL);
        if (association->sent_pdu == NULL)
          goto error;
        if (coap_get_data(pdu, &size, &data)) {
          coap_add_data(association->sent_pdu, size, data);
        }
      } else {
        association->sent_pdu = NULL;
      }
    } else if (!oscore_new_association(session,
                                       session->b_2_step != COAP_OSCORE_B_2_NONE ? pdu : NULL,
                                       &pdu_token,
                                       rcp_ctx,
                                       &cose->aad,
                                       &cose->nonce,
                                       &cose->partial_iv,
                                       doing_observe)) {
      goto error;
    }
  }
  return osc_pdu;

error:
  if (ciphertext_buffer)
    coap_free_type(COAP_OSCORE_BUF, ciphertext_buffer);
  coap_delete_pdu(osc_pdu);
  coap_delete_pdu(plain_pdu);
  return NULL;
}

static void
build_and_send_error_pdu(coap_session_t *session,
                         coap_pdu_t *rcvd,
                         coap_pdu_code_t code,
                         const char *diagnostic,
                         uint8_t *echo_data,
                         coap_bin_const_t *kid_context,
                         int encrypt_oscore) {
  coap_pdu_t *err_pdu = NULL;
  coap_bin_const_t token;
  int oscore_encryption = session->oscore_encryption;
  unsigned char buf[4];

  token = coap_pdu_get_token(rcvd);
  err_pdu = coap_pdu_init(rcvd->type == COAP_MESSAGE_NON ? COAP_MESSAGE_NON :
                          COAP_MESSAGE_ACK,
                          code,
                          rcvd->mid,
                          token.length + 2 + 8 +
                          (diagnostic ? strlen(diagnostic) : 0));
  if (!err_pdu)
    return;
  coap_add_token(err_pdu, token.length, token.s);
  if (echo_data) {
    coap_add_option_internal(err_pdu, COAP_OPTION_ECHO, 8, echo_data);
  } else if (kid_context == NULL) {
    coap_add_option_internal(err_pdu,
                             COAP_OPTION_MAXAGE,
                             coap_encode_var_safe(buf, sizeof(buf), 0),
                             buf);
  }
  if (diagnostic)
    coap_add_data(err_pdu, strlen(diagnostic), (const uint8_t *)diagnostic);
  session->oscore_encryption = encrypt_oscore;

  if ((echo_data || kid_context) && encrypt_oscore) {
    coap_pdu_t *osc_pdu;

    osc_pdu =
        coap_oscore_new_pdu_encrypted(session, err_pdu, kid_context,
                                      echo_data ? 1 : 0);
    if (!osc_pdu)
      goto fail_resp;
    session->oscore_encryption = 0;
    coap_send_internal(session, osc_pdu);
    coap_delete_pdu(err_pdu);
    err_pdu = NULL;
  } else {
    coap_send_internal(session, err_pdu);
    err_pdu = NULL;
  }
fail_resp:
  session->oscore_encryption = oscore_encryption;
  coap_delete_pdu(err_pdu);
  return;
}

/* pdu contains incoming message with encrypted COSE ciphertext payload
 * function returns decrypted message
 * and verifies signature, if present
 * returns NULL when decryption,verification fails
 */
coap_pdu_t *
coap_oscore_decrypt_pdu(coap_session_t *session,
                        coap_pdu_t *pdu) {
  coap_pdu_t *decrypt_pdu = NULL;
  coap_pdu_t *plain_pdu = NULL;
  const uint8_t *osc_value; /* value of OSCORE option */
  uint8_t osc_size;         /* size of OSCORE OPTION */
  coap_opt_iterator_t opt_iter;
  coap_opt_t *opt = NULL;
  cose_encrypt0_t cose[1];
  oscore_ctx_t *osc_ctx = NULL;
  uint8_t aad_buffer[AAD_BUF_LEN];
  uint8_t nonce_buffer[13];
  coap_bin_const_t aad;
  coap_bin_const_t nonce;
  int pltxt_size = 0;
  uint8_t coap_request = COAP_PDU_IS_REQUEST(pdu);
  coap_bin_const_t pdu_token;
  uint8_t *st_encrypt;
  size_t encrypt_len;
  size_t tag_len;
  oscore_recipient_ctx_t *rcp_ctx = NULL;
  oscore_association_t *association = NULL;
  uint8_t external_aad_buffer[100];
  coap_bin_const_t external_aad;
  oscore_sender_ctx_t *snd_ctx = NULL;
#if COAP_CLIENT_SUPPORT
  coap_pdu_t *sent_pdu = NULL;
#endif /* COAP_CLIENT_SUPPORT */

  opt = coap_check_option(pdu, COAP_OPTION_OSCORE, &opt_iter);
  assert(opt);
  if (opt == NULL)
    return NULL;

  if (session->context->p_osc_ctx == NULL) {
    coap_log_warn("OSCORE: Not enabled\n");
    if (!coap_request)
      coap_handle_event(session->context,
                        COAP_EVENT_OSCORE_NOT_ENABLED,
                        session);
    return NULL;
  }

  if (pdu->data == NULL) {
    coap_log_warn("OSCORE: No protected payload\n");
    if (!coap_request)
      coap_handle_event(session->context,
                        COAP_EVENT_OSCORE_NO_PROTECTED_PAYLOAD,
                        session);
    return NULL;
  }

  osc_size = coap_opt_length(opt);
  osc_value = coap_opt_value(opt);

  cose_encrypt0_init(cose); /* clear cose memory */

  /* PDU code will be filled in after decryption */
  decrypt_pdu =
      coap_pdu_init(pdu->type, 0, pdu->mid, pdu->used_size);
  if (decrypt_pdu == NULL) {
    if (!coap_request)
      coap_handle_event(session->context,
                        COAP_EVENT_OSCORE_INTERNAL_ERROR,
                        session);
    goto error;
  }

  /* Copy across the Token */
  pdu_token = coap_pdu_get_token(pdu);
  coap_add_token(decrypt_pdu, pdu_token.length, pdu_token.s);

  /*
   * 8.2/8.4 Step 1.
   * Copy outer options across, except E and OSCORE options
   */
  coap_option_iterator_init(pdu, &opt_iter, COAP_OPT_ALL);
  while ((opt = coap_option_next(&opt_iter))) {
    switch (opt_iter.number) {
    /* 'E' options skipped */
    case COAP_OPTION_IF_MATCH:
    case COAP_OPTION_ETAG:
    case COAP_OPTION_IF_NONE_MATCH:
    case COAP_OPTION_OBSERVE:
    case COAP_OPTION_LOCATION_PATH:
    case COAP_OPTION_URI_PATH:
    case COAP_OPTION_CONTENT_FORMAT:
    case COAP_OPTION_MAXAGE:
    case COAP_OPTION_URI_QUERY:
    case COAP_OPTION_ACCEPT:
    case COAP_OPTION_LOCATION_QUERY:
    case COAP_OPTION_BLOCK2:
    case COAP_OPTION_BLOCK1:
    case COAP_OPTION_SIZE2:
    case COAP_OPTION_SIZE1:
    case COAP_OPTION_NORESPONSE:
    case COAP_OPTION_ECHO:
    case COAP_OPTION_RTAG:
    /* OSCORE does not get copied across */
    case COAP_OPTION_OSCORE:
      break;
    default:
      if (!coap_add_option_internal(decrypt_pdu,
                                    opt_iter.number,
                                    coap_opt_length(opt),
                                    coap_opt_value(opt))) {
        if (!coap_request)
          coap_handle_event(session->context,
                            COAP_EVENT_OSCORE_INTERNAL_ERROR,
                            session);
        goto error;
      }
      break;
    }
  }

  if (coap_request) {
    uint64_t incoming_seq;
    /*
     * 8.2 Step 2
     * Decompress COSE object
     * Get Recipient Context based on kid and optional kid_context
     */
    if (oscore_decode_option_value(osc_value, osc_size, cose) == 0) {
      coap_log_warn("OSCORE: OSCORE Option cannot be decoded.\n");
      build_and_send_error_pdu(session,
                               pdu,
                               COAP_RESPONSE_CODE(402),
                               "Failed to decode COSE",
                               NULL,
                               NULL,
                               0);
      goto error_no_ack;
    }
    osc_ctx = oscore_find_context(session->context,
                                  cose->key_id,
                                  &cose->kid_context,
                                  NULL,
                                  &rcp_ctx);
    if (!osc_ctx) {
      if (cose->kid_context.length > 0) {
        const uint8_t *ptr;
        size_t length;
        /* Appendix B.2 protocol check - Is the recipient key_id known */
        osc_ctx = oscore_find_context(session->context,
                                      cose->key_id,
                                      NULL,
                                      session->oscore_r2 != 0 ? (uint8_t *)&session->oscore_r2 : NULL,
                                      &rcp_ctx);
        ptr = cose->kid_context.s;
        length = cose->kid_context.length;
        if (ptr && osc_ctx && osc_ctx->rfc8613_b_2 &&
            osc_ctx->mode == OSCORE_MODE_SINGLE) {
          /* Processing Appendix B.2 protocol */
          /* Need to CBOR unwrap kid_context */
          coap_bin_const_t kid_context;

          kid_context.length = oscore_cbor_get_element_size(&ptr, &length);
          kid_context.s = ptr;
          cose_encrypt0_set_kid_context(cose, (coap_bin_const_t *)&kid_context);

          if (session->oscore_r2 != 0) {
            /* B.2 step 4 */
            coap_bin_const_t *kc = coap_new_bin_const(cose->kid_context.s,
                                                      cose->kid_context.length);

            if (kc == NULL)
              goto error;

            session->b_2_step = COAP_OSCORE_B_2_STEP_4;
            coap_log_oscore("Appendix B.2 server step 4 (R2 || R3)\n");
            oscore_update_ctx(osc_ctx, kc);
          } else {
            session->b_2_step = COAP_OSCORE_B_2_STEP_2;
            coap_log_oscore("Appendix B.2 server step 2 (ID1)\n");
            osc_ctx = oscore_duplicate_ctx(session->context,
                                           osc_ctx,
                                           osc_ctx->sender_context->sender_id,
                                           &cose->key_id,
                                           &cose->kid_context);
            if (osc_ctx == NULL)
              goto error;
            /*
             * Complete the Verify (B.2 step 2)
             * before sending back the response
             */
            rcp_ctx = osc_ctx->recipient_chain;
          }
        } else {
          osc_ctx = NULL;
        }
      }
    } else if (session->b_2_step != COAP_OSCORE_B_2_NONE) {
      session->b_2_step = COAP_OSCORE_B_2_NONE;
      coap_log_oscore("Appendix B.2 server finished\n");
    }
    if (!osc_ctx) {
      coap_log_crit("OSCORE: Security Context not found\n");
      oscore_log_hex_value(COAP_LOG_OSCORE, "key_id", &cose->key_id);
      oscore_log_hex_value(COAP_LOG_OSCORE, "kid_context", &cose->kid_context);
      build_and_send_error_pdu(session,
                               pdu,
                               COAP_RESPONSE_CODE(401),
                               "Security context not found",
                               NULL,
                               NULL,
                               0);
      goto error_no_ack;
    }
    /* to be used for encryption of returned response later */
    session->recipient_ctx = rcp_ctx;
    snd_ctx = osc_ctx->sender_context;

    /*
     * 8.2 Step 3.
     * Verify Partial IV is not duplicated.
     *
     * Requires in COSE object as appropriate
     *   partial_iv (as received)
     */
    if (rcp_ctx->initial_state == 0 &&
        !oscore_validate_sender_seq(rcp_ctx, cose)) {
      coap_log_warn("OSCORE: Replayed or old message\n");
      build_and_send_error_pdu(session,
                               pdu,
                               COAP_RESPONSE_CODE(401),
                               "Replay detected",
                               NULL,
                               NULL,
                               0);
      goto error_no_ack;
    }

    incoming_seq =
        coap_decode_var_bytes8(cose->partial_iv.s, cose->partial_iv.length);
    rcp_ctx->last_seq = incoming_seq;
  } else { /* !coap_request */
    /*
     * 8.4 Step 2
     * Decompress COSE object
     * Get Recipient Context based on token
     */
    if (oscore_decode_option_value(osc_value, osc_size, cose) == 0) {
      coap_log_warn("OSCORE: OSCORE Option cannot be decoded.\n");
      coap_handle_event(session->context,
                        COAP_EVENT_OSCORE_DECODE_ERROR,
                        session);
      goto error;
    }
    association = oscore_find_association(session, &pdu_token);
    if (association) {
      rcp_ctx = association->recipient_ctx;
      osc_ctx = rcp_ctx->osc_ctx;
      snd_ctx = osc_ctx->sender_context;
#if COAP_CLIENT_SUPPORT
      sent_pdu = association->sent_pdu;
      if (session->b_2_step != COAP_OSCORE_B_2_NONE) {
        const uint8_t *ptr = cose->kid_context.s;
        size_t length = cose->kid_context.length;

        if (ptr) {
          /* Need to CBOR unwrap kid_context */
          coap_bin_const_t kid_context;

          kid_context.length = oscore_cbor_get_element_size(&ptr, &length);
          kid_context.s = ptr;
          cose_encrypt0_set_kid_context(cose, &kid_context);
        }
        if (ptr && !coap_binary_equal(osc_ctx->id_context, &cose->kid_context)) {
          /* If Appendix B.2 step 3 is in operation */
          /* Need to update Security Context with new (R2 || ID1) ID Context */
          coap_binary_t *kc = coap_new_binary(cose->kid_context.length +
                                              osc_ctx->id_context->length);

          if (kc == NULL) {
            coap_handle_event(session->context,
                              COAP_EVENT_OSCORE_INTERNAL_ERROR,
                              session);
            goto error;
          }

          memcpy(kc->s, cose->kid_context.s, cose->kid_context.length);
          memcpy(&kc->s[cose->kid_context.length],
                 osc_ctx->id_context->s,
                 osc_ctx->id_context->length);

          session->b_2_step = COAP_OSCORE_B_2_STEP_3;
          coap_log_oscore("Appendix B.2 client step 3 (R2 || ID1)\n");
          oscore_update_ctx(osc_ctx, (coap_bin_const_t *)kc);
        } else {
          session->b_2_step = COAP_OSCORE_B_2_STEP_5;
          coap_log_oscore("Appendix B.2 client step 5 (R2 || R3)\n");
        }
      }
#endif /* COAP_CLIENT_SUPPORT */
    } else {
      coap_log_crit("OSCORE: Security Context association not found\n");
      coap_handle_event(session->context,
                        COAP_EVENT_OSCORE_NO_SECURITY,
                        session);
      goto error;
    }
  }

  cose_encrypt0_set_alg(cose, osc_ctx->aead_alg);

  if (coap_request) {
    /*
     * RFC8613 8.2 Step 4.
     * Compose the External AAD and then AAD
     *
     * Non Group (based on osc_tx->mode) requires the following
     *   aead_alg                   (osc_ctx)
     *   request_kid                (request key_id using cose)
     *   request_piv                (request partial_iv using cose)
     *   options                    (none at present)
     * Group (based on osc_tx->mode) requires the following
     *   aead_alg                   (osc_ctx) (pairwise mode)
     *   sign_enc_alg               (osc_ctx) (group mode)
     *   sign_alg                   (osc_ctx) (group mode)
     *   alg_pairwise_key_agreement (osc_ctx) (pairwise mode)
     *   request_kid                (request key_id using cose)
     *   request_piv                (request partial_iv using cose)
     *   options                    (none at present)
     *   request_kid_context        (osc_ctx id_context)
     *   OSCORE_option              (as received in request)
     *   test_gs_public_key         (recipient public key)
     *   gm_public_key              (osc_ctx gm_public_key)
     *
     * Note: No I options at present
     */

    /* External AAD */
    external_aad.s = external_aad_buffer;
    external_aad.length = oscore_prepare_e_aad(osc_ctx,
                                               cose,
                                               osc_value,
                                               osc_size,
                                               NULL,
                                               external_aad_buffer,
                                               sizeof(external_aad_buffer));
    cose_encrypt0_set_external_aad(cose, &external_aad);

    /* AAD */
    aad.s = aad_buffer;
    aad.length = oscore_prepare_aad(external_aad_buffer,
                                    external_aad.length,
                                    aad_buffer,
                                    sizeof(aad_buffer));
    assert(aad.length < AAD_BUF_LEN);
    cose_encrypt0_set_aad(cose, &aad);

    /*
     * RFC8613 8.2 Step 5.
     * Compute the AEAD nonce.
     *
     * Requires in COSE object as appropriate
     *   key_id (kid) (Recipient ID)
     *   partial_iv   (as received in request)
     *   common_iv    (already in osc_ctx)
     */
    nonce.s = nonce_buffer;
    nonce.length = 13;
    oscore_generate_nonce(cose, osc_ctx, nonce_buffer, 13);
    cose_encrypt0_set_nonce(cose, &nonce);
    /*
     * Set up an association for use in the response
     */
    association = oscore_find_association(session, &pdu_token);
    if (association) {
      /* Refresh the association */
      coap_delete_bin_const(association->nonce);
      association->nonce =
          coap_new_bin_const(cose->nonce.s, cose->nonce.length);
      if (association->nonce == NULL)
        goto error;
      coap_delete_bin_const(association->partial_iv);
      association->partial_iv =
          coap_new_bin_const(cose->partial_iv.s, cose->partial_iv.length);
      if (association->partial_iv == NULL)
        goto error;
      coap_delete_bin_const(association->aad);
      association->aad = coap_new_bin_const(cose->aad.s, cose->aad.length);
      if (association->aad == NULL)
        goto error;
      association->recipient_ctx = rcp_ctx;
    } else if (!oscore_new_association(session,
                                       NULL,
                                       &pdu_token,
                                       rcp_ctx,
                                       &cose->aad,
                                       &cose->nonce,
                                       &cose->partial_iv,
                                       0)) {
      goto error;
    }
    /* So association is not released when handling decrypt */
    association = NULL;
  } else { /* ! coap_request */
    /* Need to do nonce before AAD because of different partial_iv */
    /*
     * 8.4 Step 4.
     * Compose the AEAD nonce.
     */
    cose_encrypt0_set_key_id(cose, rcp_ctx->recipient_id);
    if (cose->partial_iv.length == 0) {
      cose_encrypt0_set_partial_iv(cose, association->partial_iv);
      cose_encrypt0_set_nonce(cose, association->nonce);
    } else {
      uint64_t last_seq;

      if (rcp_ctx->initial_state == 0 &&
          !oscore_validate_sender_seq(rcp_ctx, cose)) {
        coap_log_warn("OSCORE: Replayed or old message\n");
        goto error;
      }
      last_seq =
          coap_decode_var_bytes8(cose->partial_iv.s, cose->partial_iv.length);
      if (rcp_ctx->last_seq>= OSCORE_SEQ_MAX) {
        coap_log_warn("OSCORE Replay protection, SEQ larger than SEQ_MAX.\n");
        goto error;
      }
      if (last_seq > rcp_ctx->last_seq)
        rcp_ctx->last_seq = last_seq;
      /*
       * Requires in COSE object as appropriate
       *   kid (set above)
       *   partial_iv (as received)
       *   common_iv (already in osc_ctx)
       */
      oscore_generate_nonce(cose, osc_ctx, nonce_buffer, 13);
      nonce.s = nonce_buffer;
      nonce.length = 13;
      cose_encrypt0_set_nonce(cose, &nonce);
    }
#ifdef OSCORE_EXTRA_DEBUG
    dump_cose(cose, "!req post set nonce");
#endif /* OSCORE_EXTRA_DEBUG */
    /*
     * 8.4 Step 3.
     * Compose the External AAD and then AAD (same as request non-group (5.4)
     *
     * Non Group (based on osc_tx->mode) requires the following
     *   aead_alg                   (osc_ctx)
     *   request_kid                (request key_id using cose)
     *   request_piv                (request partial_iv using cose)
     *   options                    (none at present)
     * Group (based on osc_tx->mode) requires the following
     *   aead_alg                   (osc_ctx) (pairwise mode)
     *   sign_enc_alg               (osc_ctx) (group mode)
     *   sign_alg                   (osc_ctx) (group mode)
     *   alg_pairwise_key_agreement (osc_ctx) (pairwise mode)
     *   request_kid                (request key_id using cose)
     *   request_piv                (request partial_iv using cose)
     *   options                    (none at present)
     *   request_kid_context        (osc_ctx id_context)
     *   OSCORE_option              (as received in request)
     *   test_gs_public_key         (recipient public key)
     *   gm_public_key              (osc_ctx gm_public_key)
     *
     * Note: No I options at present
     */

    /* External AAD */
    cose_encrypt0_set_key_id(cose, snd_ctx->sender_id);
    cose_encrypt0_set_partial_iv(cose, association->partial_iv);
#ifdef OSCORE_EXTRA_DEBUG
    dump_cose(cose, "!req pre aad");
#endif /* OSCORE_EXTRA_DEBUG */
    external_aad.s = external_aad_buffer;
    external_aad.length = oscore_prepare_e_aad(osc_ctx,
                                               cose,
                                               NULL,
                                               0,
                                               NULL,
                                               external_aad_buffer,
                                               sizeof(external_aad_buffer));
    cose_encrypt0_set_external_aad(cose, &external_aad);

    /* AAD */
    aad.s = aad_buffer;
    aad.length = oscore_prepare_aad(external_aad_buffer,
                                    external_aad.length,
                                    aad_buffer,
                                    sizeof(aad_buffer));
    assert(aad.length < AAD_BUF_LEN);
    cose_encrypt0_set_aad(cose, &aad);
#ifdef OSCORE_EXTRA_DEBUG
    dump_cose(cose, "!req post set aad");
#endif /* OSCORE_EXTRA_DEBUG */
  }

  /*
   * 8.2 Step 6 / 8.4 Step 5.
   * Decrypt the COSE object.
   *
   * Requires in COSE object as appropriate
   *   alg   (already set)
   *   key
   *   nonce (already set)
   *   aad   (already set)
   *   ciphertext
   */
  st_encrypt = pdu->data;
  encrypt_len = pdu->used_size - (pdu->data - pdu->token);
  if (encrypt_len <= 0) {
    coap_log_warn("OSCORE: No protected payload\n");
    if (!coap_request)
      coap_handle_event(session->context,
                        COAP_EVENT_OSCORE_NO_PROTECTED_PAYLOAD,
                        session);
    goto error;
  }
  cose_encrypt0_set_key(cose, rcp_ctx->recipient_key);
  cose_encrypt0_set_ciphertext(cose, st_encrypt, encrypt_len);

  tag_len = cose_tag_len(cose->alg);
  /* Decrypt into plain_pdu, so code (token), options and data are in place */
  plain_pdu = coap_pdu_init(0, 0, 0, encrypt_len /* - tag_len */);
  if (plain_pdu == NULL) {
    if (!coap_request)
      coap_handle_event(session->context,
                        COAP_EVENT_OSCORE_INTERNAL_ERROR,
                        session);
    goto error;
  }

  /* need the tag_len on the end for TinyDTLS to do its work - yuk */
  if (!coap_pdu_resize(plain_pdu, encrypt_len /* - tag_len */)) {
    if (!coap_request)
      coap_handle_event(session->context,
                        COAP_EVENT_OSCORE_INTERNAL_ERROR,
                        session);
    goto error;
  }

  /* Account for 1 byte 'code' used as token */
  plain_pdu->e_token_length = 1;
  plain_pdu->actual_token.length = 1;
  /* Account for the decrypted data */
  plain_pdu->used_size = encrypt_len - tag_len;

  dump_cose(cose, "Pre decrypt");
  pltxt_size =
      cose_encrypt0_decrypt(cose, plain_pdu->token, encrypt_len - tag_len);
  if (pltxt_size <= 0) {
    coap_log_warn("OSCORE: Decryption Failure, result code: %d \n",
                  (int)pltxt_size);
    if (coap_request) {
      build_and_send_error_pdu(session,
                               pdu,
                               COAP_RESPONSE_CODE(400),
                               "Decryption failed",
                               NULL,
                               NULL,
                               0);
      oscore_roll_back_seq(rcp_ctx);
      goto error_no_ack;
    } else {
      coap_handle_event(session->context,
                        COAP_EVENT_OSCORE_DECRYPTION_FAILURE,
                        session);
    }
    goto error;
  }

  assert((size_t)pltxt_size < pdu->alloc_size + pdu->max_hdr_size);

  /* Appendix B.2 Trap */
  if (session->b_2_step == COAP_OSCORE_B_2_STEP_2) {
    /* Need to update Security Context with new (R2 || ID1) ID Context */
    coap_binary_t *kc =
        coap_new_binary(sizeof(session->oscore_r2) + cose->kid_context.length);
    coap_bin_const_t oscore_r2;

    if (kc == NULL) {
      if (!coap_request)
        coap_handle_event(session->context,
                          COAP_EVENT_OSCORE_INTERNAL_ERROR,
                          session);
      goto error;
    }

    coap_prng(&session->oscore_r2, sizeof(session->oscore_r2));
    memcpy(kc->s, &session->oscore_r2, sizeof(session->oscore_r2));
    memcpy(&kc->s[sizeof(session->oscore_r2)],
           cose->kid_context.s,
           cose->kid_context.length);

    coap_log_oscore("Appendix B.2 server step 2 (R2 || ID1)\n");
    oscore_update_ctx(osc_ctx, (coap_bin_const_t *)kc);

    oscore_r2.length = sizeof(session->oscore_r2);
    oscore_r2.s = (const uint8_t *)&session->oscore_r2;
    coap_log_oscore("Appendix B.2 server step 2 plain response\n");
    build_and_send_error_pdu(session,
                             pdu,
                             COAP_RESPONSE_CODE(401),
                             NULL,
                             NULL,
                             &oscore_r2,
                             1);
    goto error_no_ack;
  }
#if COAP_CLIENT_SUPPORT
  if (session->b_2_step == COAP_OSCORE_B_2_STEP_3) {
    coap_log_oscore("Appendix B.2 client step 3 (R2 || R3)\n");
    coap_pdu_encode_header(plain_pdu, session->proto);
    plain_pdu->actual_token.s = plain_pdu->token;
    plain_pdu->code = plain_pdu->token[0];
    if (plain_pdu->code != COAP_RESPONSE_CODE(401)) {
      coap_log_warn("OSCORE Appendix B.2: Expected 4.01 response\n");
    }
    /* Skip the options */
    coap_option_iterator_init(plain_pdu, &opt_iter, COAP_OPT_ALL);
    while ((opt = coap_option_next(&opt_iter))) {
    }
    if (opt_iter.length > 0 && opt_iter.next_option &&
        opt_iter.next_option[0] == COAP_PAYLOAD_START) {
      plain_pdu->data = &opt_iter.next_option[1];
    }
    coap_log_oscore("Inner Response PDU (plaintext)\n");
    coap_show_pdu(COAP_LOG_OSCORE, plain_pdu);
    /*
     * Need to update Security Context with new (R2 || R3) ID Context
     * and retransmit the request
     */
    coap_binary_t *kc = coap_new_binary(cose->kid_context.length + 8);

    if (kc == NULL) {
      if (!coap_request)
        coap_handle_event(session->context,
                          COAP_EVENT_OSCORE_INTERNAL_ERROR,
                          session);
      goto error;
    }
    memcpy(kc->s, cose->kid_context.s, cose->kid_context.length);
    coap_prng(&kc->s[cose->kid_context.length], 8);

    oscore_update_ctx(osc_ctx, (coap_bin_const_t *)kc);

    coap_cancel_all_messages(session->context,
                             session,
                             &pdu->actual_token);
    if (session->con_active)
      session->con_active--;
    coap_send_ack(session, pdu);
    if (sent_pdu) {
      coap_log_oscore("Appendix B.2 retransmit pdu\n");
      if (coap_retransmit_oscore_pdu(session, sent_pdu, NULL) ==
          COAP_INVALID_MID)
        goto error_no_ack;
    }
    goto error_no_ack;
  }
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT
  /* Appendix B.1.2 request Trap */
  if (coap_request && osc_ctx->rfc8613_b_1_2) {
    if (rcp_ctx->initial_state == 1) {
      opt = coap_check_option(plain_pdu, COAP_OPTION_ECHO, &opt_iter);
      if (opt) {
        /* Verify Client is genuine */
        if (coap_opt_length(opt) == 8 &&
            memcmp(coap_opt_value(opt), rcp_ctx->echo_value, 8) == 0) {
          if (!oscore_validate_sender_seq(rcp_ctx, cose)) {
            coap_log_warn("OSCORE: Replayed or old message\n");
            build_and_send_error_pdu(session,
                                     pdu,
                                     COAP_RESPONSE_CODE(401),
                                     "Replay detected",
                                     NULL,
                                     NULL,
                                     0);
            goto error_no_ack;
          }
        } else
          goto error;
      } else {
        /* RFC 8163 Appendix B.1.2 */
        if (session->b_2_step == COAP_OSCORE_B_2_STEP_4) {
          session->b_2_step = COAP_OSCORE_B_2_NONE;
          coap_log_oscore("Appendix B.2 server finished\n");
        }
        coap_prng(rcp_ctx->echo_value, sizeof(rcp_ctx->echo_value));
        coap_log_oscore("Appendix B.1.2 server plain response\n");
        build_and_send_error_pdu(session,
                                 pdu,
                                 COAP_RESPONSE_CODE(401),
                                 NULL,
                                 rcp_ctx->echo_value,
                                 NULL,
                                 1);
        goto error_no_ack;
      }
    }
  }
#endif /* COAP_SERVER_SUPPORT */

  /*
   * 8.2 Step 7 / 8.4 Step 6.
   * Add decrypted Code, options and payload
   * [OSCORE option not copied across previously]
   */

  /* PDU code is pseudo plain_pdu token */
  decrypt_pdu->code = plain_pdu->token[0];

  /* Copy inner decrypted options across */
  coap_option_iterator_init(plain_pdu, &opt_iter, COAP_OPT_ALL);
  while ((opt = coap_option_next(&opt_iter))) {
    size_t len;
    size_t bias;

    switch (opt_iter.number) {
    case COAP_OPTION_OSCORE:
      break;
    case COAP_OPTION_OBSERVE:
      if (!coap_request) {
        bias = cose->partial_iv.length > 3 ? cose->partial_iv.length - 3 : 0;
        len = cose->partial_iv.length > 3 ? 3 : cose->partial_iv.length;
        /* Make Observe option reflect last 3 bytes of partial_iv */
        if (!coap_add_option_internal(
                decrypt_pdu,
                opt_iter.number,
                len,
                cose->partial_iv.s ? &cose->partial_iv.s[bias] : NULL)) {
          coap_handle_event(session->context,
                            COAP_EVENT_OSCORE_INTERNAL_ERROR,
                            session);
          goto error;
        }
        break;
      }
      association = oscore_find_association(session, &pdu_token);
      if (association) {
        association->is_observe = 1;
        association = NULL;
      }
    /* Fall Through */
    default:
      if (!coap_insert_option(decrypt_pdu,
                              opt_iter.number,
                              coap_opt_length(opt),
                              coap_opt_value(opt))) {
        if (!coap_request)
          coap_handle_event(session->context,
                            COAP_EVENT_OSCORE_INTERNAL_ERROR,
                            session);
        goto error;
      }
      break;
    }
  }
  /* Need to copy across any data */
  if (opt_iter.length > 0 && opt_iter.next_option &&
      opt_iter.next_option[0] == COAP_PAYLOAD_START) {
    plain_pdu->data = &opt_iter.next_option[1];
    if (!coap_add_data(decrypt_pdu,
                       plain_pdu->used_size -
                       (plain_pdu->data - plain_pdu->token),
                       plain_pdu->data)) {
      if (!coap_request)
        coap_handle_event(session->context,
                          COAP_EVENT_OSCORE_INTERNAL_ERROR,
                          session);
      goto error;
    }
  }
  coap_delete_pdu(plain_pdu);
  plain_pdu = NULL;

  /* Make sure headers are correctly set up */
  if (!coap_pdu_encode_header(decrypt_pdu, session->proto)) {
    if (!coap_request)
      coap_handle_event(session->context,
                        COAP_EVENT_OSCORE_INTERNAL_ERROR,
                        session);
    goto error;
  }

  if (session->b_2_step != COAP_OSCORE_B_2_NONE) {
    session->b_2_step = COAP_OSCORE_B_2_NONE;
    coap_log_oscore("Appendix B.2 client finished\n");
  }
#if COAP_CLIENT_SUPPORT
  if (decrypt_pdu->code == COAP_RESPONSE_CODE(401) &&
      (opt = coap_check_option(decrypt_pdu, COAP_OPTION_ECHO, &opt_iter))) {
    /* Server is requesting Echo refresh check */
    coap_cancel_all_messages(session->context,
                             session,
                             &pdu->actual_token);
    if (session->con_active)
      session->con_active--;
    if (sent_pdu) {
      coap_send_ack(session, pdu);
      coap_log_debug("PDU requesting re-transmit\n");
      coap_show_pdu(COAP_LOG_DEBUG, decrypt_pdu);
      coap_log_oscore("RFC9175 retransmit pdu\n");
      /* Do not care if this fails */
      coap_retransmit_oscore_pdu(session, sent_pdu, opt);
      goto error_no_ack;
    }
  }
#endif /* COAP_CLIENT_SUPPORT */
  if (association && association->is_observe == 0)
    oscore_delete_association(session, association);
  return decrypt_pdu;

error:
  coap_send_ack(session, pdu);
error_no_ack:
  if (association && association->is_observe == 0)
    oscore_delete_association(session, association);
  coap_delete_pdu(decrypt_pdu);
  coap_delete_pdu(plain_pdu);
  return NULL;
}

typedef enum {
  COAP_ENC_ASCII = 0x01,
  COAP_ENC_HEX = 0x02,
  COAP_ENC_INTEGER = 0x08,
  COAP_ENC_TEXT = 0x10,
  COAP_ENC_BOOL = 0x20,
  COAP_ENC_LAST
} coap_oscore_coding_t;

#undef TEXT_MAPPING
#define TEXT_MAPPING(t, v)                     \
  { { sizeof(#t)-1, (const uint8_t *)#t }, v }

static struct coap_oscore_encoding_t {
  coap_str_const_t name;
  coap_oscore_coding_t encoding;
} oscore_encoding[] = {
  TEXT_MAPPING(ascii, COAP_ENC_ASCII),
  TEXT_MAPPING(hex, COAP_ENC_HEX),
  TEXT_MAPPING(integer, COAP_ENC_INTEGER),
  TEXT_MAPPING(text, COAP_ENC_TEXT),
  TEXT_MAPPING(bool, COAP_ENC_BOOL),
  {{0, NULL}, COAP_ENC_LAST}
};

typedef struct {
  coap_oscore_coding_t encoding;
  const char *encoding_name;
  union {
    int value_int;
    coap_bin_const_t *value_bin;
    coap_str_const_t value_str;
  } u;
} oscore_value_t;

static uint8_t
hex2char(char c) {
  assert(isxdigit(c));
  if ('a' <= c && c <= 'f')
    return c - 'a' + 10;
  else if ('A' <= c && c <= 'F')
    return c - 'A' + 10;
  else
    return c - '0';
}

/* Parse the hex into binary */
static coap_bin_const_t *
parse_hex_bin(const char *begin, const char *end) {
  coap_binary_t *binary = NULL;
  size_t i;

  if ((end - begin) % 2 != 0)
    goto bad_entry;
  binary = coap_new_binary((end - begin) / 2);
  if (binary == NULL)
    goto bad_entry;
  for (i = 0; (i < (size_t)(end - begin)) && isxdigit((u_char)begin[i]) &&
       isxdigit((u_char)begin[i + 1]);
       i += 2) {
    binary->s[i / 2] = (hex2char(begin[i]) << 4) + hex2char(begin[i + 1]);
  }
  if (i != (size_t)(end - begin))
    goto bad_entry;
  return (coap_bin_const_t *)binary;

bad_entry:
  coap_delete_binary(binary);
  return NULL;
}

/*
 * Break up each OSCORE Configuration line entry into the 3 parts which
 * are comma separated
 *
 * keyword,encoding,value
 */
static int
get_split_entry(const char **start,
                size_t size,
                coap_str_const_t *keyword,
                oscore_value_t *value) {
  const char *begin = *start;
  const char *end;
  const char *split;
  size_t i;

retry:
  end = memchr(begin, '\n', size);
  if (end == NULL)
    return 0;

  /* Track beginning of next line */
  *start = end + 1;
  if (end > begin && end[-1] == '\r')
    end--;

  if (begin[0] == '#' || (end - begin) == 0) {
    /* Skip comment / blank line */
    size -= end - begin + 1;
    begin = *start;
    goto retry;
  }

  /* Get in the keyword */
  split = memchr(begin, ',', end - begin);
  if (split == NULL)
    goto bad_entry;

  keyword->s = (const uint8_t *)begin;
  keyword->length = split - begin;

  begin = split + 1;
  if ((end - begin) == 0)
    goto bad_entry;
  /* Get in the encoding */
  split = memchr(begin, ',', end - begin);
  if (split == NULL)
    goto bad_entry;

  for (i = 0; oscore_encoding[i].name.s; i++) {
    coap_str_const_t temp = { split - begin, (const uint8_t *)begin };

    if (coap_string_equal(&temp, &oscore_encoding[i].name)) {
      value->encoding = oscore_encoding[i].encoding;
      value->encoding_name = (const char *)oscore_encoding[i].name.s;
      break;
    }
  }
  if (oscore_encoding[i].name.s == NULL)
    goto bad_entry;

  begin = split + 1;
  if ((end - begin) == 0)
    goto bad_entry;
  /* Get in the keyword's value */
  if (begin[0] == '"') {
    split = memchr(&begin[1], '"', end - split - 1);
    if (split == NULL)
      goto bad_entry;
    end = split;
    begin++;
  }
  switch (value->encoding) {
  case COAP_ENC_ASCII:
    value->u.value_bin =
        coap_new_bin_const((const uint8_t *)begin, end - begin);
    break;
  case COAP_ENC_HEX:
    /* Parse the hex into binary */
    value->u.value_bin = parse_hex_bin(begin, end);
    if (value->u.value_bin == NULL)
      goto bad_entry;
    break;
  case COAP_ENC_INTEGER:
    value->u.value_int = atoi(begin);
    break;
  case COAP_ENC_TEXT:
    value->u.value_str.s = (const uint8_t *)begin;
    value->u.value_str.length = end - begin;
    break;
  case COAP_ENC_BOOL:
    if (memcmp("true", begin, end - begin) == 0)
      value->u.value_int = 1;
    else if (memcmp("false", begin, end - begin) == 0)
      value->u.value_int = 0;
    else
      goto bad_entry;
    break;
  case COAP_ENC_LAST:
  default:
    goto bad_entry;
  }
  return 1;

bad_entry:
  coap_log_warn("oscore_conf: Unrecognized configuration entry '%.*s'\n",
                (int)(end - begin),
                begin);
  return 0;
}

#undef CONFIG_ENTRY
#define CONFIG_ENTRY(n, e, t)                                                  \
  { { sizeof(#n)-1, (const uint8_t *)#n }, e, \
    offsetof(coap_oscore_conf_t, n), t }

typedef struct oscore_text_mapping_t {
  coap_str_const_t text;
  int value;
} oscore_text_mapping_t;

/* Naming as per https://www.iana.org/assignments/cose/cose.xhtml#algorithms */
static oscore_text_mapping_t text_aead_alg[] = {
  TEXT_MAPPING(AES-CCM-16-64-128, COSE_ALGORITHM_AES_CCM_16_64_128),
  TEXT_MAPPING(AES-CCM-16-64-256, COSE_ALGORITHM_AES_CCM_16_64_256),
  {{0, NULL}, 0}
};

static oscore_text_mapping_t text_hkdf_alg[] = {
  TEXT_MAPPING(direct+HKDF-SHA-256, COSE_HKDF_ALG_HKDF_SHA_256),
  {{0, NULL}, 0}
};

static struct oscore_config_t {
  coap_str_const_t str_keyword;
  coap_oscore_coding_t encoding;
  size_t offset;
  oscore_text_mapping_t *text_mapping;
} oscore_config[] = {
  CONFIG_ENTRY(master_secret, COAP_ENC_HEX | COAP_ENC_ASCII, NULL),
  CONFIG_ENTRY(master_salt, COAP_ENC_HEX | COAP_ENC_ASCII, NULL),
  CONFIG_ENTRY(sender_id, COAP_ENC_HEX | COAP_ENC_ASCII, NULL),
  CONFIG_ENTRY(id_context, COAP_ENC_HEX | COAP_ENC_ASCII, NULL),
  CONFIG_ENTRY(recipient_id, COAP_ENC_HEX | COAP_ENC_ASCII, NULL),
  CONFIG_ENTRY(replay_window, COAP_ENC_INTEGER, NULL),
  CONFIG_ENTRY(ssn_freq, COAP_ENC_INTEGER, NULL),
  CONFIG_ENTRY(aead_alg, COAP_ENC_INTEGER | COAP_ENC_TEXT, text_aead_alg),
  CONFIG_ENTRY(hkdf_alg, COAP_ENC_INTEGER | COAP_ENC_TEXT, text_hkdf_alg),
  CONFIG_ENTRY(rfc8613_b_1_2, COAP_ENC_BOOL, NULL),
  CONFIG_ENTRY(rfc8613_b_2, COAP_ENC_BOOL, NULL),
  CONFIG_ENTRY(break_sender_key, COAP_ENC_BOOL, NULL),
  CONFIG_ENTRY(break_recipient_key, COAP_ENC_BOOL, NULL),
};

int
coap_delete_oscore_conf(coap_oscore_conf_t *oscore_conf) {
  uint32_t i;

  if (oscore_conf == NULL)
    return 0;

  coap_delete_bin_const(oscore_conf->master_secret);
  coap_delete_bin_const(oscore_conf->master_salt);
  coap_delete_bin_const(oscore_conf->id_context);
  coap_delete_bin_const(oscore_conf->sender_id);
  for (i = 0; i < oscore_conf->recipient_id_count; i++) {
    coap_delete_bin_const(oscore_conf->recipient_id[i]);
  }
  coap_free_type(COAP_STRING, oscore_conf->recipient_id);
  coap_free_type(COAP_STRING, oscore_conf);
  return 1;
}

static coap_oscore_conf_t *
coap_parse_oscore_conf_mem(coap_str_const_t conf_mem) {
  const char *start = (const char *)conf_mem.s;
  const char *end = start + conf_mem.length;
  coap_str_const_t keyword;
  oscore_value_t value;
  coap_oscore_conf_t *oscore_conf;

  oscore_conf = coap_malloc_type(COAP_STRING, sizeof(coap_oscore_conf_t));
  if (oscore_conf == NULL)
    return NULL;
  memset(oscore_conf, 0, sizeof(coap_oscore_conf_t));

  memset(&value, 0, sizeof(value));
  /* Preset with defaults */
  oscore_conf->replay_window = COAP_OSCORE_DEFAULT_REPLAY_WINDOW;
  oscore_conf->ssn_freq = 1;
  oscore_conf->aead_alg = COSE_ALGORITHM_AES_CCM_16_64_128;
  oscore_conf->hkdf_alg = COSE_HKDF_ALG_HKDF_SHA_256;
  oscore_conf->rfc8613_b_1_2 = 1;
  oscore_conf->rfc8613_b_2 = 0;
  oscore_conf->break_sender_key = 0;
  oscore_conf->break_recipient_key = 0;

  while (end > start &&
         get_split_entry(&start, end - start, &keyword, &value)) {
    size_t i;
    size_t j;

    for (i = 0; i < sizeof(oscore_config) / sizeof(oscore_config[0]); i++) {
      if (coap_string_equal(&oscore_config[i].str_keyword, &keyword) != 0 &&
          value.encoding & oscore_config[i].encoding) {
        if (coap_string_equal(coap_make_str_const("recipient_id"), &keyword)) {
          if (value.u.value_bin->length > 7) {
            coap_log_warn("oscore_conf: Maximum size of recipient_id is 7 bytes\n");
            goto error_free_value_bin;
          }
          /* Special case as there are potentially multiple entries */
          oscore_conf->recipient_id =
              coap_realloc_type(COAP_STRING,
                                oscore_conf->recipient_id,
                                sizeof(oscore_conf->recipient_id[0]) *
                                (oscore_conf->recipient_id_count + 1));
          if (oscore_conf->recipient_id == NULL) {
            goto error_free_value_bin;
          }
          oscore_conf->recipient_id[oscore_conf->recipient_id_count++] =
              value.u.value_bin;
        } else {
          coap_bin_const_t *unused_check;

          switch (value.encoding) {
          case COAP_ENC_HEX:
          case COAP_ENC_ASCII:
            memcpy(&unused_check,
                   &(((char *)oscore_conf)[oscore_config[i].offset]),
                   sizeof(unused_check));
            if (unused_check != NULL) {
              coap_log_warn("oscore_conf: Keyword '%.*s' duplicated\n",
                            (int)keyword.length,
                            (const char *)keyword.s);
              goto error;
            }
            memcpy(&(((char *)oscore_conf)[oscore_config[i].offset]),
                   &value.u.value_bin,
                   sizeof(value.u.value_bin));
            break;
          case COAP_ENC_INTEGER:
          case COAP_ENC_BOOL:
            memcpy(&(((char *)oscore_conf)[oscore_config[i].offset]),
                   &value.u.value_int,
                   sizeof(value.u.value_int));
            break;
          case COAP_ENC_TEXT:
            for (j = 0; oscore_config[i].text_mapping[j].text.s != NULL; j++) {
              if (coap_string_equal(&value.u.value_str,
                                    &oscore_config[i].text_mapping[j].text)) {
                memcpy(&(((char *)oscore_conf)[oscore_config[i].offset]),
                       &oscore_config[i].text_mapping[j].value,
                       sizeof(oscore_config[i].text_mapping[j].value));
                break;
              }
            }
            if (oscore_config[i].text_mapping[j].text.s == NULL) {
              coap_log_warn("oscore_conf: Keyword '%.*s': value '%.*s' unknown\n",
                            (int)keyword.length,
                            (const char *)keyword.s,
                            (int)value.u.value_str.length,
                            (const char *)value.u.value_str.s);
              goto error;
            }
            break;
          case COAP_ENC_LAST:
          default:
            assert(0);
            break;
          }
        }
        break;
      }
    }
    if (i == sizeof(oscore_config) / sizeof(oscore_config[0])) {
      coap_log_warn("oscore_conf: Keyword '%.*s', type '%s' unknown\n",
                    (int)keyword.length,
                    (const char *)keyword.s,
                    value.encoding_name);
      if (value.encoding == COAP_ENC_HEX || value.encoding == COAP_ENC_ASCII)
        coap_delete_bin_const(value.u.value_bin);
      goto error;
    }
  }
  if (!oscore_conf->master_secret) {
    coap_log_warn("oscore_conf: master_secret not defined\n");
    goto error;
  }
  if (!oscore_conf->sender_id) {
    coap_log_warn("oscore_conf: sender_id not defined\n");
    goto error;
  }
  if (oscore_conf->sender_id->length > 7) {
    coap_log_warn("oscore_conf: Maximum size of sender_id is 7 bytes\n");
    goto error;
  }
  if (oscore_conf->recipient_id && oscore_conf->recipient_id[0]->length > 7) {
    coap_log_warn("oscore_conf: Maximum size of recipient_id is 7 bytes\n");
    goto error;
  }
  return oscore_conf;

error_free_value_bin:
  coap_delete_bin_const(value.u.value_bin);
error:
  coap_delete_oscore_conf(oscore_conf);
  return NULL;
}

static oscore_ctx_t *
coap_oscore_init(coap_context_t *c_context, coap_oscore_conf_t *oscore_conf) {
  oscore_ctx_t *osc_ctx = NULL;

  if (!coap_crypto_check_cipher_alg(oscore_conf->aead_alg)) {
    coap_log_warn("COSE: Cipher Algorithm %d not supported\n",
                  oscore_conf->aead_alg);
    goto error;
  }
  if (!coap_crypto_check_hkdf_alg(oscore_conf->hkdf_alg)) {
    coap_log_warn("COSE: HKDF Algorithm %d not supported\n",
                  oscore_conf->hkdf_alg);
    goto error;
  }

  osc_ctx = oscore_derive_ctx(c_context, oscore_conf);
  if (!osc_ctx) {
    coap_log_crit("OSCORE: Could not create Security Context!\n");
    goto error;
  }

  /* Free off the recipient_id array */
  coap_free_type(COAP_STRING, oscore_conf->recipient_id);
  oscore_conf->recipient_id = NULL;

  /* As all is stored in osc_ctx, oscore_conf is no longer needed */
  coap_free_type(COAP_STRING, oscore_conf);

  /* return default first context  */
  return osc_ctx;

error:
  /* Remove from linked chain */
  oscore_remove_context(c_context, osc_ctx);

  coap_delete_oscore_conf(oscore_conf);
  return NULL;
}

void
coap_delete_all_oscore(coap_context_t *c_context) {
  oscore_free_contexts(c_context);
}

void
coap_delete_oscore_associations(coap_session_t *session) {
  oscore_delete_server_associations(session);
}

coap_oscore_conf_t *
coap_new_oscore_conf(coap_str_const_t conf_mem,
                     coap_oscore_save_seq_num_t save_seq_num_func,
                     void *save_seq_num_func_param,
                     uint64_t start_seq_num) {
  coap_oscore_conf_t *oscore_conf = coap_parse_oscore_conf_mem(conf_mem);

  if (oscore_conf == NULL)
    return NULL;

  oscore_conf->save_seq_num_func = save_seq_num_func;
  oscore_conf->save_seq_num_func_param = save_seq_num_func_param;
  oscore_conf->start_seq_num = start_seq_num;
  coap_log_oscore("Start Seq no %" PRIu64 "\n", start_seq_num);
  return oscore_conf;
}

/*
 * Compute the size of the potential OSCORE overhead
 */
size_t
coap_oscore_overhead(coap_session_t *session, coap_pdu_t *pdu) {
  size_t overhead = 0;
  oscore_recipient_ctx_t *rcp_ctx = session->recipient_ctx;
  oscore_ctx_t *osc_ctx = rcp_ctx ? rcp_ctx->osc_ctx : NULL;
  coap_opt_iterator_t opt_iter;
  coap_opt_t *option;

  if (osc_ctx == NULL)
    return 0;

  /* Protected code held in inner PDU as token */
  overhead += 1;

  /* Observe option (creates inner and outer */
  option = coap_check_option(pdu, COAP_OPTION_OBSERVE, &opt_iter);
  if (option) {
    /* Assume delta is small */
    overhead += 2 + coap_opt_length(option);
  }

  /* Proxy URI option Split - covered by coap_rebuild_pdu_for_proxy () */

  /* OSCORE option */
  /* Option header */
  overhead += 1 +
              /* Partial IV (64 bits max)*/
              8 +
              /* kid context */
              (osc_ctx->id_context ? osc_ctx->id_context->length : 0) +
              /* kid */
              osc_ctx->sender_context->sender_id->length;

  /* AAD overhead */
  overhead += AES_CCM_TAG;

  /* End of options marker */
  overhead += 1;

  return overhead;
}

int
coap_new_oscore_recipient(coap_context_t *context,
                          coap_bin_const_t *recipient_id) {
  coap_lock_check_locked(context);
  if (context->p_osc_ctx == NULL)
    return 0;
  if (oscore_add_recipient(context->p_osc_ctx, recipient_id, 0) == NULL)
    return 0;
  return 1;
}

int
coap_delete_oscore_recipient(coap_context_t *context,
                             coap_bin_const_t *recipient_id) {
  coap_lock_check_locked(context);
  if (context->p_osc_ctx == NULL)
    return 0;
  return oscore_delete_recipient(context->p_osc_ctx, recipient_id);
}

/** @} */

#else /* !COAP_OSCORE_SUPPORT */
int
coap_oscore_is_supported(void) {
  return 0;
}

coap_session_t *
coap_new_client_session_oscore(coap_context_t *ctx,
                               const coap_address_t *local_if,
                               const coap_address_t *server,
                               coap_proto_t proto,
                               coap_oscore_conf_t *oscore_conf) {
  (void)ctx;
  (void)local_if;
  (void)server;
  (void)proto;
  (void)oscore_conf;
  return NULL;
}

coap_session_t *
coap_new_client_session_oscore_psk(coap_context_t *ctx,
                                   const coap_address_t *local_if,
                                   const coap_address_t *server,
                                   coap_proto_t proto,
                                   coap_dtls_cpsk_t *psk_data,
                                   coap_oscore_conf_t *oscore_conf) {
  (void)ctx;
  (void)local_if;
  (void)server;
  (void)proto;
  (void)psk_data;
  (void)oscore_conf;
  return NULL;
}

coap_session_t *
coap_new_client_session_oscore_pki(coap_context_t *ctx,
                                   const coap_address_t *local_if,
                                   const coap_address_t *server,
                                   coap_proto_t proto,
                                   coap_dtls_pki_t *pki_data,
                                   coap_oscore_conf_t *oscore_conf) {
  (void)ctx;
  (void)local_if;
  (void)server;
  (void)proto;
  (void)pki_data;
  (void)oscore_conf;
  return NULL;
}

int
coap_context_oscore_server(coap_context_t *context,
                           coap_oscore_conf_t *oscore_conf) {
  (void)context;
  (void)oscore_conf;
  return 0;
}

coap_oscore_conf_t *
coap_new_oscore_conf(coap_str_const_t conf_mem,
                     coap_oscore_save_seq_num_t save_seq_num_func,
                     void *save_seq_num_func_param,
                     uint64_t start_seq_num) {
  (void)conf_mem;
  (void)save_seq_num_func;
  (void)save_seq_num_func_param;
  (void)start_seq_num;
  return NULL;
}

int
coap_delete_oscore_conf(coap_oscore_conf_t *oscore_conf) {
  (void)oscore_conf;
  return 0;
}

int
coap_new_oscore_recipient(coap_context_t *context,
                          coap_bin_const_t *recipient_id) {
  (void)context;
  (void)recipient_id;
  return 0;
}

int
coap_delete_oscore_recipient(coap_context_t *context,
                             coap_bin_const_t *recipient_id) {
  (void)context;
  (void)recipient_id;
  return 0;
}

#endif /* !COAP_OSCORE_SUPPORT */
