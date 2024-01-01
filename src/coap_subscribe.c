/* coap_subscribe.c -- subscription handling for CoAP
 *                see RFC7641
 *
 * Copyright (C) 2010-2019,2022-2024 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file coap_subscribe.c
 * @brief Subscription handling functions
 */

#include "coap3/coap_internal.h"

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

#if COAP_SERVER_SUPPORT
void
coap_subscription_init(coap_subscription_t *s) {
  assert(s);
  memset(s, 0, sizeof(coap_subscription_t));
}

void
coap_persist_track_funcs(coap_context_t *context,
                         coap_observe_added_t observe_added,
                         coap_observe_deleted_t observe_deleted,
                         coap_track_observe_value_t track_observe_value,
                         coap_dyn_resource_added_t dyn_resource_added,
                         coap_resource_deleted_t resource_deleted,
                         uint32_t save_freq,
                         void *user_data) {
  context->observe_added = observe_added;
  context->observe_deleted = observe_deleted;
  context->observe_user_data = user_data;
  context->observe_save_freq = save_freq ? save_freq : 1;
  context->track_observe_value = track_observe_value;
  context->dyn_resource_added = dyn_resource_added;
  context->resource_deleted = resource_deleted;
}

coap_subscription_t *
coap_persist_observe_add(coap_context_t *context,
                         coap_proto_t e_proto,
                         const coap_address_t *e_listen_addr,
                         const coap_addr_tuple_t *s_addr_info,
                         const coap_bin_const_t *raw_packet,
                         const coap_bin_const_t *oscore_info) {
  coap_session_t *session = NULL;
  const uint8_t *data;
  size_t data_len;
  coap_pdu_t *pdu = NULL;
#if COAP_CONSTRAINED_STACK
  /* e_packet protected by mutex m_persist_add */
  static coap_packet_t e_packet;
#else /* ! COAP_CONSTRAINED_STACK */
  coap_packet_t e_packet;
#endif /* ! COAP_CONSTRAINED_STACK */
  coap_packet_t *packet = &e_packet;
  coap_tick_t now;
  coap_string_t *uri_path = NULL;
  coap_opt_iterator_t opt_iter;
  coap_opt_t *observe;
  int observe_action;
  coap_resource_t *r;
  coap_subscription_t *s;
  coap_endpoint_t *ep;

  coap_lock_check_locked(context);
  if (e_listen_addr == NULL || s_addr_info == NULL || raw_packet == NULL)
    return NULL;

  /* Will be creating a local 'open' session */
  if (e_proto != COAP_PROTO_UDP)
    return NULL;

  ep = context->endpoint;
  while (ep) {
    if (ep->proto == e_proto &&
        memcmp(e_listen_addr, &ep->bind_addr, sizeof(ep->bind_addr)) == 0)
      break;
    ep = ep->next;
  }
  if (!ep)
    return NULL;

#if COAP_CONSTRAINED_STACK
  coap_mutex_lock(&m_persist_add);
#endif /* COAP_CONSTRAINED_STACK */

  /* Build up packet */
  memcpy(&packet->addr_info, s_addr_info, sizeof(packet->addr_info));
  packet->ifindex = 0;
  memcpy(&packet->payload, &raw_packet->s, sizeof(packet->payload));
  packet->length = raw_packet->length;

  data = raw_packet->s;
  data_len = raw_packet->length;
  if (data_len < 4)
    goto malformed;

  /* Get the session */

  coap_ticks(&now);
  session = coap_endpoint_get_session(ep, packet, now);
  if (session == NULL)
    goto fail;
  /* Need max space incase PDU is updated with updated token, huge size etc. */
  pdu = coap_pdu_init(0, 0, 0, 0);
  if (!pdu)
    goto fail;

  if (!coap_pdu_parse(session->proto, data, data_len, pdu)) {
    goto malformed;
  }
  pdu->max_size = pdu->used_size;

  if (pdu->code != COAP_REQUEST_CODE_GET &&
      pdu->code != COAP_REQUEST_CODE_FETCH)
    goto malformed;

  observe = coap_check_option(pdu, COAP_OPTION_OBSERVE, &opt_iter);
  if (observe == NULL)
    goto malformed;
  observe_action = coap_decode_var_bytes(coap_opt_value(observe),
                                         coap_opt_length(observe));
  if (observe_action != COAP_OBSERVE_ESTABLISH)
    goto malformed;

  /* Get the resource */

  uri_path = coap_get_uri_path(pdu);
  if (!uri_path)
    goto malformed;

  r = coap_get_resource_from_uri_path(session->context,
                                      (coap_str_const_t *)uri_path);
  if (r == NULL) {
    coap_log_warn("coap_persist_observe_add: resource '%s' not defined\n",
                  uri_path->s);
    goto fail;
  }
  if (!r->observable) {
    coap_log_warn("coap_persist_observe_add: resource '%s' not observable\n",
                  uri_path->s);
    goto fail;
  }
  coap_delete_string(uri_path);
  uri_path = NULL;

  /* Create / update subscription for observing */
  /* Now set up the subscription */
  s = coap_add_observer(r, session, &pdu->actual_token, pdu);
  if (s == NULL)
    goto fail;

#if COAP_OSCORE_SUPPORT
  if (oscore_info) {
    coap_log_debug("persist: OSCORE association being updated\n");
    /*
     * Need to track the association used for tracking this observe, done as
     * a CBOR array. Written in coap_add_observer().
     *
     * If an entry is null, then use nil, else a set of bytes
     *
     * Currently tracking 5 items
     *  recipient_id
     *  id_context
     *  aad        (from oscore_association_t)
     *  partial_iv (from oscore_association_t)
     *  nonce      (from oscore_association_t)
     */
    oscore_ctx_t *osc_ctx;
    const uint8_t *info_buf = oscore_info->s;
    size_t info_buf_len = oscore_info->length;
    size_t ret = 0;
    coap_bin_const_t oscore_key_id;
    coap_bin_const_t partial_iv;
    coap_bin_const_t aad;
    coap_bin_const_t id_context;
    coap_bin_const_t nonce;
    int have_aad = 0;
    int have_partial_iv = 0;
    int have_id_context = 0;
    int have_nonce = 0;

    ret = oscore_cbor_get_next_element(&info_buf, &info_buf_len);
    if (ret != CBOR_ARRAY)
      goto oscore_fail;
    if (oscore_cbor_get_element_size(&info_buf, &info_buf_len) != 5)
      goto oscore_fail;

    /* recipient_id */
    ret = oscore_cbor_get_next_element(&info_buf, &info_buf_len);
    if (ret != CBOR_BYTE_STRING)
      goto oscore_fail;
    oscore_key_id.length = oscore_cbor_get_element_size(&info_buf,
                                                        &info_buf_len);
    oscore_key_id.s = info_buf;
    info_buf += oscore_key_id.length;

    /* id_context */
    ret = oscore_cbor_get_next_element(&info_buf, &info_buf_len);
    if (ret == CBOR_BYTE_STRING) {
      id_context.length = oscore_cbor_get_element_size(&info_buf,
                                                       &info_buf_len);
      id_context.s = info_buf;
      info_buf += id_context.length;
      have_id_context = 1;
    } else if (ret == CBOR_SIMPLE_VALUE &&
               oscore_cbor_get_element_size(&info_buf,
                                            &info_buf_len) == CBOR_NULL) {
    } else
      goto oscore_fail;

    /* aad */
    ret = oscore_cbor_get_next_element(&info_buf, &info_buf_len);
    if (ret == CBOR_BYTE_STRING) {
      aad.length = oscore_cbor_get_element_size(&info_buf, &info_buf_len);
      aad.s = info_buf;
      info_buf += aad.length;
      have_aad = 1;
    } else if (ret == CBOR_SIMPLE_VALUE &&
               oscore_cbor_get_element_size(&info_buf,
                                            &info_buf_len) == CBOR_NULL) {
    } else
      goto oscore_fail;

    /* partial_iv */
    ret = oscore_cbor_get_next_element(&info_buf, &info_buf_len);
    if (ret == CBOR_BYTE_STRING) {
      partial_iv.length = oscore_cbor_get_element_size(&info_buf,
                                                       &info_buf_len);
      partial_iv.s = info_buf;
      info_buf += partial_iv.length;
      have_partial_iv = 1;
    } else if (ret == CBOR_SIMPLE_VALUE &&
               oscore_cbor_get_element_size(&info_buf,
                                            &info_buf_len) == CBOR_NULL) {
    } else
      goto oscore_fail;

    /* nonce */
    ret = oscore_cbor_get_next_element(&info_buf, &info_buf_len);
    if (ret == CBOR_BYTE_STRING) {
      nonce.length = oscore_cbor_get_element_size(&info_buf,
                                                  &info_buf_len);
      nonce.s = info_buf;
      info_buf += nonce.length;
      have_nonce = 1;
    } else if (ret == CBOR_SIMPLE_VALUE &&
               oscore_cbor_get_element_size(&info_buf,
                                            &info_buf_len) == CBOR_NULL) {
    } else
      goto oscore_fail;

    osc_ctx = oscore_find_context(session->context, oscore_key_id,
                                  have_id_context ? &id_context : NULL, NULL,
                                  &session->recipient_ctx);
    if (osc_ctx) {
      session->oscore_encryption = 1;
      oscore_new_association(session, pdu, &pdu->actual_token,
                             session->recipient_ctx,
                             have_aad ? &aad : NULL,
                             have_nonce ? &nonce : NULL,
                             have_partial_iv ? &partial_iv : NULL,
                             1);
      coap_log_debug("persist: OSCORE association added\n");
      oscore_log_hex_value(COAP_LOG_OSCORE, "partial_iv",
                           have_partial_iv ? &partial_iv : NULL);
    }
  }
oscore_fail:
#else /* ! COAP_OSCORE_SUPPORT */
  (void)oscore_info;
#endif /* ! COAP_OSCORE_SUPPORT */
  coap_delete_pdu(pdu);
#if COAP_CONSTRAINED_STACK
  coap_mutex_unlock(&m_persist_add);
#endif /* COAP_CONSTRAINED_STACK */
  return s;

malformed:
  coap_log_warn("coap_persist_observe_add: discard malformed PDU\n");
fail:
#if COAP_CONSTRAINED_STACK
  coap_mutex_unlock(&m_persist_add);
#endif /* COAP_CONSTRAINED_STACK */
  coap_delete_string(uri_path);
  coap_delete_pdu(pdu);
  return NULL;
}

#if COAP_WITH_OBSERVE_PERSIST
#include <stdio.h>

/*
 * read in active observe entry.
 */
static int
coap_op_observe_read(FILE *fp, coap_subscription_t **observe_key,
                     coap_proto_t *e_proto, coap_address_t *e_listen_addr,
                     coap_addr_tuple_t *s_addr_info,
                     coap_bin_const_t **raw_packet, coap_bin_const_t **oscore_info) {
  ssize_t size;
  coap_binary_t *scratch = NULL;

  assert(fp && observe_key && e_proto && e_listen_addr && s_addr_info &&
         raw_packet && oscore_info);

  *raw_packet = NULL;
  *oscore_info = NULL;

  if (fread(observe_key, sizeof(*observe_key), 1, fp) == 1) {
    /* New record 'key proto listen addr_info len raw_packet len oscore' */
    if (fread(e_proto, sizeof(*e_proto), 1, fp) != 1)
      goto fail;
    if (fread(e_listen_addr, sizeof(*e_listen_addr), 1, fp) != 1)
      goto fail;
    if (fread(s_addr_info, sizeof(*s_addr_info), 1, fp) != 1)
      goto fail;
    if (fread(&size, sizeof(size), 1, fp) != 1)
      goto fail;
    if (size < 0 || size > 0x10000)
      goto fail;
    scratch = coap_new_binary(size);
    if ((scratch) == NULL)
      goto fail;
    if (fread(scratch->s, scratch->length, 1, fp) != 1)
      goto fail;
    *raw_packet = (coap_bin_const_t *)scratch;
    scratch = NULL;
    if (fread(&size, sizeof(size), 1, fp) != 1)
      goto fail;
    /* If size == -1, then no oscore information */
    if (size == -1)
      return 1;
    else if (size < 0 || size > 0x10000)
      goto fail;
    else {
      scratch = coap_new_binary(size);
      if (scratch == NULL)
        goto fail;
      if (fread(scratch->s, scratch->length, 1, fp) != 1)
        goto fail;
      *oscore_info = (coap_bin_const_t *)scratch;
    }
    return 1;
  }
fail:
  coap_delete_bin_const(*raw_packet);
  coap_delete_binary(scratch);

  *observe_key = NULL;
  memset(e_proto, 0, sizeof(*e_proto));
  memset(e_listen_addr, 0, sizeof(*e_listen_addr));
  memset(s_addr_info, 0, sizeof(*s_addr_info));
  *raw_packet = NULL;
  return 0;
}

/*
 * write out active observe entry.
 */
static int
coap_op_observe_write(FILE *fp, coap_subscription_t *observe_key,
                      coap_proto_t e_proto, coap_address_t e_listen_addr,
                      coap_addr_tuple_t s_addr_info,
                      coap_bin_const_t *raw_packet, coap_bin_const_t *oscore_info) {
  if (fwrite(&observe_key, sizeof(observe_key), 1, fp) != 1)
    goto fail;
  if (fwrite(&e_proto, sizeof(e_proto), 1, fp) != 1)
    goto fail;
  if (fwrite(&e_listen_addr, sizeof(e_listen_addr),
             1, fp) != 1)
    goto fail;
  if (fwrite(&s_addr_info, sizeof(s_addr_info), 1, fp) != 1)
    goto fail;
  if (fwrite(&raw_packet->length, sizeof(raw_packet->length), 1, fp) != 1)
    goto fail;
  if (fwrite(raw_packet->s, raw_packet->length, 1, fp) != 1)
    goto fail;
  if (oscore_info) {
    if (fwrite(&oscore_info->length, sizeof(oscore_info->length), 1, fp) != 1)
      goto fail;
    if (fwrite(oscore_info->s, oscore_info->length, 1, fp) != 1)
      goto fail;
  } else {
    ssize_t not_defined = -1;

    if (fwrite(&not_defined, sizeof(not_defined), 1, fp) != 1)
      goto fail;
  }
  return 1;
fail:
  return 0;
}

/*
 * This should be called before coap_persist_track_funcs() to prevent
 * coap_op_observe_added() getting unnecessarily called.
 * It should be called after init_resources() and coap_op_resource_load_disk()
 * so that all the resources are in place.
 */
static void
coap_op_observe_load_disk(coap_context_t *ctx) {
  FILE *fp_orig = fopen((const char *)ctx->observe_save_file->s, "r");
  FILE *fp_new = NULL;
  coap_subscription_t *observe_key = NULL;
  coap_proto_t e_proto;
  coap_address_t e_listen_addr;
  coap_addr_tuple_t s_addr_info;
  coap_bin_const_t *raw_packet = NULL;
  coap_bin_const_t *oscore_info = NULL;
  char *new = NULL;

  if (fp_orig == NULL)
    goto fail;

  new = coap_malloc_type(COAP_STRING, ctx->observe_save_file->length + 5);
  if (!new)
    goto fail;

  strcpy(new, (const char *)ctx->observe_save_file->s);
  strcat(new, ".tmp");
  fp_new = fopen(new, "w+");
  if (fp_new == NULL)
    goto fail;

  /* Go through and load oscore entry, updating key on the way */
  while (1) {
    if (!coap_op_observe_read(fp_orig, &observe_key, &e_proto, &e_listen_addr,
                              &s_addr_info, &raw_packet, &oscore_info))
      break;
    coap_log_debug("persist: New session/observe being created\n");
    observe_key = coap_persist_observe_add(ctx, e_proto,
                                           &e_listen_addr,
                                           &s_addr_info,
                                           raw_packet,
                                           oscore_info);
    if (observe_key) {
      if (!coap_op_observe_write(fp_new, observe_key, e_proto, e_listen_addr,
                                 s_addr_info, raw_packet, oscore_info))
        goto fail;
      coap_delete_bin_const(raw_packet);
      raw_packet = NULL;
      coap_delete_bin_const(oscore_info);
      oscore_info = NULL;
    }
  }
  coap_delete_bin_const(raw_packet);
  raw_packet = NULL;
  coap_delete_bin_const(oscore_info);
  oscore_info = NULL;

  if (fflush(fp_new) == EOF)
    goto fail;
  fclose(fp_new);
  fclose(fp_orig);
  /* Either old or new is in place */
  (void)rename(new, (const char *)ctx->observe_save_file->s);
  coap_free_type(COAP_STRING, new);
  return;

fail:
  coap_delete_bin_const(raw_packet);
  coap_delete_bin_const(oscore_info);
  if (fp_new)
    fclose(fp_new);
  if (fp_orig)
    fclose(fp_orig);
  if (new) {
    (void)remove(new);
  }
  coap_free_type(COAP_STRING, new);
  return;
}

/*
 * client has registered a new observe subscription request.
 */
static int
coap_op_observe_added(coap_session_t *session,
                      coap_subscription_t *a_observe_key,
                      coap_proto_t a_e_proto, coap_address_t *a_e_listen_addr,
                      coap_addr_tuple_t *a_s_addr_info,
                      coap_bin_const_t *a_raw_packet,
                      coap_bin_const_t *a_oscore_info, void *user_data) {
  FILE *fp_orig = fopen((const char *)session->context->observe_save_file->s,
                        "r");
  FILE *fp_new = NULL;
  coap_subscription_t *observe_key = NULL;
  coap_proto_t e_proto;
  coap_address_t e_listen_addr;
  coap_addr_tuple_t s_addr_info;
  coap_bin_const_t *raw_packet = NULL;
  coap_bin_const_t *oscore_info = NULL;
  char *new = NULL;

  (void)user_data;

  new = coap_malloc_type(COAP_STRING,
                         session->context->observe_save_file->length + 5);
  if (!new)
    goto fail;

  strcpy(new, (const char *)session->context->observe_save_file->s);
  strcat(new, ".tmp");
  fp_new = fopen(new, "w+");
  if (fp_new == NULL)
    goto fail;

  /* Go through and delete observe entry if it exists */
  while (fp_orig) {
    if (!coap_op_observe_read(fp_orig, &observe_key, &e_proto, &e_listen_addr,
                              &s_addr_info, &raw_packet, &oscore_info))
      break;
    if (observe_key != a_observe_key) {
      if (!coap_op_observe_write(fp_new, observe_key, e_proto, e_listen_addr,
                                 s_addr_info, raw_packet, oscore_info))
        goto fail;
    }
    coap_delete_bin_const(raw_packet);
    raw_packet = NULL;
    coap_delete_bin_const(oscore_info);
    oscore_info = NULL;
  }
  coap_delete_bin_const(raw_packet);
  raw_packet = NULL;
  coap_delete_bin_const(oscore_info);
  oscore_info = NULL;

  /* Add in new entry to the end */
  if (!coap_op_observe_write(fp_new, a_observe_key, a_e_proto, *a_e_listen_addr,
                             *a_s_addr_info, a_raw_packet, a_oscore_info))
    goto fail;

  if (fflush(fp_new) == EOF)
    goto fail;
  fclose(fp_new);
  if (fp_orig)
    fclose(fp_orig);
  /* Either old or new is in place */
  (void)rename(new, (const char *)session->context->observe_save_file->s);
  coap_free_type(COAP_STRING, new);
  return 1;

fail:
  coap_delete_bin_const(raw_packet);
  coap_delete_bin_const(oscore_info);
  if (fp_new)
    fclose(fp_new);
  if (fp_orig)
    fclose(fp_orig);
  if (new) {
    (void)remove(new);
  }
  coap_free_type(COAP_STRING, new);
  return 0;
}

/*
 * client has de-registered a observe subscription request.
 */
static int
coap_op_observe_deleted(coap_session_t *session,
                        coap_subscription_t *d_observe_key,
                        void *user_data) {
  FILE *fp_orig = fopen((const char *)session->context->observe_save_file->s,
                        "r");
  FILE *fp_new = NULL;
  coap_subscription_t *observe_key = NULL;
  coap_proto_t e_proto;
  coap_address_t e_listen_addr;
  coap_addr_tuple_t s_addr_info;
  coap_bin_const_t *raw_packet = NULL;
  coap_bin_const_t *oscore_info = NULL;
  char *new = NULL;

  (void)user_data;

  if (fp_orig == NULL)
    goto fail;
  new = coap_malloc_type(COAP_STRING,
                         session->context->observe_save_file->length + 5);
  if (!new)
    goto fail;

  strcpy(new, (const char *)session->context->observe_save_file->s);
  strcat(new, ".tmp");
  fp_new = fopen(new, "w+");
  if (fp_new == NULL)
    goto fail;

  /* Go through and locate observe entry to delete and not copy it across */
  while (1) {
    if (!coap_op_observe_read(fp_orig, &observe_key, &e_proto, &e_listen_addr,
                              &s_addr_info, &raw_packet, &oscore_info))
      break;
    if (observe_key != d_observe_key) {
      if (!coap_op_observe_write(fp_new, observe_key, e_proto, e_listen_addr,
                                 s_addr_info, (coap_bin_const_t *)raw_packet,
                                 (coap_bin_const_t *)oscore_info))
        goto fail;
    }
    coap_delete_bin_const(raw_packet);
    raw_packet = NULL;
    coap_delete_bin_const(oscore_info);
    oscore_info = NULL;
  }
  coap_delete_bin_const(raw_packet);
  raw_packet = NULL;
  coap_delete_bin_const(oscore_info);
  oscore_info = NULL;

  if (fflush(fp_new) == EOF)
    goto fail;
  fclose(fp_new);
  fclose(fp_orig);
  /* Either old or new is in place */
  (void)rename(new, (const char *)session->context->observe_save_file->s);
  coap_free_type(COAP_STRING, new);
  return 1;

fail:
  coap_delete_bin_const(raw_packet);
  coap_delete_bin_const(oscore_info);
  if (fp_new)
    fclose(fp_new);
  if (fp_orig)
    fclose(fp_orig);
  if (new) {
    (void)remove(new);
  }
  coap_free_type(COAP_STRING, new);
  return 0;
}

/*
 * This should be called before coap_persist_track_funcs() to prevent
 * coap_op_obs_cnt_track_observe() getting unnecessarily called.
 * Should be called after coap_op_dyn_resource_load_disk() to make sure that
 * all the resources are in the right place.
 */
static void
coap_op_obs_cnt_load_disk(coap_context_t *context) {
  FILE *fp = fopen((const char *)context->obs_cnt_save_file->s, "r");
  char buf[1500];

  if (fp == NULL)
    return;

  while (fgets(buf, sizeof(buf), fp) != NULL) {
    char *cp = strchr(buf, ' ');
    coap_str_const_t resource_key;
    uint32_t observe_num;
    coap_resource_t *r;

    if (!cp)
      break;

    *cp = '\000';
    cp++;
    observe_num = atoi(cp);
    /*
     * Need to assume 0 .. (context->observe_save_freq-1) have in addition
     * been sent so need to round up to latest possible send value
     */
    observe_num = ((observe_num + context->observe_save_freq) /
                   context->observe_save_freq) *
                  context->observe_save_freq - 1;
    resource_key.s = (uint8_t *)buf;
    resource_key.length = strlen(buf);
    r = coap_get_resource_from_uri_path(context, &resource_key);
    if (r) {
      coap_log_debug("persist: Initial observe number being updated\n");
      coap_persist_set_observe_num(r, observe_num);
    }
  }
  fclose(fp);
}

/*
 * Called when the observe value of a resource has been changed, but limited
 * to be called every context->context->observe_save_freq to reduce update
 * overheads.
 */
static int
coap_op_obs_cnt_track_observe(coap_context_t *context,
                              coap_str_const_t *resource_name,
                              uint32_t n_observe_num,
                              void *user_data) {
  FILE *fp_orig = fopen((const char *)context->obs_cnt_save_file->s, "r");
  FILE *fp_new = NULL;
  char buf[1500];
  char *new = NULL;

  (void)user_data;

  new = coap_malloc_type(COAP_STRING, context->obs_cnt_save_file->length + 5);
  if (!new)
    goto fail;

  strcpy(new, (const char *)context->obs_cnt_save_file->s);
  strcat(new, ".tmp");
  fp_new = fopen(new, "w+");
  if (fp_new == NULL)
    goto fail;

  /* Go through and locate resource entry to update */
  while (fp_orig && fgets(buf, sizeof(buf), fp_orig) != NULL) {
    char *cp = strchr(buf, ' ');
    uint32_t observe_num;
    coap_bin_const_t resource_key;

    if (!cp)
      break;

    *cp = '\000';
    cp++;
    observe_num = atoi(cp);
    resource_key.s = (uint8_t *)buf;
    resource_key.length = strlen(buf);
    if (!coap_binary_equal(resource_name, &resource_key)) {
      if (fprintf(fp_new, "%s %u\n", resource_key.s, observe_num) < 0)
        goto fail;
    }
  }
  if (fprintf(fp_new, "%s %u\n", resource_name->s, n_observe_num) < 0)
    goto fail;
  if (fflush(fp_new) == EOF)
    goto fail;
  fclose(fp_new);
  if (fp_orig)
    fclose(fp_orig);
  /* Either old or new is in place */
  (void)rename(new, (const char *)context->obs_cnt_save_file->s);
  coap_free_type(COAP_STRING, new);
  return 1;

fail:
  if (fp_new)
    fclose(fp_new);
  if (fp_orig)
    fclose(fp_orig);
  if (new) {
    (void)remove(new);
  }
  coap_free_type(COAP_STRING, new);
  return 0;
}

/*
 * Called when a resource has been deleted.
 */
static int
coap_op_obs_cnt_deleted(coap_context_t *context,
                        coap_str_const_t *resource_name) {
  FILE *fp_orig = fopen((const char *)context->obs_cnt_save_file->s, "r");
  FILE *fp_new = NULL;
  char buf[1500];
  char *new = NULL;

  if (fp_orig == NULL)
    goto fail;
  new = coap_malloc_type(COAP_STRING, context->obs_cnt_save_file->length + 5);
  if (!new)
    goto fail;

  strcpy(new, (const char *)context->obs_cnt_save_file->s);
  strcat(new, ".tmp");
  fp_new = fopen(new, "w+");
  if (fp_new == NULL)
    goto fail;

  /* Go through and locate resource entry to delete */
  while (fgets(buf, sizeof(buf), fp_orig) != NULL) {
    char *cp = strchr(buf, ' ');
    uint32_t observe_num;
    coap_bin_const_t resource_key;

    if (!cp)
      break;

    *cp = '\000';
    cp++;
    observe_num = atoi(cp);
    resource_key.s = (uint8_t *)buf;
    resource_key.length = strlen(buf);
    if (!coap_binary_equal(resource_name, &resource_key)) {
      if (fprintf(fp_new, "%s %u\n", resource_key.s, observe_num) < 0)
        goto fail;
    }
  }
  if (fflush(fp_new) == EOF)
    goto fail;
  fclose(fp_new);
  fclose(fp_orig);
  /* Either old or new is in place */
  (void)rename(new, (const char *)context->obs_cnt_save_file->s);
  coap_free_type(COAP_STRING, new);
  return 1;

fail:
  if (fp_new)
    fclose(fp_new);
  if (fp_orig)
    fclose(fp_orig);
  if (new) {
    (void)remove(new);
  }
  coap_free_type(COAP_STRING, new);
  return 0;
}

/*
 * read in dynamic resource entry, allocating name & raw_packet
 * which need to be freed off by caller.
 */
static int
coap_op_dyn_resource_read(FILE *fp, coap_proto_t *e_proto,
                          coap_string_t **name,
                          coap_binary_t **raw_packet) {
  ssize_t size;

  *name = NULL;
  *raw_packet = NULL;

  if (fread(e_proto, sizeof(*e_proto), 1, fp) == 1) {
    /* New record 'proto len resource_name len raw_packet' */
    if (fread(&size, sizeof(size), 1, fp) != 1)
      goto fail;
    if (size < 0 || size > 0x10000)
      goto fail;
    *name = coap_new_string(size);
    if (!(*name))
      goto fail;
    if (fread((*name)->s, size, 1, fp) != 1)
      goto fail;
    if (fread(&size, sizeof(size), 1, fp) != 1)
      goto fail;
    if (size < 0 || size > 0x10000)
      goto fail;
    *raw_packet = coap_new_binary(size);
    if (!(*raw_packet))
      goto fail;
    if (fread((*raw_packet)->s, size, 1, fp) != 1)
      goto fail;
    return 1;
  }
fail:
  return 0;
}

/*
 * write out dynamic resource entry.
 */
static int
coap_op_dyn_resource_write(FILE *fp, coap_proto_t e_proto,
                           coap_str_const_t *name,
                           coap_bin_const_t *raw_packet) {
  if (fwrite(&e_proto, sizeof(e_proto), 1, fp) != 1)
    goto fail;
  if (fwrite(&name->length, sizeof(name->length), 1, fp) != 1)
    goto fail;
  if (fwrite(name->s, name->length, 1, fp) != 1)
    goto fail;
  if (fwrite(&raw_packet->length, sizeof(raw_packet->length), 1, fp) != 1)
    goto fail;
  if (fwrite(raw_packet->s, raw_packet->length, 1, fp) != 1)
    goto fail;
  return 1;
fail:
  return 0;
}

/*
 * This should be called before coap_persist_track_funcs() to prevent
 * coap_op_dyn_resource_added() getting unnecessarily called.
 *
 * Each record 'proto len resource_name len raw_packet'
 */
static void
coap_op_dyn_resource_load_disk(coap_context_t *ctx) {
  FILE *fp_orig = NULL;
  coap_proto_t e_proto;
  coap_string_t *name = NULL;
  coap_binary_t *raw_packet = NULL;
  coap_resource_t *r;
  coap_session_t *session = NULL;
  coap_pdu_t *request = NULL;
  coap_pdu_t *response = NULL;
  coap_string_t *query = NULL;

  if (!ctx->unknown_resource)
    return;

  fp_orig = fopen((const char *)ctx->dyn_resource_save_file->s, "r");
  if (fp_orig == NULL)
    return;
  session = (coap_session_t *)coap_malloc_type(COAP_SESSION,
                                               sizeof(coap_session_t));
  if (!session)
    goto fail;
  memset(session, 0, sizeof(coap_session_t));
  session->context = ctx;

  /* Go through and create each dynamic resource if it does not exist*/
  while (1) {
    if (!coap_op_dyn_resource_read(fp_orig, &e_proto, &name, &raw_packet))
      break;
    r = coap_get_resource_from_uri_path(ctx, (coap_str_const_t *)name);
    if (!r) {
      /* Create the new resource using the application logic */

      coap_log_debug("persist: dynamic resource being re-created\n");
      /*
       * Need max space incase PDU is updated with updated token,
       * huge size etc.
       * */
      request = coap_pdu_init(0, 0, 0, 0);
      if (!request)
        goto fail;

      session->proto = e_proto;
      if (!coap_pdu_parse(session->proto, raw_packet->s,
                          raw_packet->length, request)) {
        goto fail;
      }
      if (!ctx->unknown_resource->handler[request->code-1])
        goto fail;
      response = coap_pdu_init(0, 0, 0, 0);
      if (!response)
        goto fail;
      query = coap_get_query(request);
      /* Call the application handler to set up this dynamic resource */
      coap_lock_callback(ctx,
                         ctx->unknown_resource->handler[request->code-1](ctx->unknown_resource,
                             session, request,
                             query, response));
      coap_delete_string(query);
      query = NULL;
      coap_delete_pdu(request);
      request = NULL;
      coap_delete_pdu(response);
      response = NULL;
    }
    coap_delete_string(name);
    coap_delete_binary(raw_packet);
  }
fail:
  coap_delete_string(name);
  coap_delete_binary(raw_packet);
  coap_delete_string(query);
  coap_delete_pdu(request);
  coap_delete_pdu(response);
  fclose(fp_orig);
  coap_free_type(COAP_SESSION, session);
}

/*
 * Server has set up a new dynamic resource agains a request for an unknown
 * resource.
 */
static int
coap_op_dyn_resource_added(coap_session_t *session,
                           coap_str_const_t *resource_name,
                           coap_bin_const_t *packet,
                           void *user_data) {
  FILE *fp_orig;
  FILE *fp_new = NULL;
  char *new = NULL;
  coap_context_t *context = session->context;
  coap_string_t *name = NULL;
  coap_binary_t *raw_packet = NULL;
  coap_proto_t e_proto;

  (void)user_data;

  fp_orig = fopen((const char *)context->dyn_resource_save_file->s, "a");
  if (fp_orig == NULL)
    return 0;

  new = coap_malloc_type(COAP_STRING,
                         context->dyn_resource_save_file->length + 5);
  if (!new)
    goto fail;

  strcpy(new, (const char *)context->dyn_resource_save_file->s);
  strcat(new, ".tmp");
  fp_new = fopen(new, "w+");
  if (fp_new == NULL)
    goto fail;

  /* Go through and locate duplicate resource to delete */
  while (1) {
    if (!coap_op_dyn_resource_read(fp_orig, &e_proto, &name, &raw_packet))
      break;
    if (!coap_string_equal(resource_name, name)) {
      /* Copy across non-matching entry */
      if (!coap_op_dyn_resource_write(fp_new, e_proto, (coap_str_const_t *)name,
                                      (coap_bin_const_t *)raw_packet))
        break;
    }
    coap_delete_string(name);
    name = NULL;
    coap_delete_binary(raw_packet);
    raw_packet = NULL;
  }
  coap_delete_string(name);
  coap_delete_binary(raw_packet);
  /* Add new entry to the end */
  if (!coap_op_dyn_resource_write(fp_new, session->proto,
                                  resource_name, packet))
    goto fail;

  if (fflush(fp_new) == EOF)
    goto fail;
  fclose(fp_new);
  fclose(fp_orig);
  /* Either old or new is in place */
  (void)rename(new, (const char *)context->dyn_resource_save_file->s);
  coap_free_type(COAP_STRING, new);
  return 1;

fail:
  if (fp_new)
    fclose(fp_new);
  if (fp_orig)
    fclose(fp_orig);
  if (new) {
    (void)remove(new);
  }
  coap_free_type(COAP_STRING, new);
  return 0;
}

/*
 * Server has deleted a resource
 */
static int
coap_op_resource_deleted(coap_context_t *context,
                         coap_str_const_t *resource_name,
                         void *user_data) {
  FILE *fp_orig = NULL;
  FILE *fp_new = NULL;
  char *new = NULL;
  coap_proto_t e_proto;
  coap_string_t *name = NULL;
  coap_binary_t *raw_packet = NULL;
  (void)user_data;

  coap_op_obs_cnt_deleted(context, resource_name);

  fp_orig = fopen((const char *)context->dyn_resource_save_file->s, "r");
  if (fp_orig == NULL)
    return 1;

  new = coap_malloc_type(COAP_STRING,
                         context->dyn_resource_save_file->length + 5);
  if (!new)
    goto fail;

  strcpy(new, (const char *)context->dyn_resource_save_file->s);
  strcat(new, ".tmp");
  fp_new = fopen(new, "w+");
  if (fp_new == NULL)
    goto fail;

  /* Go through and locate resource to delete and not copy it across */
  while (1) {
    if (!coap_op_dyn_resource_read(fp_orig, &e_proto, &name, &raw_packet))
      break;
    if (!coap_string_equal(resource_name, name)) {
      /* Copy across non-matching entry */
      if (!coap_op_dyn_resource_write(fp_new, e_proto, (coap_str_const_t *)name,
                                      (coap_bin_const_t *)raw_packet))
        break;
    }
    coap_delete_string(name);
    name = NULL;
    coap_delete_binary(raw_packet);
    raw_packet = NULL;
  }
  coap_delete_string(name);
  coap_delete_binary(raw_packet);

  if (fflush(fp_new) == EOF)
    goto fail;
  fclose(fp_new);
  fclose(fp_orig);
  /* Either old or new is in place */
  (void)rename(new, (const char *)context->dyn_resource_save_file->s);
  coap_free_type(COAP_STRING, new);
  return 1;

fail:
  if (fp_new)
    fclose(fp_new);
  if (fp_orig)
    fclose(fp_orig);
  if (new) {
    (void)remove(new);
  }
  coap_free_type(COAP_STRING, new);
  return 0;
}

int
coap_persist_startup(coap_context_t *context,
                     const char *dyn_resource_save_file,
                     const char *observe_save_file,
                     const char *obs_cnt_save_file,
                     uint32_t save_freq) {
  coap_lock_check_locked(context);
  if (dyn_resource_save_file) {
    context->dyn_resource_save_file =
        coap_new_bin_const((const uint8_t *)dyn_resource_save_file,
                           strlen(dyn_resource_save_file));
    if (!context->dyn_resource_save_file)
      return 0;
    coap_op_dyn_resource_load_disk(context);
    context->dyn_resource_added = coap_op_dyn_resource_added;
    context->resource_deleted = coap_op_resource_deleted;
  }
  if (obs_cnt_save_file) {
    context->obs_cnt_save_file =
        coap_new_bin_const((const uint8_t *)obs_cnt_save_file,
                           strlen(obs_cnt_save_file));
    if (!context->obs_cnt_save_file)
      return 0;
    context->observe_save_freq = save_freq ? save_freq : 1;
    coap_op_obs_cnt_load_disk(context);
    context->track_observe_value = coap_op_obs_cnt_track_observe;
    context->resource_deleted = coap_op_resource_deleted;
  }
  if (observe_save_file) {
    context->observe_save_file =
        coap_new_bin_const((const uint8_t *)observe_save_file,
                           strlen(observe_save_file));
    if (!context->observe_save_file)
      return 0;
    coap_op_observe_load_disk(context);
    context->observe_added = coap_op_observe_added;
    context->observe_deleted = coap_op_observe_deleted;
  }
  return 1;
}

void
coap_persist_cleanup(coap_context_t *context) {
  coap_delete_bin_const(context->dyn_resource_save_file);
  coap_delete_bin_const(context->obs_cnt_save_file);
  coap_delete_bin_const(context->observe_save_file);
  context->dyn_resource_save_file = NULL;
  context->obs_cnt_save_file = NULL;
  context->observe_save_file = NULL;

  /* Close down any tracking */
  coap_persist_track_funcs(context, NULL, NULL, NULL, NULL,
                           NULL, 0, NULL);
}

void
coap_persist_stop(coap_context_t *context) {
  if (context == NULL)
    return;
  coap_lock_check_locked(context);
  context->observe_no_clear = 1;
  coap_persist_cleanup(context);
}
#else /* ! COAP_WITH_OBSERVE_PERSIST */
int
coap_persist_startup(coap_context_t *context,
                     const char *dyn_resource_save_file,
                     const char *observe_save_file,
                     const char *obs_cnt_save_file,
                     uint32_t save_freq) {
  (void)context;
  (void)dyn_resource_save_file;
  (void)observe_save_file;
  (void)obs_cnt_save_file;
  (void)save_freq;
  return 0;
}

void
coap_persist_stop(coap_context_t *context) {
  context->observe_no_clear = 1;
  /* Close down any tracking */
  coap_persist_track_funcs(context, NULL, NULL, NULL, NULL,
                           NULL, 0, NULL);
}

#endif /* ! COAP_WITH_OBSERVE_PERSIST */

#endif /* COAP_SERVER_SUPPORT */
