/*
 * coap_threadsafe_internal.h -- Mapping of threadsafe functions
 *
 * Copyright (C) 2023-2024 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_threadsafe_internal.h
 * @brief CoAP mapping of locking functions
 */

#ifndef COAP_THREADSAFE_INTERNAL_H_
#define COAP_THREADSAFE_INTERNAL_H_

#if COAP_THREAD_SAFE

/* *INDENT-OFF* */
#ifndef COAP_THREAD_IGNORE_LOCKED_MAPPING

#define coap_context_set_block_mode(c,b)                coap_context_set_block_mode_locked(c,b)
#define coap_context_set_max_block_size(c,m)            coap_context_set_max_block_size_locked(c,m)
#define coap_context_set_pki(c,s)                       coap_context_set_pki_locked(c,s)
#define coap_context_set_pki_root_cas(c,f,d)            coap_context_set_pki_root_cas_locked(c,f,d)
#define coap_context_set_psk(c,h,k,l)                   coap_context_set_psk_locked(c,h,k,l)
#define coap_context_set_psk2(c,s)                      coap_context_set_psk2_locked(c,s)
#define coap_free_endpoint(e)                           coap_free_endpoint_locked(e)
#define coap_join_mcast_group_intf(c,g,i)               coap_join_mcast_group_intf_locked(c,g,i)
#define coap_persist_observe_add(c,p,l,a,r,o)           coap_persist_observe_add_locked(c,p,l,a,r,o)
#define coap_persist_startup(c,d,o,m,s)                 coap_persist_startup_locked(c,d,o,m,s)
#define coap_persist_stop(c)                            coap_persist_stop_locked(c)
#define coap_pdu_duplicate(o,s,l,t,d)                   coap_pdu_duplicate_locked(o,s,l,t,d)
#define coap_register_option(c,t)                       coap_register_option_locked(c,t)
#define coap_send(s,p)                                  coap_send_locked(s,p)
#define coap_send_ack(s,r)                              coap_send_ack_locked(s,r)
#define coap_send_error(s,r,c,o)                        coap_send_error_locked(s,r,c,o)
#define coap_send_message_type(s,r,t)                   coap_send_message_type_locked(s,r,t)
#define coap_send_rst(s,r)                              coap_send_rst_locked(s,r)
#define coap_session_max_pdu_size(s)                    coap_session_max_pdu_size_locked(s)
#define coap_session_reference(s)                       coap_session_reference_locked(s)
#define coap_session_release(s)                         coap_session_release_locked(s)
#define coap_session_disconnected(s,r)                  coap_session_disconnected_locked(s,r)
#define coap_session_send_ping(s)                       coap_session_send_ping_locked(s)

#endif /* ! COAP_THREAD_IGNORE_LOCKED_MAPPING */

/* Locked equivalend functions */

void                 coap_context_set_block_mode_locked(coap_context_t *context,
                                                        uint32_t block_mode);
int                  coap_context_set_max_block_size_locked(coap_context_t *context,
                                                            size_t max_block_size);
int                  coap_context_set_pki_locked(coap_context_t *ctx,
                                                 const coap_dtls_pki_t *setup_data);
int                  coap_context_set_pki_root_cas_locked(coap_context_t *ctx,
                                                          const char *ca_file, const char *ca_dir);
int                  coap_context_set_psk_locked(coap_context_t *ctx, const char *hint,
                                                 const uint8_t *key, size_t key_len);
int                  coap_context_set_psk2_locked(coap_context_t *ctx,
                                                  coap_dtls_spsk_t *setup_data);
void                 coap_free_endpoint_locked(coap_endpoint_t *ep);
int                  coap_join_mcast_group_intf_locked(coap_context_t *ctx, const char *group_name,
                                                       const char *ifname);
coap_subscription_t *coap_persist_observe_add_locked(coap_context_t *context,
                                                     coap_proto_t e_proto,
                                                     const coap_address_t *e_listen_addr,
                                                     const coap_addr_tuple_t *s_addr_info,
                                                     const coap_bin_const_t *raw_packet,
                                                     const coap_bin_const_t *oscore_info);
int                  coap_persist_startup_locked(coap_context_t *context,
                                                 const char *dyn_resource_save_file,
                                                 const char *observe_save_file,
                                                 const char *obs_cnt_save_file,
                                                 uint32_t save_freq);
void                 coap_persist_stop_locked(coap_context_t *context);
size_t               coap_session_max_pdu_size_locked(const coap_session_t *session);
coap_pdu_t          *coap_pdu_duplicate_locked(const coap_pdu_t *old_pdu,
                                               coap_session_t *session,
                                               size_t token_length,
                                               const uint8_t *token,
                                               coap_opt_filter_t *drop_options);
void                 coap_register_option_locked(coap_context_t *ctx, uint16_t type);
int                  coap_resource_set_dirty_locked(coap_resource_t *r,
                                                    const coap_string_t *query);
coap_mid_t          coap_send_locked(coap_session_t *session, coap_pdu_t *pdu);
coap_mid_t          coap_send_ack_locked(coap_session_t *session, const coap_pdu_t *request);
coap_mid_t          coap_send_error_locked(coap_session_t *session, const coap_pdu_t *request,
                                           coap_pdu_code_t code, coap_opt_filter_t *opts);
coap_mid_t          coap_send_message_type_locked(coap_session_t *session,
                                                  const coap_pdu_t *request,
                                                  coap_pdu_type_t type);
coap_mid_t          coap_send_rst_locked(coap_session_t *session, const coap_pdu_t *request);
void                coap_session_disconnected_locked(coap_session_t *session,
                                                     coap_nack_reason_t reason);
coap_session_t     *coap_session_reference_locked(coap_session_t *session);
void                coap_session_release_locked(coap_session_t *session);
coap_mid_t          coap_session_send_ping_locked(coap_session_t *session);

/* *INDENT-ON* */

#endif /* COAP_THREAD_SAFE */

#endif /* COAP_THREADSAFE_INTERNAL_H_ */
