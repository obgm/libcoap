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

#define coap_add_data_large_request(a,b,c,d,e,f)        coap_add_data_large_request_locked(a,b,c,d,e,f)
#define coap_add_data_large_response(a,b,c,d,e,f,g,h,i,j,k,l) coap_add_data_large_response_locked(a,b,c,d,e,f,g,h,i,j,k,l)
#define coap_add_resource(c,r)                          coap_add_resource_locked(c,r)
#define coap_async_trigger(a)                           coap_async_trigger_locked(a)
#define coap_async_set_delay(a,d)                       coap_async_set_delay_locked(a,d)
#define coap_cache_get_by_key(s,c)                      coap_cache_get_by_key_locked(s,c)
#define coap_cache_get_by_pdu(s,r,b)                    coap_cache_get_by_pdu_locked(s,r,b)
#define coap_cache_ignore_options(c,o,n)                coap_cache_ignore_options_locked(c,o,n)
#define coap_can_exit(c)                                coap_can_exit_locked(c)
#define coap_cancel_observe(s,t,v)                      coap_cancel_observe_locked(s,t,v)
#define coap_check_notify(s)                            coap_check_notify_locked(s)
#define coap_context_oscore_server(c,o)                 coap_context_oscore_server_locked(c,o)
#define coap_context_set_block_mode(c,b)                coap_context_set_block_mode_locked(c,b)
#define coap_context_set_max_block_size(c,m)            coap_context_set_max_block_size_locked(c,m)
#define coap_context_set_pki(c,s)                       coap_context_set_pki_locked(c,s)
#define coap_context_set_pki_root_cas(c,f,d)            coap_context_set_pki_root_cas_locked(c,f,d)
#define coap_context_set_psk(c,h,k,l)                   coap_context_set_psk_locked(c,h,k,l)
#define coap_context_set_psk2(c,s)                      coap_context_set_psk2_locked(c,s)
#define coap_find_async(s,t)                            coap_find_async_locked(s,t)
#define coap_delete_oscore_recipient(s,r)               coap_delete_oscore_recipient_locked(s,r)
#define coap_delete_resource(c,r)                       coap_delete_resource_locked(c,r)
#define coap_free_context(c)                            coap_free_context_locked(c)
#define coap_free_endpoint(e)                           coap_free_endpoint_locked(e)
#define coap_get_resource_from_uri_path(c,u)            coap_get_resource_from_uri_path_locked(c,u)
#define coap_io_do_epoll(c,e,n)                         coap_io_do_epoll_locked(c,e,n)
#define coap_io_do_io(c,n)                              coap_io_do_io_locked(c,n)
#define coap_io_pending(c)                              coap_io_pending_locked(c)
#define coap_io_prepare_epoll(c,n)                      coap_io_prepare_epoll_locked(c,n)
#define coap_io_prepare_io(c,s,m,n,t)                   coap_io_prepare_io_locked(c,s,m,n,t)
#define coap_io_process(s,t)                            coap_io_process_locked(s,t)
#define coap_io_process_with_fds(s,t,n,r,w,e)           coap_io_process_with_fds_locked(s,t,n,r,w,e)
#define coap_join_mcast_group_intf(c,g,i)               coap_join_mcast_group_intf_locked(c,g,i)
#define coap_new_cache_entry(s,p,r,b,i)                 coap_new_cache_entry_locked(s,p,r,b,i)
#define coap_new_client_session(c,l,s,p)                coap_new_client_session_locked(c,l,s,p)
#define coap_new_client_session_oscore(c,l,s,p,o)       coap_new_client_session_oscore_locked(c,l,s,p,o)
#define coap_new_client_session_oscore_pki(c,l,s,p,d,o) coap_new_client_session_oscore_pki_locked(c,l,s,p,d,o)
#define coap_new_client_session_oscore_psk(c,l,s,p,d,o) coap_new_client_session_oscore_psk_locked(c,l,s,p,d,o)
#define coap_new_client_session_pki(c,l,s,p,d)          coap_new_client_session_pki_locked(c,l,s,p,d)
#define coap_new_client_session_psk(c,l,s,p,i,k,m)      coap_new_client_session_psk_locked(c,l,s,p,i,k,m)
#define coap_new_client_session_psk2(c,l,s,p,d)         coap_new_client_session_psk2_locked(c,l,s,p,d)
#define coap_new_endpoint(c,l,t)                        coap_new_endpoint_locked(c,l,t)
#define coap_new_message_id(s)                          coap_new_message_id_locked(s)
#define coap_new_oscore_recipient(c,r)                  coap_new_oscore_recipient_locked(c,r)
#define coap_new_pdu(t,c,s)                             coap_new_pdu_locked(t,c,s)
#define coap_persist_observe_add(c,p,l,a,r,o)           coap_persist_observe_add_locked(c,p,l,a,r,o)
#define coap_persist_startup(c,d,o,m,s)                 coap_persist_startup_locked(c,d,o,m,s)
#define coap_persist_stop(c)                            coap_persist_stop_locked(c)
#define coap_pdu_duplicate(o,s,l,t,d)                   coap_pdu_duplicate_locked(o,s,l,t,d)
#define coap_register_async(s,r,d)                      coap_register_async_locked(s,r,d)
#define coap_register_option(c,t)                       coap_register_option_locked(c,t)
#define coap_resource_notify_observers(r,q)             coap_resource_notify_observers_locked(r,q)
#define coap_resource_set_dirty(r,q)                    coap_resource_set_dirty_locked(r,q)
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

int                  coap_add_data_large_request_locked(coap_session_t *session,
                                                        coap_pdu_t *pdu,
                                                        size_t length,
                                                        const uint8_t *data,
                                                        coap_release_large_data_t release_func,
                                                        void *app_ptr);
int                  coap_add_data_large_response_locked(coap_resource_t *resource,
                                                         coap_session_t *session,
                                                         const coap_pdu_t *request,
                                                         coap_pdu_t *response,
                                                         const coap_string_t *query,
                                                         uint16_t media_type,
                                                         int maxage,
                                                         uint64_t etag,
                                                         size_t length,
                                                         const uint8_t *data,
                                                         coap_release_large_data_t release_func,
                                                         void *app_ptr);
void                 coap_add_resource_locked(coap_context_t *context, coap_resource_t *resource);
void                 coap_async_trigger_locked(coap_async_t *async);
void                 coap_async_set_delay_locked(coap_async_t *async, coap_tick_t delay);
coap_cache_entry_t  *coap_cache_get_by_key_locked(coap_context_t *context,
                                                  const coap_cache_key_t *cache_key);
coap_cache_entry_t  *coap_cache_get_by_pdu_locked(coap_session_t *session,
                                                  const coap_pdu_t *request,
                                                  coap_cache_session_based_t session_based);
int                  coap_cache_ignore_options_locked(coap_context_t *ctx,
                                                      const uint16_t *options,
                                                      size_t count);
int                  coap_can_exit_locked(coap_context_t *context);
int                  coap_cancel_observe_locked(coap_session_t *session, coap_binary_t *token,
                                                coap_pdu_type_t type);
void                 coap_check_notify_locked(coap_context_t *context);
int                  coap_context_oscore_server_locked(coap_context_t *context,
                                                       coap_oscore_conf_t *oscore_conf);
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
int                  coap_delete_oscore_recipient_locked(coap_context_t *context,
                                                         coap_bin_const_t *recipient_id);
int                  coap_delete_resource_locked(coap_context_t *context, coap_resource_t *resource);
coap_async_t        *coap_find_async_locked(coap_session_t *session, coap_bin_const_t token);
void                 coap_free_context_locked(coap_context_t *context);
void                 coap_free_endpoint_locked(coap_endpoint_t *ep);
coap_resource_t     *coap_get_resource_from_uri_path_locked(coap_context_t *context,
                                                            coap_str_const_t *uri_path);
void                 coap_io_do_epoll_locked(coap_context_t *ctx, struct epoll_event *events,
                                             size_t nevents);
void                 coap_io_do_io_locked(coap_context_t *ctx, coap_tick_t now);
int                  coap_io_pending_locked(coap_context_t *context);
unsigned int         coap_io_prepare_epoll_locked(coap_context_t *ctx, coap_tick_t now);
unsigned int         coap_io_prepare_io_locked(coap_context_t *ctx,
                                               coap_socket_t *sockets[],
                                               unsigned int max_sockets,
                                               unsigned int *num_sockets,
                                               coap_tick_t now);
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
int                  coap_io_process_locked(coap_context_t *ctx, uint32_t timeout_ms);
int                  coap_io_process_with_fds_locked(coap_context_t *ctx, uint32_t timeout_ms,
                                                     int nfds, fd_set *readfds, fd_set *writefds,
                                                     fd_set *exceptfds);
coap_async_t        *coap_register_async_locked(coap_session_t *session, const coap_pdu_t *request,
                                                coap_tick_t delay);
size_t               coap_session_max_pdu_size_locked(const coap_session_t *session);
coap_cache_entry_t  *coap_new_cache_entry_locked(coap_session_t *session, const coap_pdu_t *pdu,
                                                 coap_cache_record_pdu_t record_pdu,
                                                 coap_cache_session_based_t session_based,
                                                 unsigned int idle_timeout);
coap_session_t      *coap_new_client_session_locked(coap_context_t *ctx,
                                                    const coap_address_t *local_if,
                                                    const coap_address_t *server,
                                                    coap_proto_t proto);
coap_session_t      *coap_new_client_session_oscore_locked(coap_context_t *ctx,
                                                           const coap_address_t *local_if,
                                                           const coap_address_t *server,
                                                           coap_proto_t proto,
                                                           coap_oscore_conf_t *oscore_conf);
coap_session_t      *coap_new_client_session_oscore_pki_locked(coap_context_t *ctx,
                                                               const coap_address_t *local_if,
                                                               const coap_address_t *server,
                                                               coap_proto_t proto,
                                                               coap_dtls_pki_t *pki_data,
                                                               coap_oscore_conf_t *oscore_conf);
coap_session_t      *coap_new_client_session_oscore_psk_locked(coap_context_t *ctx,
                                                               const coap_address_t *local_if,
                                                               const coap_address_t *server,
                                                               coap_proto_t proto,
                                                               coap_dtls_cpsk_t *psk_data,
                                                               coap_oscore_conf_t *oscore_conf);
coap_session_t      *coap_new_client_session_pki_locked(coap_context_t *ctx,
                                                        const coap_address_t *local_if,
                                                        const coap_address_t *server,
                                                        coap_proto_t proto,
                                                        coap_dtls_pki_t *setup_data);
coap_session_t      *coap_new_client_session_psk_locked(coap_context_t *ctx,
                                                        const coap_address_t *local_if,
                                                        const coap_address_t *server,
                                                        coap_proto_t proto, const char *identity,
                                                        const uint8_t *key, unsigned key_len);
coap_session_t      *coap_new_client_session_psk2_locked(coap_context_t *ctx,
                                                         const coap_address_t *local_if,
                                                         const coap_address_t *server,
                                                         coap_proto_t proto,
                                                         coap_dtls_cpsk_t *setup_data);
coap_endpoint_t     *coap_new_endpoint_locked(coap_context_t *context,
                                              const coap_address_t *listen_addr,
                                              coap_proto_t proto);
uint16_t             coap_new_message_id_locked(coap_session_t *session);
int                  coap_new_oscore_recipient_locked(coap_context_t *context,
                                                      coap_bin_const_t *recipient_id);
coap_pdu_t          *coap_new_pdu_locked(coap_pdu_type_t type, coap_pdu_code_t code,
                                         coap_session_t *session);
coap_pdu_t          *coap_pdu_duplicate_locked(const coap_pdu_t *old_pdu,
                                               coap_session_t *session,
                                               size_t token_length,
                                               const uint8_t *token,
                                               coap_opt_filter_t *drop_options);
void                 coap_register_option_locked(coap_context_t *ctx, uint16_t type);
int                  coap_resource_notify_observers_locked(coap_resource_t *r,
                                                           const coap_string_t *query);
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
