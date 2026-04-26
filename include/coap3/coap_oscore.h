/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/*
 * coap_oscore.h -- Object Security for Constrained RESTful Environments
 *                  (OSCORE) support for libcoap
 *
 * Copyright (C) 2019-2026 Olaf Bergmann <bergmann@tzi.org>
 * Copyright (C) 2021-2026 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_oscore.h
 * @brief CoAP OSCORE support
 */

#ifndef COAP_OSCORE_H_
#define COAP_OSCORE_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup application_api
 * @defgroup oscore OSCORE Support
 * API functions for interfacing with OSCORE (RFC8613)
 * @{
 */

/**
 * Callback function type for overriding oscore_find_context().
 *
 * If set via coap_oscore_register_external_handlers(), this function is
 * called before the internal oscore_find_context() to locate the OSCORE
 * recipient and security context for an incoming request.
 *
 * The implementation of this function should be combined with
 * @ref coap_oscore_update_seq_num_handler_t if sequence counter management is required.
 * Otherwise, libcoap will lose those values
 * and replay protection will not work properly.
 *
 * @param session    The active CoAP session receiving the request from.
 * @param rcpkey_id  The Recipient Key ID (KID).
 * @param ctxkey_id  The ID Context to match or NULL.
 *
 * @return The OSCORE config retrieved from the custom OSCORE storage or NULL if not found.
 *         Will fallback to libcoap internal credential storage lookup.
 */
typedef coap_oscore_conf_t *(*coap_oscore_find_handler_t)(
    const coap_session_t    *session,
    const coap_bin_const_t  *rcpkey_id,
    const coap_bin_const_t  *ctxkey_id
);

/**
 * Callback function type for persisting the OSCORE receiver sequence number
 * and anti-replay sliding window to an external storage.
 *
 * Called by the library whenever the Receiver Sequence Number or the
 * anti-replay window is updated, giving the application the opportunity to
 * store both values for external OSCORE credential management. Required
 * to provide those values via the coap_oscore_find_handler_t callback, since
 * the values will otherwise be lost.
 *
 * @param session           The active CoAP session receiving the request from.
 * @param rcpkey_id         The Recipient ID for which the sequence number and window applies.
 * @param ctxkey_id         The ID Context for which the sequence number and window applies.
 * @param receiver_seq_num  The receiver sequence number.
 * @param seq_num_window    The 64-bit anti-replay sliding window bitmask.
 * @return @c 1 if persisted successfully, else @c 0.
 */
typedef int (*coap_oscore_update_seq_num_handler_t)(
    const coap_session_t *session,
    const coap_bin_const_t *rcpkey_id,
    const coap_bin_const_t *ctxkey_id,
    uint64_t             receiver_seq_num,
    uint64_t             seq_num_window
);

/**
 * Creates a new client session to the designated server, protecting the data
 * using OSCORE.
 *
 * @deprecated Use coap_new_client_session_oscore3() instead.
 *
 * @param ctx The CoAP context.
 * @param local_if Address of local interface. It is recommended to use NULL
 *                 to let the operating system choose a suitable local
 *                 interface. If an address is specified, the port number
 *                 should be zero, which means that a free port is
 *                 automatically selected.
 * @param server The server's address. If the port number is zero, the default
 *               port for the protocol will be used.
 * @param proto  CoAP Protocol.
 * @param oscore_conf OSCORE configuration information. This structure is
 *                    freed off by this call.
 *
 * @return A new CoAP session or NULL if failed. Call coap_session_release()
 *         to free.
 */
COAP_API coap_session_t *coap_new_client_session_oscore(coap_context_t *ctx,
                                                        const coap_address_t *local_if,
                                                        const coap_address_t *server,
                                                        coap_proto_t proto,
                                                        coap_oscore_conf_t *oscore_conf);

/**
 * Creates a new client session to the designated server, protecting the data
 * using OSCORE, along with app_data information (as per coap_session_set_app_data2())
 * and optional WebSockets host (as per coap_ws_set_host_request()) to remove timing
 * window call-back in startup instead of doing
 *   coap_new_client_session_oscore();
 *   coap_session_set_app_data2();
 * or
 *   coap_new_client_session_oscore();
 *   coap_ws_set_host_request();
 *
 * @param ctx The CoAP context.
 * @param local_if Address of local interface. It is recommended to use NULL
 *                 to let the operating system choose a suitable local
 *                 interface. If an address is specified, the port number
 *                 should be zero, which means that a free port is
 *                 automatically selected.
 * @param server The server's address. If the port number is zero, the default
 *               port for the protocol will be used.
 * @param proto  CoAP Protocol.
 * @param oscore_conf OSCORE configuration information. This structure is
 *                    freed off by this call.
 * @param app_data The pointer to the application data to store or NULL.
 * @param callback The optional release call-back for app_data on session
 *                 removal or NULL.
 * @param ws_host If proto is COAP_PROTO_WS or COAP_PROTO_WSS, then set the
 *                Host parameter accordingly.
 *
 * @return A new CoAP session or NULL if failed. Call coap_session_release()
 *         to free.
 */
COAP_API coap_session_t *coap_new_client_session_oscore3(coap_context_t *ctx,
                                                         const coap_address_t *local_if,
                                                         const coap_address_t *server,
                                                         coap_proto_t proto,
                                                         coap_oscore_conf_t *oscore_conf,
                                                         void *app_data,
                                                         coap_app_data_free_callback_t callback,
                                                         coap_str_const_t *ws_host);

/**
 * Creates a new client session to the designated server with PSK credentials
 * as well as protecting the data using OSCORE.
 *
 * @deprecated Use coap_new_client_session_oscore_psk3() instead.
 *
 * @param ctx The CoAP context.
 * @param local_if Address of local interface. It is recommended to use NULL to
 *                 let the operating system choose a suitable local interface.
 *                 If an address is specified, the port number should be zero,
 *                 which means that a free port is automatically selected.
 * @param server The server's address. If the port number is zero, the default
 *               port for the protocol will be used.
 * @param proto CoAP Protocol.
 * @param psk_data PSK parameters.
 * @param oscore_conf OSCORE configuration information. This structure is
 *                    freed off by this call.
 *
 * @return A new CoAP session or NULL if failed. Call coap_session_release()
 *         to free.
 */
COAP_API coap_session_t *coap_new_client_session_oscore_psk(coap_context_t *ctx,
                                                            const coap_address_t *local_if,
                                                            const coap_address_t *server,
                                                            coap_proto_t proto,
                                                            coap_dtls_cpsk_t *psk_data,
                                                            coap_oscore_conf_t *oscore_conf);

/**
 * Creates a new client session to the designated server, with PSK credentials
 * protecting the data using OSCORE, along with app_data information (as per
 * coap_session_set_app_data2()) and optional WebSockets host (as per
 * coap_ws_set_host_request()) to remove timing window call-back in (D)TLS startup
 * instead of doing
 *   coap_new_client_session_oscore_psk();
 *   coap_session_set_app_data2();
 * or
 *   coap_new_client_session_oscore_psk();
 *   coap_ws_set_host_request();
 *
 * @param ctx The CoAP context.
 * @param local_if Address of local interface. It is recommended to use NULL to
 *                 let the operating system choose a suitable local interface.
 *                 If an address is specified, the port number should be zero,
 *                 which means that a free port is automatically selected.
 * @param server The server's address. If the port number is zero, the default
 *               port for the protocol will be used.
 * @param proto CoAP Protocol.
 * @param psk_data PSK parameters.
 * @param oscore_conf OSCORE configuration information. This structure is
 *                    freed off by this call.
 * @param app_data The pointer to the application data to store or NULL.
 * @param callback The optional release call-back for app_data on session
 *                 removal or NULL.
 * @param ws_host If proto is COAP_PROTO_WS or COAP_PROTO_WSS, then set the
 *                Host parameter accordingly.
 *
 * @return A new CoAP session or NULL if failed. Call coap_session_release()
 *         to free.
 */
COAP_API coap_session_t *coap_new_client_session_oscore_psk3(coap_context_t *ctx,
    const coap_address_t *local_if,
    const coap_address_t *server,
    coap_proto_t proto,
    coap_dtls_cpsk_t *psk_data,
    coap_oscore_conf_t *oscore_conf,
    void *app_data,
    coap_app_data_free_callback_t callback,
    coap_str_const_t *ws_host);

/**
 * Creates a new client session to the designated server with PKI credentials
 * as well as protecting the data using OSCORE.
 *
 * @deprecated Use coap_new_client_session_oscore_pki3() instead.
 *
 * @param ctx The CoAP context.
 * @param local_if Address of local interface. It is recommended to use NULL to
 *                 let the operating system choose a suitable local interface.
 *                 If an address is specified, the port number should be zero,
 *                 which means that a free port is automatically selected.
 * @param server The server's address. If the port number is zero, the default
 *               port for the protocol will be used.
 * @param proto CoAP Protocol.
 * @param pki_data PKI parameters.
 * @param oscore_conf OSCORE configuration information. This structure is
 *                    freed off by this call.
 *
 * @return A new CoAP session or NULL if failed. Call coap_session_release()
 *         to free.
 */
COAP_API coap_session_t *coap_new_client_session_oscore_pki(coap_context_t *ctx,
                                                            const coap_address_t *local_if,
                                                            const coap_address_t *server,
                                                            coap_proto_t proto,
                                                            coap_dtls_pki_t *pki_data,
                                                            coap_oscore_conf_t *oscore_conf);

/**
 * Creates a new client session to the designated server, with PKI credentials
 * protecting the data using OSCORE, along with app_data information (as per
 * coap_session_set_app_data2()) and optional WebSockets host (as per
 * coap_ws_set_host_request()) to remove timing window call-back in (D)TLS startup
 * instead of doing
 *   coap_new_client_session_oscore_pki();
 *   coap_session_set_app_data2();
 * or
 *   coap_new_client_session_oscore_pki();
 *   coap_ws_set_host_request();
 *
 * @param ctx The CoAP context.
 * @param local_if Address of local interface. It is recommended to use NULL to
 *                 let the operating system choose a suitable local interface.
 *                 If an address is specified, the port number should be zero,
 *                 which means that a free port is automatically selected.
 * @param server The server's address. If the port number is zero, the default
 *               port for the protocol will be used.
 * @param proto CoAP Protocol.
 * @param pki_data PKI parameters.
 * @param oscore_conf OSCORE configuration information. This structure is
 *                    freed off by this call.
 * @param app_data The pointer to the application data to store or NULL.
 * @param callback The optional release call-back for app_data on session
 *                 removal or NULL.
 * @param ws_host If proto is COAP_PROTO_WS or COAP_PROTO_WSS, then set the
 *                Host parameter accordingly.
 *
 * @return A new CoAP session or NULL if failed. Call coap_session_release()
 *         to free.
 */
COAP_API coap_session_t *coap_new_client_session_oscore_pki3(coap_context_t *ctx,
    const coap_address_t *local_if,
    const coap_address_t *server,
    coap_proto_t proto,
    coap_dtls_pki_t *pki_data,
    coap_oscore_conf_t *oscore_conf,
    void *app_data,
    coap_app_data_free_callback_t callback,
    coap_str_const_t *ws_host);

/**
 * Set the context's default OSCORE configuration for a server.
 *
 * @param context     The current coap_context_t object.
 * @param oscore_conf OSCORE configuration information. This structure is
 *                    freed off by this call.
 *
 * @return @c 1 if successful, else @c 0.
 */
COAP_API int coap_context_oscore_server(coap_context_t *context,
                                        coap_oscore_conf_t *oscore_conf);

/**
 * Definition of the function used to save the current Sender Sequence Number
 *
 * @param sender_seq_num The Sender Sequence Number to save in non-volatile
 *                      memory.
 * @param param The save_seq_num_func_param provided to
 *              coap_new_oscore_context().
 *
 * @return @c 1 if success, else @c 0 if a failure of some sort.
 */
typedef int (*coap_oscore_save_seq_num_t)(uint64_t sender_seq_num, void *param);

/**
 * Parse an OSCORE configuration (held in memory) and populate a OSCORE
 * configuration structure.
 *
 * @param conf_mem    The current configuration in memory.
 * @param save_seq_num_func Function to call to save Sender Sequence Number in
 *                          non-volatile memory, or NULL.
 * @param save_seq_num_func_param Parameter to pass into
 *                          save_seq_num_func() function.
 * @param start_seq_num The Sender Sequence Number to start with following a
 *                      reboot retrieved out of non-volatile menory or 0.
 *
 * @return The new OSCORE configuration. NULL if failed.  It needs to be freed
 *         off with coap_delete_oscore_conf() when no longer required,
 *         otherwise it is freed off when coap_free_context() is called.
 */
coap_oscore_conf_t *coap_new_oscore_conf(coap_str_const_t conf_mem,
                                         coap_oscore_save_seq_num_t save_seq_num_func,
                                         void *save_seq_num_func_param,
                                         uint64_t start_seq_num);

/**
 * Release all the information associated with the OSCORE configuration.
 *
 * @param oscore_conf The OSCORE configuration structure to release.
 *
 * @return @c 1 Successfully released, else @c 0 if not valid.
 */
int coap_delete_oscore_conf(coap_oscore_conf_t *oscore_conf);

/**
 * Register external storage handlers for OSCORE session state.
 *
 * Allows providing a custom OSCORE credential storage for
 * persistence and optimized for the needs of the application.
 * Expands the built-in OSCORE context lookup and enables management
 * of persistent OSCORE data (sequence numbers and Echo challenges)
 * from within the application.
 *
 * @param context                 The CoAP context to configure.
 * @param find_handler            Inject a customized OSCORE config-lookup function
 *                                to return temporary oscore credentials managed by
 *                                an external credential store (see coap_oscore_find_handler_t),
 *                                or @c NULL to only use the built-in oscore_find_context().
 * @param update_seq_num_handler  Called whenever the Sender Sequence Number
 *                                or anti-replay window changes.  Use this
 *                                to synchronize values with the external
 *                                credential storage.  @c NULL to disable.
 *                                If find_handler is set, then it is recommended that
 *                                update_seq_num_handler is set.
 */
COAP_API void coap_oscore_register_external_handlers(
    coap_context_t                   *context,
    coap_oscore_find_handler_t           find_handler,
    coap_oscore_update_seq_num_handler_t update_seq_num_handler);

/**
 * Add in the specific Recipient ID into the OSCORE context (server only).
 * Note: This is only added to the OSCORE context as first defined by
 * coap_new_client_session_oscore*() or coap_context_oscore_server().
 *
 * @param context The CoAP context to add the OSCORE recipient_id to.
 * @param recipient_id The Recipient ID to add. Ownership of memory moves into the function
 *                     and will be freed off when the context is freed or if the
 *                     function fails.
 *
 * @return @c 1 Successfully added, else @c 0 there is an issue.
 */
COAP_API int coap_new_oscore_recipient(coap_context_t *context,
                                       coap_bin_const_t *recipient_id);

/**
 * Release all the information associated for the specific Recipient ID
 * (and hence stop any further OSCORE protection for this Recipient).
 * Note: This is only removed from the OSCORE context as first defined by
 * coap_new_client_session_oscore*() or coap_context_oscore_server().
 *
 * @param context The CoAP context holding the OSCORE recipient_id to be removed.
 * @param recipient_id The Recipient ID to remove.
 *
 * @return @c 1 Successfully removed, else @c 0 not found.
 */
COAP_API int coap_delete_oscore_recipient(coap_context_t *context,
                                          coap_bin_const_t *recipient_id);

/**
 * Set the latest sequence number and sliding window for the specified recipient
 * id in the compiled configuration file.
 *
 * @param oscore_conf The compiled configuration file.
 * @param recipient_id The Recipient ID to update in @p oscore_conf.
 * @param last_seq The sequence number to update the recipient id with.
 * @param seq_window The sliding window to update the recipient id with.
 *
 * @return @c 1 Successfully updated, else @c 0 recipient id not found.
 */
COAP_API int coap_oscore_recipient_set_latest_seq(coap_oscore_conf_t *oscore_conf,
                                                  const coap_bin_const_t *recipient_id,
                                                  uint64_t last_seq,
                                                  uint64_t seq_window);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* COAP_OSCORE_H */
