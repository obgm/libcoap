/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/*
 * coap_oscore.h -- Object Security for Constrained RESTful Environments
 *                  (OSCORE) support for libcoap
 *
 * Copyright (C) 2019-2024 Olaf Bergmann <bergmann@tzi.org>
 * Copyright (C) 2021-2024 Jon Shallow <supjps-libcoap@jpshallow.com>
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

/**
 * @ingroup application_api
 * @defgroup oscore OSCORE Support
 * API functions for interfacing with OSCORE (RFC8613)
 * @{
 */

/**
 * Check whether OSCORE is available.
 *
 * @return @c 1 if support for OSCORE is enabled, or @c 0 otherwise.
 */
int coap_oscore_is_supported(void);

/**
 * Creates a new client session to the designated server, protecting the data
 * using OSCORE.
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
coap_session_t *coap_new_client_session_oscore(coap_context_t *ctx,
                                               const coap_address_t *local_if,
                                               const coap_address_t *server,
                                               coap_proto_t proto,
                                               coap_oscore_conf_t *oscore_conf);

/**
 * Creates a new client session to the designated server with PSK credentials
 * as well as protecting the data using OSCORE.
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
coap_session_t *coap_new_client_session_oscore_psk(coap_context_t *ctx,
                                                   const coap_address_t *local_if,
                                                   const coap_address_t *server,
                                                   coap_proto_t proto,
                                                   coap_dtls_cpsk_t *psk_data,
                                                   coap_oscore_conf_t *oscore_conf);

/**
 * Creates a new client session to the designated server with PKI credentials
 * as well as protecting the data using OSCORE.
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
coap_session_t *coap_new_client_session_oscore_pki(coap_context_t *ctx,
                                                   const coap_address_t *local_if,
                                                   const coap_address_t *server,
                                                   coap_proto_t proto,
                                                   coap_dtls_pki_t *pki_data,
                                                   coap_oscore_conf_t *oscore_conf);

/**
 * Set the context's default OSCORE configuration for a server.
 *
 * @param context     The current coap_context_t object.
 * @param oscore_conf OSCORE configuration information. This structure is
 *                    freed off by this call.
 *
 * @return @c 1 if successful, else @c 0.
 */
int coap_context_oscore_server(coap_context_t *context,
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
 * @return @c 1 Successfully removed, else @c 0 not found.
 */
int coap_delete_oscore_conf(coap_oscore_conf_t *oscore_conf);

/**
 * Add in the specific Recipient ID into the OSCORE context (server only).
 * Note: This is only added to the OSCORE context as first defined by
 * coap_new_client_session_oscore*() or coap_context_oscore_server().
 *
 * @param context The CoAP  context to add the OSCORE recipient_id to.
 * @param recipient_id The Recipient ID to add.
 *
 * @return @c 1 Successfully added, else @c 0 there is an issue.
 */
int coap_new_oscore_recipient(coap_context_t *context,
                              coap_bin_const_t *recipient_id);

/**
 * Release all the information associated for the specific Recipient ID
 * (and hence and stop any further OSCORE protection for this Recipient).
 * Note: This is only removed from the OSCORE context as first defined by
 * coap_new_client_session_oscore*() or coap_context_oscore_server().
 *
 * @param context The CoAP  context holding the OSCORE recipient_id to.
 * @param recipient_id The Recipient ID to remove.
 *
 * @return @c 1 Successfully removed, else @c 0 not found.
 */
int coap_delete_oscore_recipient(coap_context_t *context,
                                 coap_bin_const_t *recipient_id);

/** @} */

#endif /* COAP_OSCORE_H */
