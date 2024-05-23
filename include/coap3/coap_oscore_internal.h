/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/*
 * coap_oscore_internal.h - Object Security for Constrained RESTful Environments
 *                          (OSCORE) support for libcoap
 *
 * Copyright (C) 2019-2024 Olaf Bergmann <bergmann@tzi.org>
 * Copyright (C) 2021-2024 Jon Shallow <supjps-libcoap:jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_oscore_internal.h
 * @brief CoAP OSCORE internal information
 */

#ifndef COAP_OSCORE_INTERNAL_H_
#define COAP_OSCORE_INTERNAL_H_

#include "oscore/oscore_context.h"

/**
 * @ingroup internal_api
 * @defgroup oscore_internal OSCORE Support
 * Internal API for interfacing with OSCORE (RFC8613)
 * @{
 */

/**
 * The structure used to hold the OSCORE configuration information
 */
struct coap_oscore_conf_t {
  coap_bin_const_t *master_secret; /**< Common Master Secret */
  coap_bin_const_t *master_salt;   /**< Common Master Salt */
  coap_bin_const_t *sender_id;     /**< Sender ID (i.e. local our id) */
  coap_bin_const_t *id_context;    /**< Common ID context */
  coap_bin_const_t **recipient_id; /**< Recipient ID (i.e. remote peer id)
                                        Array of recipient_id */
  uint32_t recipient_id_count;     /**< Number of recipient_id entries */
  uint32_t replay_window;          /**< Replay window size
                                        Use COAP_OSCORE_DEFAULT_REPLAY_WINDOW */
  uint32_t ssn_freq;               /**< Sender Seq Num update frequency */
  cose_alg_t aead_alg;             /**< Set to one of COSE_ALGORITHM_AES* */
  cose_hkdf_alg_t hkdf_alg;        /**< Set to one of COSE_HKDF_ALG_* */
  uint32_t rfc8613_b_1_2;          /**< 1 if rfc8613 B.1.2 enabled else 0 */
  uint32_t rfc8613_b_2;            /**< 1 if rfc8613 B.2 protocol else 0 */

  /* General Testing */
  uint32_t break_sender_key;     /**< 1 if sender key to be broken, else 0 */
  uint32_t break_recipient_key;  /**< 1 if recipient key to be broken, else 0 */

  /* SSN handling (not in oscore_config[]) */
  coap_oscore_save_seq_num_t save_seq_num_func; /**< Called every seq num
                                                     change */
  void *save_seq_num_func_param; /**< Passed to save_seq_num_func() */
  uint64_t start_seq_num;        /**< Used for ssn_freq updating */
};

typedef enum oscore_partial_iv_t {
  OSCORE_SEND_NO_IV,  /**< Do not send partial IV unless added by a response */
  OSCORE_SEND_PARTIAL_IV /**< Send partial IV with encrypted PDU */
} oscore_partial_iv_t;

/**
 * Encrypts the specified @p pdu when OSCORE encryption is required
 * on @p session. This function returns the encrypted PDU or @c NULL
 * on error.
 *
 * @param session The session that will handle the transport of the
 *                specified @p pdu.
 * @param pdu     The PDU to encrypt if necessary.
 * @param kid_context Optional kid context to use or NULL.
 * @param send_partial_iv @c OSCORE_SEND_PARTIAL_IV if partial_iv is always to
 *                        be added, else @c OSCORE_SEND_NO_IV if not to be
 *                        added for a response if not required.
 *
 * @return The OSCORE encrypted version of @p pdu, or @c NULL on error.
 */
COAP_API coap_pdu_t *coap_oscore_new_pdu_encrypted(coap_session_t *session,
                                                   coap_pdu_t *pdu,
                                                   coap_bin_const_t *kid_context,
                                                   oscore_partial_iv_t send_partial_iv);

/**
 * Encrypts the specified @p pdu when OSCORE encryption is required
 * on @p session. This function returns the encrypted PDU or @c NULL
 * on error.
 *
 * Note: This function must be called in the locked state.
 *
 * @param session The session that will handle the transport of the
 *                specified @p pdu.
 * @param pdu     The PDU to encrypt if necessary.
 * @param kid_context Optional kid context to use or NULL.
 * @param send_partial_iv @c OSCORE_SEND_PARTIAL_IV if partial_iv is always to
 *                        be added, else @c OSCORE_SEND_NO_IV if not to be
 *                        added for a response if not required.
 *
 * @return The OSCORE encrypted version of @p pdu, or @c NULL on error.
 */
coap_pdu_t *coap_oscore_new_pdu_encrypted_lkd(coap_session_t *session,
                                              coap_pdu_t *pdu,
                                              coap_bin_const_t *kid_context,
                                              oscore_partial_iv_t send_partial_iv);

/**
 * Decrypts the OSCORE-encrypted parts of @p pdu when OSCORE is used.
 * This function returns the decrypted PDU or @c NULL on error.
 *
 * @param session The session that will handle the transport of the
 *                specified @p pdu.
 * @param pdu     The PDU to decrypt if necessary.
 *
 * @return The decrypted @p pdu, or @c NULL on error.
 */
struct coap_pdu_t *coap_oscore_decrypt_pdu(coap_session_t *session,
                                           coap_pdu_t *pdu);

/**
 * Cleanup all allocated OSCORE information.
 *
 * @param context The context that the OSCORE information is associated with.
 */
void coap_delete_all_oscore(coap_context_t *context);

/**
 * Cleanup all allocated OSCORE association information.
 *
 * @param session The session that the OSCORE associations are associated with.
 */
void coap_delete_oscore_associations(coap_session_t *session);

/**
 * Determine the additional data size requirements for adding in OSCORE.
 *
 * @param session The session that the OSCORE associations are associated with.
 * @param pdu The non OSCORE protected PDU that is going to be used.
 *
 * @return The OSCORE packet size overhead.
 */
size_t coap_oscore_overhead(coap_session_t *session, coap_pdu_t *pdu);

/**
 * Convert PDU to use Proxy-Scheme option if Proxy-Uri option is present
 *
 * @param pdu The PDU to check and update if appropriate.
 *
 * @return @c 1 success, else @c 0 failure.
 */
int coap_rebuild_pdu_for_proxy(coap_pdu_t *pdu);

/**
 * Initiate an OSCORE session
 *
 * @param session The session that the OSCORE associations are associated with.
 * @param oscore_conf The OSCORE configuration.
 *
 * @return @c 1 success, else @c 0 failure.
 */
int coap_oscore_initiate(coap_session_t *session,
                         coap_oscore_conf_t *oscore_conf);
/**
 * Set the context's default OSCORE configuration for a server.
 *
 * Note: This function must be called in the locked state.
 *
 * @param context     The current coap_context_t object.
 * @param oscore_conf OSCORE configuration information. This structure is
 *                    freed off by this call.
 *
 * @return @c 1 if successful, else @c 0.
 */
int coap_context_oscore_server_lkd(coap_context_t *context,
                                   coap_oscore_conf_t *oscore_conf);

/**
 * Release all the information associated for the specific Recipient ID
 * (and hence and stop any further OSCORE protection for this Recipient).
 * Note: This is only removed from the OSCORE context as first defined by
 * coap_new_client_session_oscore*_lkd() or coap_context_oscore_server().
 *
 * Note: This function must be called in the locked state.
 *
 * @param context The CoAP  context holding the OSCORE recipient_id to.
 * @param recipient_id The Recipient ID to remove.
 *
 * @return @c 1 Successfully removed, else @c 0 not found.
 */
int coap_delete_oscore_recipient_lkd(coap_context_t *context,
                                     coap_bin_const_t *recipient_id);

/**
 * Creates a new client session to the designated server, protecting the data
 * using OSCORE.
 *
 * Note: This function must be called in the locked state.
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
 * @return A new CoAP session or NULL if failed. Call coap_session_release_lkd()
 *         to free.
 */
coap_session_t *coap_new_client_session_oscore_lkd(coap_context_t *ctx,
                                                   const coap_address_t *local_if,
                                                   const coap_address_t *server,
                                                   coap_proto_t proto,
                                                   coap_oscore_conf_t *oscore_conf);

/**
 * Creates a new client session to the designated server with PKI credentials
 * as well as protecting the data using OSCORE.
 *
 * Note: This function must be called in the locked state.
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
 * @return A new CoAP session or NULL if failed. Call coap_session_release_lkd()
 *         to free.
 */
coap_session_t *coap_new_client_session_oscore_pki_lkd(coap_context_t *ctx,
                                                       const coap_address_t *local_if,
                                                       const coap_address_t *server,
                                                       coap_proto_t proto,
                                                       coap_dtls_pki_t *pki_data,
                                                       coap_oscore_conf_t *oscore_conf);

/**
 * Creates a new client session to the designated server with PSK credentials
 * as well as protecting the data using OSCORE.
 *
 * Note: This function must be called in the locked state.
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
 * @return A new CoAP session or NULL if failed. Call coap_session_release_lkd()
 *         to free.
 */
coap_session_t *coap_new_client_session_oscore_psk_lkd(coap_context_t *ctx,
                                                       const coap_address_t *local_if,
                                                       const coap_address_t *server,
                                                       coap_proto_t proto,
                                                       coap_dtls_cpsk_t *psk_data,
                                                       coap_oscore_conf_t *oscore_conf);

/**
 * Add in the specific Recipient ID into the OSCORE context (server only).
 * Note: This is only added to the OSCORE context as first defined by
 * coap_new_client_session_oscore*() or coap_context_oscore_server().
 *
 * Note: This function must be called in the locked state.
 *
 * @param context The CoAP  context to add the OSCORE recipient_id to.
 * @param recipient_id The Recipient ID to add.
 *
 * @return @c 1 Successfully added, else @c 0 there is an issue.
 */
int coap_new_oscore_recipient_lkd(coap_context_t *context,
                                  coap_bin_const_t *recipient_id);

/** @} */

#endif /* COAP_OSCORE_INTERNAL_H */
