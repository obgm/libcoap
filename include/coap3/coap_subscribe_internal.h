/*
 * coap_subscribe_internal.h -- Structures, Enums & Functions that are not
 * exposed to application programming
 *
 * Copyright (C) 2010-2024 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_subscribe_internal.h
 * @brief CoAP subscribe internal information
 */

#ifndef COAP_SUBSCRIBE_INTERNAL_H_
#define COAP_SUBSCRIBE_INTERNAL_H_

#include "coap_internal.h"

#if COAP_SERVER_SUPPORT

/**
 * @ingroup internal_api
 * @defgroup subscribe_internal Observe Subscription
 * Internal API for handling CoAP Observe Subscriptions (RFC7641)
 * @{
 */

/**
 * Number of notifications that may be sent non-confirmable before a confirmable
 * message is sent to detect if observers are alive. The maximum allowed value
 * here is @c 255.
 */
#ifndef COAP_OBS_MAX_NON
#define COAP_OBS_MAX_NON   5
#endif /* COAP_OBS_MAX_NON */
#if COAP_OBS_MAX_NON > 255
#error COAP_OBS_MAX_NON is too large
#endif /* COAP_OBS_MAX_NON > 255 */

/**
 * Number of different confirmable notifications that may fail (i.e. those
 * that have hit MAX_RETRANSMIT multiple times) before an observer is removed.
 * The maximum value for COAP_OBS_MAX_FAIL is @c 255.
 */
#ifndef COAP_OBS_MAX_FAIL
#define COAP_OBS_MAX_FAIL  1
#endif /* COAP_OBS_MAX_FAIL */
#if COAP_OBS_MAX_FAIL > 255
#error COAP_OBS_MAX_FAIL is too large
#endif /* COAP_OBS_MAX_FAIL > 255 */

/** Subscriber information */
struct coap_subscription_t {
  struct coap_subscription_t *next; /**< next element in linked list */
  struct coap_session_t *session;   /**< subscriber session */

  uint8_t non_cnt;  /**< up to 255 non-confirmable notifies allowed */
  uint8_t fail_cnt; /**< up to 255 confirmable notifies can fail */
  uint8_t dirty;    /**< set if the notification temporarily could not be
                     *   sent (in that case, the resource's partially
                     *   dirty flag is set too) */
  coap_cache_key_t *cache_key; /** cache_key to identify requester */
  coap_pdu_t *pdu;         /**< PDU to use for additional requests */
};

void coap_subscription_init(coap_subscription_t *);

/**
 * Handles a failed observe notify.
 *
 * @param context The context holding the resource.
 * @param session The session that the observe notify failed on.
 * @param token The token used when the observe notify failed.
 */
void coap_handle_failed_notify(coap_context_t *context,
                               coap_session_t *session,
                               const coap_bin_const_t *token);

/**
 * Adds the specified peer as observer for @p resource. The subscription is
 * identified by the given @p token. This function returns the registered
 * subscription information if the @p observer has been added, or @c NULL on
 * error.
 *
 * @param resource        The observed resource.
 * @param session         The observer's session
 * @param token           The token that identifies this subscription.
 * @param pdu             The requesting pdu.
 *
 * @return                A pointer to the added/updated subscription
 *                        information or @c NULL on error.
 */
coap_subscription_t *coap_add_observer(coap_resource_t *resource,
                                       coap_session_t *session,
                                       const coap_bin_const_t *token,
                                       const coap_pdu_t *pdu);

/**
 * Returns a subscription object for given @p peer.
 *
 * @param resource The observed resource.
 * @param session  The observer's session
 * @param token    The token that identifies this subscription or @c NULL for
 *                 the first subscription.
 *
 * @return         A valid subscription if exists or @c NULL otherwise.
 */
coap_subscription_t *coap_find_observer(coap_resource_t *resource,
                                        coap_session_t *session,
                                        const coap_bin_const_t *token);

/**
 * Flags that data is ready to be sent to observers.
 *
 * @param context  The CoAP context to use.
 * @param session  The observer's session
 * @param token    The corresponding token that has been used for the
 *                 subscription.
 */
void coap_touch_observer(coap_context_t *context,
                         coap_session_t *session,
                         const coap_bin_const_t *token);

/**
 * Removes any subscription for @p session observer from @p resource and releases the
 * allocated storage. The result is @c 1 if an observation relationship with @p
 * session observer and @p token existed, @c 0 otherwise.
 *
 * @param resource The observed resource.
 * @param session  The observer's session.
 * @param token    The token that identifies this subscription or @c NULL for
 *                 the first subscription.
 *
 * @return         @c 1 if the observer has been deleted, @c 0 otherwise.
 */
int coap_delete_observer(coap_resource_t *resource,
                         coap_session_t *session,
                         const coap_bin_const_t *token);

/**
 * Removes any subscription for @p session observer from @p resource and releases the
 * allocated storage. The result is @c 1 if an observation relationship with @p
 * session observer and @p token existed, or cache-key derived from @p request matches,
 * @c 0 otherwise.
 *
 * @param resource The observed resource.
 * @param session  The observer's session.
 * @param token    The token that identifies this subscription or @c NULL for
 *                 the first subscription.
 * @param request  The requesting PDU.
 *
 * @return         @c 1 if the observer has been deleted, @c 0 otherwise.
 */
int coap_delete_observer_request(coap_resource_t *resource,
                                 coap_session_t *session,
                                 const coap_bin_const_t *token,
                                 coap_pdu_t *request);

/**
 * Removes any subscription for @p session and releases the allocated storage.
 *
 * @param context  The CoAP context to use.
 * @param session  The observer's session.
 */
void coap_delete_observers(coap_context_t *context, coap_session_t *session);

/**
 * Initiate the sending of an Observe packet for all observers of @p resource,
 * optionally matching @p query if not NULL
 *
 * Note: This function must be called in the locked state.
 *
 * @param resource The CoAP resource to use.
 * @param query    The Query to match against or NULL
 *
 * @return         @c 1 if the Observe has been triggered, @c 0 otherwise.
 */
int coap_resource_notify_observers_lkd(coap_resource_t *resource,
                                       const coap_string_t *query);

/**
 * Checks all known resources to see if they are dirty and then notifies
 * subscribed observers.
 *
 * Note: This function must be called in the locked state.
 *
 * @param context The context to check for dirty resources.
 */
void coap_check_notify_lkd(coap_context_t *context);

/**
 * Close down persist tracking, releasing any memory used.
 *
 * @param context The current CoAP context.
 */
void coap_persist_cleanup(coap_context_t *context);

/**
 * Set up an active subscription for an observe that was previously active
 * over a coap-server inadvertant restart.
 *
 * Only UDP sessions currently supported.
 *
 * Note: This function must be called in the locked state.
 *
 * @param context The context that the session is to be associated with.
 * @param e_proto The CoAP protocol in use for the session / endpoint.
 * @param e_listen_addr The IP/port that the endpoint is listening on.
 * @param s_addr_info Local / Remote IP addresses. ports etc. of previous
 *                    session.
 * @param raw_packet L7 packet as seen on the wire (could be concatenated if
 *                   Block1 FETCH is being used).
 * @param oscore_info Has OSCORE information if OSCORE is protecting the
 *                    session or NULL if OSCORE is not in use.
 *
 * @return ptr to subscription if success else @c NULL.
 */
coap_subscription_t *coap_persist_observe_add_lkd(coap_context_t *context,
                                                  coap_proto_t e_proto,
                                                  const coap_address_t *e_listen_addr,
                                                  const coap_addr_tuple_t *s_addr_info,
                                                  const coap_bin_const_t *raw_packet,
                                                  const coap_bin_const_t *oscore_info);

/**
 * Start up persist tracking using the libcoap module. If the files already
 * exist with saved data, then this information is used in building back
 * up the persist information.
 *
 * Note: This function must be called in the locked state.
 *
 * @param context The current CoAP context.
 * @param dyn_resource_save_file File where dynamically created resource
 *                               information is stored or NULL if not required.
 * @param observe_save_file File where observe information is stored or NULL
 *                          if not required.
 * @param obs_cnt_save_file File where resource observe counter information
 *                          is stored or NULL if not required.
 * @param save_freq Frequency of change of observe value for calling
 *                  the save observe counter logic.
 *
 * @return  @c 1 if success else @c 0.
 */
int coap_persist_startup_lkd(coap_context_t *context,
                             const char *dyn_resource_save_file,
                             const char *observe_save_file,
                             const char *obs_cnt_save_file,
                             uint32_t save_freq);

/**
 * Stop tracking persist information, leaving the current persist information
 * in the files defined in coap_persist_startup(). It is then safe to call
 * coap_free_context() to close the application down cleanly.
 *
 * Note: This function must be called in the locked state.
 *
 * Alternatively, if coap_persist_track_funcs() was called, then this will
 * disable all the callbacks, as well as making sure that no 4.04 is sent out
 * for any active observe subscriptions when the resource is deleted after
 * subsequently calling coap_free_context().
 *
 * @param context The context that tracking information is to be stopped on.
 */
void coap_persist_stop_lkd(coap_context_t *context);

#endif /* COAP_SERVER_SUPPORT */

#if COAP_CLIENT_SUPPORT

/**
 * Cancel an observe that is being tracked by the client large receive logic.
 * (coap_context_set_block_mode() has to be called)
 * This will trigger the sending of an observe cancel pdu to the server.
 *
 * Note: This function must be called in the locked state.
 *
 * @param session  The session that is being used for the observe.
 * @param token    The original token used to initiate the observation.
 * @param message_type The COAP_MESSAGE_ type (NON or CON) to send the observe
 *                 cancel pdu as.
 *
 * @return @c 1 if observe cancel transmission initiation is successful,
 *         else @c 0.
 */
int coap_cancel_observe_lkd(coap_session_t *session, coap_binary_t *token,
                            coap_pdu_type_t message_type);

#endif /* COAP_CLIENT_SUPPORT */

/** @} */
#endif /* COAP_SUBSCRIBE_INTERNAL_H_ */
