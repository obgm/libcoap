/*
 * coap_subscribe.h -- subscription handling for CoAP
 *                see RFC7641
 *
 * Copyright (C) 2010-2012,2014-2024 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_subscribe.h
 * @brief Defines the application visible subscribe information
 */

#ifndef COAP_SUBSCRIBE_H_
#define COAP_SUBSCRIBE_H_

/**
 * @ingroup application_api
 * @defgroup observe Resource Observation
 * API for interfacing with the observe handling (RFC7641)
 * @{
 */

/**
 * The value COAP_OBSERVE_ESTABLISH in a GET/FETCH request option
 * COAP_OPTION_OBSERVE indicates a new observe relationship for (sender
 * address, token) is requested.
 */
#define COAP_OBSERVE_ESTABLISH 0

/**
 * The value COAP_OBSERVE_CANCEL in a GET/FETCH request option
 * COAP_OPTION_OBSERVE indicates that the observe relationship for (sender
 * address, token) must be cancelled.
 */
#define COAP_OBSERVE_CANCEL 1

/**
 * Set whether a @p resource is observable.  If the resource is observable
 * and the client has set the COAP_OPTION_OBSERVE in a request packet, then
 * whenever the state of the resource changes (a call to
 * coap_resource_trigger_observe()), an Observer response will get sent.
 *
 * @param resource The CoAP resource to use.
 * @param mode     @c 1 if Observable is to be set, @c 0 otherwise.
 *
 */
void coap_resource_set_get_observable(coap_resource_t *resource, int mode);

/**
 * Initiate the sending of an Observe packet for all observers of @p resource,
 * optionally matching @p query if not NULL
 *
 * @param resource The CoAP resource to use.
 * @param query    The Query to match against or NULL
 *
 * @return         @c 1 if the Observe has been triggered, @c 0 otherwise.
 */
int coap_resource_notify_observers(coap_resource_t *resource,
                                   const coap_string_t *query);

/**
 * Checks all known resources to see if they are dirty and then notifies
 * subscribed observers.
 *
 * @param context The context to check for dirty resources.
 */
void coap_check_notify(coap_context_t *context);

/**
 * Callback handler definition called when a new observe has been set up,
 * as defined in coap_persist_track_funcs().
 *
 * @param session The current session.
 * @param observe_key The pointer to the subscription.
 * @param e_proto The CoAP protocol in use for the session / endpoint.
 * @param e_listen_addr The IP/port that the endpoint is listening on.
 * @param s_addr_info Local / Remote IP addresses. ports etc. of session.
 * @param raw_packet L7 packet as seen on the wire (could be concatenated if
 *                   Block1 FETCH is being used).
 * @param oscore_info Has OSCORE information if OSCORE is protecting the
 *                    session or NULL if OSCORE is not in use.
 * @param user_data Application provided information from
 *                  coap_persist_track_funcs().
 *
 * @return @c 1 if success else @c 0.
 */
typedef int (*coap_observe_added_t)(coap_session_t *session,
                                    coap_subscription_t *observe_key,
                                    coap_proto_t e_proto,
                                    coap_address_t *e_listen_addr,
                                    coap_addr_tuple_t *s_addr_info,
                                    coap_bin_const_t *raw_packet,
                                    coap_bin_const_t *oscore_info,
                                    void *user_data);

/**
 * Callback handler definition called when an observe is being removed,
 * as defined in coap_persist_track_funcs().
 *
 * @param session The current session.
 * @param observe_key The pointer to the subscription.
 * @param user_data Application provided information from
 *                  coap_persist_track_funcs().
 *
 * @return @c 1 if success else @c 0.
 */
typedef int (*coap_observe_deleted_t)(coap_session_t *session,
                                      coap_subscription_t *observe_key,
                                      void *user_data);

/**
 * Callback handler definition called when an observe unsolicited response is
 * being sent, as defined in coap_persist_track_funcs().
 *
 * Note: This will only get called every save_freq as defined by
 * coap_persist_track_funcs().
 *
 * @param context The current CoAP context.
 * @param resource_name The uri path name of the resource.
 * @param observe_num The current observe value just sent.
 * @param user_data Application provided information from
 *                  coap_persist_track_funcs().
 *
 * @return @c 1 if success else @c 0.
 */
typedef int (*coap_track_observe_value_t)(coap_context_t *context,
                                          coap_str_const_t *resource_name,
                                          uint32_t observe_num,
                                          void *user_data);

/**
 * Callback handler definition called when a dynamic resource is getting
 * created, as defined in coap_persist_track_funcs().
 *
 * @param session The current CoAP session.
 * @param resource_name The uri path name of the resource.
 * @param raw_packet L7 packet as seen on the wire (could be concatenated if
 *                   Block1 PUT/POST/FETCH used to create resource).
 * @param user_data Application provided information from
 *                  coap_persist_track_funcs().
 *
 * @return @c 1 if success else @c 0.
 */
typedef int (*coap_dyn_resource_added_t)(coap_session_t *session,
                                         coap_str_const_t *resource_name,
                                         coap_bin_const_t *raw_packet,
                                         void *user_data);

/**
 * Callback handler definition called when resource is removed,
 * as defined in coap_persist_track_funcs().
 *
 * This will remove any dynamic resources that are being tracked as well
 * as any observe value tracking.
 *
 * @param context The current CoAP context.
 * @param resource_name The uri path name of the resource.
 * @param user_data Application provided information from
 *                  coap_persist_track_funcs().
 *
 * @return @c 1 if success else @c 0.
 */
typedef int (*coap_resource_deleted_t)(coap_context_t *context,
                                       coap_str_const_t *resource_name,
                                       void *user_data);

/**
 * Set up callbacks to handle persist tracking so on a coap-server inadvertent
 * restart, existing observe subscriptions can continue.
 *
 * @param context The current CoAP context.
 * @param observe_added Called when a new observe subscription is set up.
 * @param observe_deleted Called when a observe subscription is de-registered.
 * @param track_observe_value Called every @p save_freq so current observe
 *                            value can be tracked.
 * @param dyn_resource_added Called whan a dynamic resource is created from the
 *                           'unknown' resource for tracking.
 * @param resource_deleted Called when a resource is removed.
 * @param save_freq Frequency of change of observe value for calling
 *                  @p save_observe_value
 * @param user_data App defined data (can be NULL) passed into various
 *                  callbacks.
 */
void coap_persist_track_funcs(coap_context_t *context,
                              coap_observe_added_t observe_added,
                              coap_observe_deleted_t observe_deleted,
                              coap_track_observe_value_t track_observe_value,
                              coap_dyn_resource_added_t dyn_resource_added,
                              coap_resource_deleted_t resource_deleted,
                              uint32_t save_freq,
                              void *user_data);

/**
 * Set up an active subscription for an observe that was previously active
 * over a coap-server inadvertant restart.
 *
 * Only UDP sessions currently supported.
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
coap_subscription_t *coap_persist_observe_add(coap_context_t *context,
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
int coap_persist_startup(coap_context_t *context,
                         const char *dyn_resource_save_file,
                         const char *observe_save_file,
                         const char *obs_cnt_save_file,
                         uint32_t save_freq);

/**
 * Stop tracking persist information, leaving the current persist information
 * in the files defined in coap_persist_startup(). It is then safe to call
 * coap_free_context() to close the application down cleanly.
 *
 * Alternatively, if coap_persist_track_funcs() was called, then this will
 * disable all the callbacks, as well as making sure that no 4.04 is sent out
 * for any active observe subscriptions when the resource is deleted after
 * subsequently calling coap_free_context().
 *
 * @param context The context that tracking information is to be stopped on.
 */
void coap_persist_stop(coap_context_t *context);

/**
 * Sets the current observe number value.

 * @param resource The resource to update.
 * @param observe_num The value to set the observe number to.
 */
void coap_persist_set_observe_num(coap_resource_t *resource,
                                  uint32_t observe_num);

/** @} */

#endif /* COAP_SUBSCRIBE_H_ */
