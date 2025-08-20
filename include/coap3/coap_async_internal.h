/*
 * coap_async_internal.h -- state management for asynchronous messages
 *
 * Copyright (C) 2010-2025 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_async_internal.h
 * @brief CoAP async internal information
 */

#ifndef COAP_ASYNC_INTERNAL_H_
#define COAP_ASYNC_INTERNAL_H_

#include "coap_internal.h"
#include "coap_net.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Note that if COAP_SERVER_SUPPORT is not set, then COAP_ASYNC_SUPPORT undefined */
#if COAP_ASYNC_SUPPORT

/**
 * @ingroup internal_api
 * @defgroup coap_async_internal Asynchronous Messaging
 * @{
 * Internal API for CoAP Asynchronous processing.
 * A coap_context_t object holds a list of coap_async_t objects that can be
 * used to generate a separate response in the case a result of a request cannot
 * be delivered immediately.
 */
struct coap_async_t {
  struct coap_async_t *next; /**< internally used for linking */
  coap_tick_t delay;    /**< When to delay to before triggering the response
                             0 indicates never trigger */
  coap_session_t *session;         /**< transaction session */
  coap_pdu_t *pdu;                 /**< copy of request pdu */
  void *app_data;                   /**< User definable data pointer */
  coap_app_data_free_callback_t app_cb; /**< callcack to call when async is
                                             being released (or NULL) */
};

/**
 * Allocates a new coap_async_t object and fills its fields according to
 * the given @p request. This function returns a pointer to the registered
 * coap_async_t object or @c NULL on error. Note that this function will
 * return @c NULL in case that an object with the same identifier is already
 * registered.
 *
 * When the delay expires, a copy of the @p request will get sent to the
 * appropriate request handler.
 *
 * Note: This function must be called in the locked state.
 *
 * @param session  The session that is used for asynchronous transmissions.
 * @param request  The request that is handled asynchronously.
 * @param delay    The amount of time to delay before sending response, 0 means
 *                 wait forever.
 *
 * @return         A pointer to the registered coap_async_t object or @c
 *                 NULL in case of an error.
 */
coap_async_t *coap_register_async_lkd(coap_session_t *session,
                                      const coap_pdu_t *request,
                                      coap_tick_t delay);

/**
 * Checks if there are any pending Async requests - if so, send them off.
 * Otherewise return the time remaining for the next Async to be triggered
 * or 0 if nothing to do.
 *
 * @param context The current context.
 * @param now     The current time in ticks.
 * @param tim_rem Updated with the remaining timeout time if return is @c 1,
 *                unless set to NULL.
 *
 * @return @c 1 if @p tim_rem is set, else @c 0 if there is no timeout.
 */
int coap_check_async(coap_context_t *context, coap_tick_t now, coap_tick_t *tim_rem);

/**
 * Retrieves the object identified by @p token from the list of asynchronous
 * transactions that are registered with @p context. This function returns a
 * pointer to that object or @c NULL if not found.
 *
 * Note: This function must be called in the locked state.
 *
 * @param session The session that is used for asynchronous transmissions.
 * @param token   The PDU's token of the object to retrieve.
 *
 * @return        A pointer to the object identified by @p token or @c NULL if
 *                not found.
 */
coap_async_t *coap_find_async_lkd(coap_session_t *session, coap_bin_const_t token);

/**
 * Trigger the registered @p async.
 *
 * A copy of the original request will get sent to the appropriate request
 * handler.
 *
 * Note: This function must be called in the locked state.
 *
 * @param async The async object to trigger.
 */
void coap_async_trigger_lkd(coap_async_t *async);

/**
 * Update the delay timeout, so changing when the registered @p async triggers.
 *
 * When the new delay expires, a copy of the original request will get sent to
 * the appropriate request handler.
 *
 * Note: This function must be called in the locked state.
 *
 * @param async The object to update.
 * @param delay    The amount of time to delay before sending response, 0 means
 *                 wait forever.
 */
void coap_async_set_delay_lkd(coap_async_t *async, coap_tick_t delay);

/**
 * Stores @p data with the given async, returning the previously stored
 * value or NULL. The data @p callback can be defined if the data is to be
 * released when the cache_entry is deleted.
 *
 * Note: This function must be called in the locked state.
 *
 * Note: It is the responsibility of the caller to free off (if appropriate) any
 * returned data.
 *
 * @param async_entry The async state object.
 * @param data The pointer to the data to store or NULL to just clear out the
 *             previous data.
 * @param callback The optional release call-back for data on async
 *                 removal or NULL.
 *
 * @return The previous data (if any) stored in the async.
 */
void *coap_async_set_app_data2_lkd(coap_async_t *async_entry,
                                   void *data,
                                   coap_app_data_free_callback_t callback);

/**
 * Releases the memory that was allocated by coap_register_async() for the
 * object @p async.
 *
 * Note: This function must be called in the locked state.
 *
 * @param session  The session to use.
 * @param async The object to delete.
 */
void coap_free_async_lkd(coap_session_t *session, coap_async_t *async);

/**
 * Removes and frees off all of the async entries for the given context.
 *
 * @param context The context to remove all async entries from.
 */
void coap_delete_all_async(coap_context_t *context);

/** @} */

#endif /* COAP_ASYNC_SUPPORT */

#ifdef __cplusplus
}
#endif

#endif /* COAP_ASYNC_INTERNAL_H_ */
