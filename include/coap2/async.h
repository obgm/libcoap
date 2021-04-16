/*
 * async.h -- state management for asynchronous messages
 *
 * Copyright (C) 2010-2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file async.h
 * @brief State management for asynchronous messages
 */

#ifndef COAP_ASYNC_H_
#define COAP_ASYNC_H_

#include "net.h"

#ifndef WITHOUT_ASYNC

/**
 * @defgroup coap_async Asynchronous Messaging
 * @{
 * API functions for  Async "separate" messages.
 * A coap_context_t object holds a list of coap_async_t objects that can
 * be used to generate a separate response in the case a result of a request
 * cannot be delivered immediately.
 */

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
 * @param context  The context to use.
 * @param session  The session that is used for asynchronous transmissions.
 * @param request  The request that is handled asynchronously.
 * @param delay    The amount of time to delay before sending response, 0 means
 *                 wait forever.
 *
 * @return         A pointer to the registered coap_async_t object or @c
 *                 NULL in case of an error.
 */
coap_async_t *
coap_register_async(coap_context_t *context,
                    coap_session_t *session,
                    coap_pdu_t *request,
                    coap_tick_t delay);

/**
 * Update the delay timeout, so changing when the registered @p async triggers.
 *
 * When the new delay expires, a copy of the original request will get sent to
 * the appropriate request handler.
 *
 * @param async The object to update.
 * @param delay    The amount of time to delay before sending response, 0 means
 *                 wait forever.
 */
void
coap_async_set_delay(coap_async_t *async, coap_tick_t delay);

/**
 * Releases the memory that was allocated by coap_async_state_init() for the
 * object @p async.
 *
 * @param context  The context to use.
 * @param async The object to delete.
 */
void
coap_free_async(coap_context_t *context, coap_async_t *async);

/**
 * Retrieves the object identified by @p token from the list of asynchronous
 * transactions that are registered with @p context. This function returns a
 * pointer to that object or @c NULL if not found.
 *
 * @param context The context where the asynchronous objects are registered
 *                with.
 * @param session The session that is used for asynchronous transmissions.
 * @param token   The PDU's token of the object to retrieve.
 *
 * @return        A pointer to the object identified by @p token or @c NULL if
 *                not found.
 */
coap_async_t *coap_find_async(coap_context_t *context,
                              coap_session_t *session, coap_binary_t token);

/**
 * Set the application data pointer held in @p async. This overwrites any
 * existing data pointer.
 *
 * @param async The async state object.
 * @param app_data The pointer to the data.
 */
void coap_async_set_app_data(coap_async_t *async, void *app_data);

/**
 * Gets the application data pointer held in @p async.
 *
 * @param async The async state object.
 *
 * @return The applicaton data pointer.
 */
void *coap_async_get_app_data(const coap_async_t *async);

/** @} */

#endif /*  WITHOUT_ASYNC */

#endif /* COAP_ASYNC_H_ */
