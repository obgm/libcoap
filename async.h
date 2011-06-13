/* async.h -- state management for asynchronous messages
 *
 * Copyright (C) 2010,2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

/** 
 * @file async.h
 * @brief state management for asynchronous messages
 */


#ifndef _COAP_ASYNC_H_
#define _COAP_ASYNC_H_

#include "net.h"

#ifndef WITHOUT_ASYNC

/**
 * @defgroup coap_async Asynchronous Messaging
 * @{
 * Structure for managing asynchronous state of CoAP resources. A
 * coap_resource_t object holds a list of coap_async_state_t objects
 * that can be used to generate a separate response in case a result
 * of an operation cannot be delivered in time, or the resource has
 * been explicitly subscribed to with the option @c observe.
 */
typedef struct coap_async_state_t {
  unsigned char flags;	/**< holds the flags to control behaviour */
  
  /** 
   * Holds the internal time when the object was registered with a
   * resource. This field will be updated whenever
   * coap_register_async() is called for a specific resource.
   */ 
  coap_tick_t created;
  
  /**
   * This field can be used to register opaque application data with
   * the asynchronous state object. */
  void *appdata;
  
  /** 
   * The message id of the original request if COAP_ASYNC_CONFIRM is
   * set. When a coap_async_state_t object is registered with a
   * resource, the immediate response will be deferred to give a
   * chance to assemble a piggy-backed response before the client has
   * to retransmit the request. If COAP_ASYNC_SEPARATE is set in
   * addition to COAP_ASYNC_CONFIRM, an acknowledgment response will
   * be generated if no piggy-backed response was sent within
   * COAP_DEFAULT_RESPONSE_TIMEOUT / @c 2. To avoid confusion with
   * separate responses, @p message_id will be set to a new and random
   * value after an acknowledgement was generated. Hence, the stored
   * @p message_id can be used in a response independent of any
   * previous messages.
   */
  unsigned short message_id; 

  struct coap_async_state_t *next; /**< internally used for linking */

  coap_address_t peer;		/**< the peer to notify */
  size_t tokenlen;		/**< length of the token */
  unsigned char token[];	/**< the token to use in a response */
} coap_async_state_t;

/* Definitions for Async Status Flags These flags can be used to
 * control the behaviour of asynchronous response generation. */
#define COAP_ASYNC_CONFIRM   0x01 /**< send confirmable response */
#define COAP_ASYNC_SEPARATE  0x02 /**< send separate response */
#define COAP_ASYNC_OBSERVED  0x04 /**< the resource is being observed */

/** release application data on destruction */
#define COAP_ASYNC_RELEASE_DATA  0x08

/** 
 * Allocates a new coap_async_state_t object and fills its fields with
 * the provided arguments. This function returns a pointer to the
 * newly created and initialized object or @c NULL on error.
 * 
 * @param context  The context to use.
 * @param peer     The remote peer that is to be asynchronously notified.
 * @param token    The token to use in asynchronous messages.
 * @param tokenlen The length of @p token.
 * @param flags    Flags to control notification behaviour.
 * @param data     Opaque application data to register. Note that the
 *                 storage occupied by @p data is released on destruction
 *                 only if flag COAP_ASYNC_RELEASE_DATA is set.
 * 
 * @return A pointer to the new coap_async_state_t object or @c NULL
 * on error.
 */
coap_async_state_t *
coap_async_state_init(coap_context_t *context, coap_address_t *peer,
		      unsigned char *token, size_t tokenlen,
		      unsigned char flags, void *data);

/** 
 * Releases the memory that was allocated by coap_async_state_init()
 * for the object @p s. The registered application data will be
 * released automatically if COAP_ASYNC_RELEASE_DATA is set.
 * 
 * @param s The object to delete.
 */
void 
coap_async_state_free(coap_async_state_t *state);

/** 
 * Updates the time stamp of @p s.
 * 
 * @param s The state object to update.
 */
static inline void
coap_async_touch(coap_async_state_t *s) { coap_ticks(&s->created); }

/** @} */

#endif /*  WITHOUT_ASYNC */

#endif /* _COAP_ASYNC_H_ */
