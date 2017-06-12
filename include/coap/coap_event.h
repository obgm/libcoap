/*
 * coap_event.h -- libcoap Event API
 *
 * Copyright (C) 2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#ifndef _COAP_EVENT_H_
#define _COAP_EVENT_H_

struct coap_context_t;

/**
 * @defgroup events Event API
 * API functions for event deliver from lower-layer library functions.
 * @{
 */

/**
 * Scalar type to represent different events, e.g. DTLS events or
 * retransmission timeouts.
 */
 typedef unsigned int coap_event_t;

#define COAP_EVENT_DTLS_CLOSED        0x0000
#define COAP_EVENT_DTLS_CONNECTED     0x01DE
#define COAP_EVENT_DTLS_RENEGOTIATE   0x01DF
#define COAP_EVENT_DTLS_ERROR         0x0200

/**
 * Type for event handler functions that can be registered with a CoAP
 * context using the unction coap_set_event_handler(). When called by
 * the library, the first argument will be the coap_context_t object
 * where the handler function has been registered. The second argument
 * is the event type that may be complemented by event-specific data
 * passed as the third argument.
 */
typedef int (*coap_event_handler_t)(struct coap_context_t *,
                                    coap_event_t,
                                    void *);

/**
 * Registers the function @p hnd as callback for events from the given
 * CoAP context @p context. Any event handler that has previously been
 * registered with @p context will be overwritten by this operation.
 *
 * @param context The CoAP context to register the event handler with.
 * @param hnd     The event handler to be registered.
 */
void coap_set_event_handler(struct coap_context_t *context,
                            coap_event_handler_t hnd);

/**
 * Clears the event handler registered with @p context.
 *
 * @param context The CoAP context whose event handler is to be removed.
 */
void coap_clear_event_handler(struct coap_context_t *context);

/** @} */

#endif /* COAP_EVENT_H */
