/*
 * resource.h -- generic resource handling
 *
 * Copyright (C) 2010,2011,2014,2015 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file resource.h
 * @brief Generic resource handling
 */

#ifndef _COAP_RESOURCE_H_
#define _COAP_RESOURCE_H_

# include <assert.h>

#ifndef COAP_RESOURCE_CHECK_TIME
/** The interval in seconds to check if resources have changed. */
#define COAP_RESOURCE_CHECK_TIME 2
#endif /* COAP_RESOURCE_CHECK_TIME */

#include "uthash.h"
#include "async.h"
#include "str.h"
#include "pdu.h"
#include "net.h"
#include "subscribe.h"

/**
 * Definition of message handler function (@sa coap_resource_t).
 */
typedef void (*coap_method_handler_t)
  (coap_context_t  *,
   struct coap_resource_t *,
   coap_session_t *,
   coap_pdu_t *,
   str * /* token */,
   str * /* query string */,
   coap_pdu_t * /* response */);

#define COAP_ATTR_FLAGS_RELEASE_NAME  0x1
#define COAP_ATTR_FLAGS_RELEASE_VALUE 0x2

typedef struct coap_attr_t {
  struct coap_attr_t *next;
  str name;
  str value;
  int flags;
} coap_attr_t;

/** The URI passed to coap_resource_init() is free'd by coap_delete_resource(). */
#define COAP_RESOURCE_FLAGS_RELEASE_URI 0x1

/**
 * Notifications will be sent non-confirmable by default. RFC 7641 Section 4.5
 * https://tools.ietf.org/html/rfc7641#section-4.5
 */
#define COAP_RESOURCE_FLAGS_NOTIFY_NON  0x0

/**
 * Notifications will be sent confirmable by default. RFC 7641 Section 4.5
 * https://tools.ietf.org/html/rfc7641#section-4.5
 */
#define COAP_RESOURCE_FLAGS_NOTIFY_CON  0x2

typedef struct coap_resource_t {
  unsigned int dirty:1;          /**< set to 1 if resource has changed */
  unsigned int partiallydirty:1; /**< set to 1 if some subscribers have not yet
                                  *   been notified of the last change */
  unsigned int observable:1;     /**< can be observed */
  unsigned int cacheable:1;      /**< can be cached */
  unsigned int is_unknown:1;     /**< resource created for unknown handler */

  /**
   * Used to store handlers for the seven coap methods @c GET, @c POST, @c PUT,
   * @c DELETE, @c FETCH, @c PATCH and @c IPATCH.
   * coap_dispatch() will pass incoming requests to the handler
   * that corresponds to its request method or generate a 4.05 response if no
   * handler is available.
   */
  coap_method_handler_t handler[7];

  UT_hash_handle hh;

  coap_attr_t *link_attr; /**< attributes to be included with the link format */
  coap_subscription_t *subscribers;  /**< list of observers for this resource */

  /**
   * Request URI Path for this resource. This field will point into static
   * or allocated memory which must remain there for the duration of the
   * resource.
   */
  str uri_path;         /**< the key used for hash lookup for this resource */
  int flags;

  /**
  * The next value for the Observe option. This field must be increased each
  * time the resource changes. Only the lower 24 bits are sent.
  */
  unsigned int observe;

  /**
   * This pointer is under user control. It can be used to store context for
   * the coap handler.
   */
  void *user_data;

} coap_resource_t;

/**
 * Creates a new resource object and initializes the link field to the string
 * of length @p len. This function returns the new coap_resource_t object.
 *
 * @param uri_path The URI path of the new resource.
 * @param len     The length of @p uri_path.
 * @param flags   Flags for memory management (in particular release of memory).
 *
 * @return       A pointer to the new object or @c NULL on error.
 */
coap_resource_t *coap_resource_init(const unsigned char *uri_path,
                                    size_t len, int flags);


/**
 * Creates a new resource object for the unknown resource handler with support
 * for PUT.  Additional methods and handlers can be added to the resource
 * with coap_register_handler(), but this is not generally recommended.
 * If this resource is added multiple times to the same coap_context with
 * coap_add_resource(), the previous resource is deleted.
 *
 * This function returns the new coap_resource_t object.
 *
 * @param put_handler The PUT handler to register with @p resource for
 *                    unknown Uri-Path.
 *
 * @return       A pointer to the new object or @c NULL on error.
 */
coap_resource_t *coap_resource_unknown_init(coap_method_handler_t put_handler);

/**
 * Sets the notification message type of resource @p resource to given
 * @p mode

 * @param resource The resource to update.
 * @param mode     Must be one of @c COAP_RESOURCE_FLAGS_NOTIFY_NON
 *                 or @c COAP_RESOURCE_FLAGS_NOTIFY_CON.
 */
COAP_STATIC_INLINE void
coap_resource_set_mode(coap_resource_t *resource, int mode) {
  resource->flags = (resource->flags &
    ~(COAP_RESOURCE_FLAGS_NOTIFY_CON|COAP_RESOURCE_FLAGS_NOTIFY_NON)) |
    (mode & (COAP_RESOURCE_FLAGS_NOTIFY_CON|COAP_RESOURCE_FLAGS_NOTIFY_NON));
}

/**
 * Sets the user_data. The user_data is exclusively used by the library-user
 * and can be used as context in the handler functions.
 *
 * @param r	Resource to attach the data to
 * @param data	Data to attach to the user_data field. This pointer is only used for
 *		storage, the data remains under user control
 */
COAP_STATIC_INLINE void
coap_resource_set_userdata(coap_resource_t *r, void *data) {
  r->user_data = data;
}

/**
 * Gets the user_data. The user_data is exclusively used by the library-user
 * and can be used as context in the handler functions.
 *
 * @param r	Resource to retrieve the user_darta from
 *
 * @return	The user_data pointer
 */
COAP_STATIC_INLINE void *
coap_resource_get_userdata(coap_resource_t *r) {
  return r->user_data;
}

/**
 * Registers the given @p resource for @p context. The resource must have been
 * created by coap_resource_init() or coap_resource_unknown_init(), the
 * storage allocated for the resource will be released by coap_delete_resource().
 *
 * @param context  The context to use.
 * @param resource The resource to store.
 */
void coap_add_resource(coap_context_t *context, coap_resource_t *resource);

/**
 * Deletes a resource identified by @p resource. The storage allocated for that
 * resource is freed, and removed from the context.
 *
 * @param context  The context where the resources are stored.
 * @param resource The resource to delete.
 *
 * @return         @c 1 if the resource was found (and destroyed),
 *                 @c 0 otherwise.
 */
int coap_delete_resource(coap_context_t *context, coap_resource_t *resource);

/**
 * Deletes all resources from given @p context and frees their storage.
 *
 * @param context The CoAP context with the resources to be deleted.
 */
void coap_delete_all_resources(coap_context_t *context);

/**
 * Registers a new attribute with the given @p resource. As the
 * attributes str fields will point to @p name and @p val the
 * caller must ensure that these pointers are valid during the
 * attribute's lifetime.
 *
 * @param resource The resource to register the attribute with.
 * @param name     The attribute's name.
 * @param nlen     Length of @p name.
 * @param val      The attribute's value or @c NULL if none.
 * @param vlen     Length of @p val if specified.
 * @param flags    Flags for memory management (in particular release of
 *                 memory).
 *
 * @return         A pointer to the new attribute or @c NULL on error.
 */
coap_attr_t *coap_add_attr(coap_resource_t *resource,
                           const unsigned char *name,
                           size_t nlen,
                           const unsigned char *val,
                           size_t vlen,
                           int flags);

/**
 * Returns @p resource's coap_attr_t object with given @p name if found, @c NULL
 * otherwise.
 *
 * @param resource The resource to search for attribute @p name.
 * @param name     Name of the requested attribute.
 * @param nlen     Actual length of @p name.
 * @return         The first attribute with specified @p name or @c NULL if none
 *                 was found.
 */
coap_attr_t *coap_find_attr(coap_resource_t *resource,
                            const unsigned char *name,
                            size_t nlen);

/**
 * Deletes an attribute.
 *
 * @param attr Pointer to a previously created attribute.
 *
 */
void coap_delete_attr(coap_attr_t *attr);

/**
 * Status word to encode the result of conditional print or copy operations such
 * as coap_print_link(). The lower 28 bits of coap_print_status_t are used to
 * encode the number of characters that has actually been printed, bits 28 to 31
 * encode the status.  When COAP_PRINT_STATUS_ERROR is set, an error occurred
 * during output. In this case, the other bits are undefined.
 * COAP_PRINT_STATUS_TRUNC indicates that the output is truncated, i.e. the
 * printing would have exceeded the current buffer.
 */
typedef unsigned int coap_print_status_t;

#define COAP_PRINT_STATUS_MASK  0xF0000000u
#define COAP_PRINT_OUTPUT_LENGTH(v) ((v) & ~COAP_PRINT_STATUS_MASK)
#define COAP_PRINT_STATUS_ERROR 0x80000000u
#define COAP_PRINT_STATUS_TRUNC 0x40000000u

/**
 * Writes a description of this resource in link-format to given text buffer. @p
 * len must be initialized to the maximum length of @p buf and will be set to
 * the number of characters actually written if successful. This function
 * returns @c 1 on success or @c 0 on error.
 *
 * @param resource The resource to describe.
 * @param buf      The output buffer to write the description to.
 * @param len      Must be initialized to the length of @p buf and
 *                 will be set to the length of the printed link description.
 * @param offset   The offset within the resource description where to
 *                 start writing into @p buf. This is useful for dealing
 *                 with the Block2 option. @p offset is updated during
 *                 output as it is consumed.
 *
 * @return If COAP_PRINT_STATUS_ERROR is set, an error occured. Otherwise,
 *         the lower 28 bits will indicate the number of characters that
 *         have actually been output into @p buffer. The flag
 *         COAP_PRINT_STATUS_TRUNC indicates that the output has been
 *         truncated.
 */
coap_print_status_t coap_print_link(const coap_resource_t *resource,
                                    unsigned char *buf,
                                    size_t *len,
                                    size_t *offset);

/**
 * Registers the specified @p handler as message handler for the request type @p
 * method
 *
 * @param resource The resource for which the handler shall be registered.
 * @param method   The CoAP request method to handle.
 * @param handler  The handler to register with @p resource.
 */
COAP_STATIC_INLINE void
coap_register_handler(coap_resource_t *resource,
                      unsigned char method,
                      coap_method_handler_t handler) {
  assert(resource);
  assert(method > 0 && (size_t)(method-1) < sizeof(resource->handler)/sizeof(coap_method_handler_t));
  resource->handler[method-1] = handler;
}

/**
 * Returns the resource identified by the unique string @p uri_path. If no
 * resource was found, this function returns @c NULL.
 *
 * @param context  The context to look for this resource.
 * @param uri_path  The unique string uri of the resource.
 *
 * @return         A pointer to the resource or @c NULL if not found.
 */
coap_resource_t *coap_get_resource_from_uri_path(coap_context_t *context,
                                                str uri_path);

/**
 * @addtogroup observe
 */

/**
 * Adds the specified peer as observer for @p resource. The subscription is
 * identified by the given @p token. This function returns the registered
 * subscription information if the @p observer has been added, or @c NULL on
 * error.
 *
 * @param resource        The observed resource.
 * @param session         The observer's session
 * @param token           The token that identifies this subscription.
 * @param query           The query string, if any. subscription will
                          take ownership of the string.
 * @return                A pointer to the added/updated subscription
 *                        information or @c NULL on error.
 */
coap_subscription_t *coap_add_observer(coap_resource_t *resource,
                                       coap_session_t *session,
                                       const str *token,
                                       str *query);

/**
 * Returns a subscription object for given @p peer.
 *
 * @param resource The observed resource.
 * @param session  The observer's session
 * @param token    The token that identifies this subscription or @c NULL for
 *                 any token.
 * @return         A valid subscription if exists or @c NULL otherwise.
 */
coap_subscription_t *coap_find_observer(coap_resource_t *resource,
                                        coap_session_t *session,
                                        const str *token);

/**
 * Marks an observer as alive.
 *
 * @param context  The CoAP context to use.
 * @param session  The observer's session
 * @param token    The corresponding token that has been used for the
 *                 subscription.
 */
void coap_touch_observer(coap_context_t *context,
                         coap_session_t *session,
                         const str *token);

/**
 * Removes any subscription for @p observer from @p resource and releases the
 * allocated storage. The result is @c 1 if an observation relationship with @p
 * observer and @p token existed, @c 0 otherwise.
 *
 * @param resource The observed resource.
 * @param session  The observer's session.
 * @param token    The token that identifies this subscription or @c NULL for
 *                 any token.
 * @return         @c 1 if the observer has been deleted, @c 0 otherwise.
 */
int coap_delete_observer(coap_resource_t *resource,
                         coap_session_t *session,
                         const str *token);

/**
 * Removes any subscription for @p session and releases the allocated storage.
 *
 * @param context  The CoAP context to use.
 * @param session  The observer's session.
 */
void coap_delete_observers(coap_context_t *context, coap_session_t *session);

/**
 * Checks for all known resources, if they are dirty and notifies subscribed
 * observers.
 */
void coap_check_notify(coap_context_t *context);

#define RESOURCES_ADD(r, obj) \
  HASH_ADD(hh, (r), uri_path.s[0], (obj)->uri_path.length, (obj))

#define RESOURCES_DELETE(r, obj) \
  HASH_DELETE(hh, (r), (obj))

#define RESOURCES_ITER(r,tmp)  \
  coap_resource_t *tmp, *rtmp; \
  HASH_ITER(hh, (r), tmp, rtmp)

#define RESOURCES_FIND(r, k, res) {                     \
    HASH_FIND(hh, (r), (k).s, (k).length, (res)); \
  }

/** @} */

coap_print_status_t coap_print_wellknown(coap_context_t *,
                                         unsigned char *,
                                         size_t *, size_t,
                                         coap_opt_t *);

void coap_handle_failed_notify(coap_context_t *, coap_session_t *, const str *);

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
COAP_STATIC_INLINE void
coap_resource_set_get_observable(coap_resource_t *resource, int mode) {
  resource->observable = mode ? 1 : 0;
}

/**
 * Initiate the sending of an Observe packet for all observers of @p resource,
 * optionally matching @p query if not NULL
 *
 * @param resource The CoAP resource to use.
 * @param query    The Query to match against or NULL  
 *
 * @return         @c 1 if the Observe has been triggered, @c 0 otherwise.
 */
int coap_resource_notify_observers(coap_resource_t *resource, const str *query);

/**
 * Get the UriPath from a @p resource.
 *
 * @param resource The CoAP resource to check.
 *
 * @return         The UriPath if it exists or @c NULL otherwise.
 */
COAP_STATIC_INLINE const str*
coap_resource_get_uri_path(coap_resource_t *resource) {
  if (resource)
    return &resource->uri_path;
  return NULL;
}

/**
 * @deprecated use coap_resource_notify_observers() instead.
 */
int coap_resource_set_dirty(coap_resource_t *r, const str *query);

#endif /* _COAP_RESOURCE_H_ */
