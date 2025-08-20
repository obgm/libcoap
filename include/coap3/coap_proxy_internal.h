/*
 * coap_proxy_internal.h -- Proxy functions for libcoap
 *
 * Copyright (C) 2024-2025 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_proxy_internal.h
 * @brief CoAP Proxy internal information
 */

#ifndef COAP_PROXY_INTERNAL_H_
#define COAP_PROXY_INTERNAL_H_

#include "coap_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

#if COAP_PROXY_SUPPORT
/**
 * @ingroup internal_api
 * @defgroup Proxy Support
 * Internal API for handling CoAP proxies
 * @{
 */

/*  Client <--> Proxy-Server | Proxy-Client <--> Server */

typedef struct coap_proxy_cache_t {
  UT_hash_handle hh;            /**< Hash list for request Cache-Keys */
  coap_cache_key_t cache_req;   /**< Cache-Key of the request */
  coap_pdu_t *req_pdu;          /**< P-Client's request PDU */
  coap_pdu_t *rsp_pdu;          /**< Latest response PDU seen by P-Client */
  coap_tick_t expire;           /**< When this cache entry is to expire */
  uint64_t etag;                /**< ETag value of response PDU */
  unsigned ref;                 /**< No of coap_proxy_req_t reference this object */
} coap_proxy_cache_t;

typedef struct coap_proxy_req_t {
  struct coap_proxy_req_t *next;
  coap_pdu_t *pdu;              /**< Requesting PDU */
  coap_resource_t *resource;    /**< P-Server resource */
  coap_session_t *incoming;     /**< Incoming session from client */
  coap_bin_const_t *token_used; /**< Token used in forwarded request */
  coap_cache_key_t *cache_key;  /**< Cache-Key passed into coap_proxy_forward_request() */
  coap_proxy_cache_t *proxy_cache; /**< Cache that this proxy request is using */
  coap_mid_t mid;               /**< Last mid sent back to client */
  unsigned doing_observe;       /**< Set if doing upstream observe */
} coap_proxy_req_t;

struct coap_proxy_list_t {
  coap_session_t *ongoing;    /**< Ongoing session */
  coap_session_t *incoming;   /**< Incoming session (used if client tracking( */
  coap_proxy_req_t *proxy_req; /**< Incoming list of request info */
  coap_proxy_cache_t *rsp_cache; /* Response cache list */
  coap_uri_t uri;             /**< URI info for connection */
  uint8_t *uri_host_keep;     /**< memory for uri.host */
  coap_tick_t idle_timeout_ticks; /**< Idle timeout (0 == no timeout). Timeout
                                       is ignored if there are any active
                                       upstream Observe requests */
  coap_tick_t last_used;      /**< Last time entry was used */
};

typedef enum {
  COAP_PROXY_SUBS_ALL,
  COAP_PROXY_SUBS_TOKEN,
  COAP_PROXY_SUBS_MID,
} coap_proxy_subs_delete_t;

/**
 * Close down proxy tracking, releasing any memory used.
 *
 * @param context The current CoAP context.
 */
void coap_proxy_cleanup(coap_context_t *context);

/**
 * Idle timeout inactive proxy sessions as well as return in @p tim_rem the time
 * to remaining to timeout the inactive proxy.
 *
 * @param context Context to check against.
 * @param now Current time in ticks.
 * @param tim_rem Where to update timeout time to the next expiry.
 *
 * @return Return 1 if there is a future expire time, else 0.
 */
int coap_proxy_check_timeouts(coap_context_t *context, coap_tick_t now,
                              coap_tick_t *tim_rem);

/**
 * Remove the upstream proxy connection from list for session.
 *
 * @param session Either incoming or ongoiing session.
 * @param send_failure Indicate to incoming session proxy issues.
 *
 * @return Return 1 if proxy_entry deleted.
 */
int coap_proxy_remove_association(coap_session_t *session, int send_failure);

/**
 * Forward incoming request upstream to the next proxy/server.
 *
 * Possible scenarios:
 *  Acting as a reverse proxy - connect to defined internal server
 *   (possibly round robin load balancing over multiple servers).
 *  Acting as a forward proxy - connect to host defined in Proxy-Uri
 *   or Proxy-Scheme with Uri-Host (and maybe Uri-Port).
 *  Acting as a relay proxy - connect to defined upstream server
 *   (possibly round robin load balancing over multiple servers).
 *
 * A request that should go direct to this server is not supported here.
 *
 * Note: This function must be called in the locked state,
 *
 * @param session The client session.
 * @param request The client's request PDU.
 * @param response The response PDU that will get sent back to the client.
 * @param resource The resource associated with this request.
 * @param cache_key A cache key generated from the request PDU or NULL.
 * @param server_list The upstream server list to connect to.
 *
 * @return @c 1 if success, or @c 0 if failure (@p response code set to
 *         appropriate value).
 */
int coap_proxy_forward_request_lkd(coap_session_t *session,
                                   const coap_pdu_t *request,
                                   coap_pdu_t *response,
                                   coap_resource_t *resource,
                                   coap_cache_key_t *cache_key,
                                   coap_proxy_server_list_t *server_list);

/**
 * Forward the returning response back to the appropriate client.
 *
 * Note: This function must be called in the locked state,
 *
 * @param session The session handling the response.
 * @param received The received PDU.
 * @param cache_key Updated with the cache key pointer provided to
 *                  coap_proxy_forward_request_lkd().  The caller should
 *                  delete this cach key (unless the client request set up an
 *                  Observe and there will be unsolicited responses).
 *
 * @return One of COAP_RESPONSE_FAIL or COAP_RESPONSE_OK.
 */
coap_response_t coap_proxy_forward_response_lkd(coap_session_t *session,
                                                const coap_pdu_t *received,
                                                coap_cache_key_t **cache_key);

/**
 * Creates a new client session to use the proxy logic going to the defined upstream
 * server.
 *
 * Note: This function must be called in the locked state,
 *
 * Note: If server_list contains more than one server, the first server is not always
 * chosen.
 *
 * Note: @p server_list must exist for the duration of the returned session as it is
 * used for every *coap_send*() or *coap_send_recv*().
 *
 * Note: Unless coap_send_recv() is used, the response is sent to the handler defined
 * by coap_register_response_handler(), not to the handler defined by
 * coap_register_proxy_response_handler().
 *
 * @param context The CoAP context.
 * @param server_list The upstream server list to connect to.
 *
 * @return A new CoAP session or NULL if failed. Call coap_session_release() to free.
 */
coap_session_t *coap_new_client_session_proxy_lkd(coap_context_t *context,
                                                  coap_proxy_server_list_t *server_list);

/**
 * coap_proxy_local_write() is used to send the PDU for a session created by
 * coap_new_client_session_proxy() into the proxy logic for onward transmittion.
 *
 * @param session The coap_new_client_session_proxy() generated session.
 * @param pdu The PDU presented to libcoap by coap_send().
 *
 * @return The MID used for the transmission, else COAP_INVALID_MID on failure.
 */
coap_mid_t coap_proxy_local_write(coap_session_t *session, coap_pdu_t *pdu);

/**
 * coap_proxy_map_outgoing_request() takes the upstream proxy client session and
 * maps it back to the incoming request.
 *
 * @param ongoing The upstream proxy client session.
 * @param received The received PDU from the upstream server.
 * @param proxy_entry Updated with the proxy server entry definition if not NULL.
 *
 * @return The proxy request information, or NULL on mapping failure.
 */
struct coap_proxy_req_t *coap_proxy_map_outgoing_request(coap_session_t *ongoing,
                                                         const coap_pdu_t *received,
                                                         coap_proxy_list_t **proxy_entry);

/**
 * coap_proxy_process_incoming() handles the Server response back to P-Client.
 *
 * @param session The upstream proxy client session.
 * @param rcvd The received PDU from the upstream server.
 * @param body_data The data to be freed off once all responses sent for rcvd,
 * @param proxy_req The current proxy request object.
 * @param proxy_entry The current proxy entry object.
 *
 * @return The proxy request information, or NULL on mapping failure.
 */
void coap_proxy_process_incoming(coap_session_t *session,
                                 coap_pdu_t *rcvd, void *body_free,
                                 coap_proxy_req_t *proxy_req,
                                 coap_proxy_list_t *proxy_entry);

/**
 * coap_proxy_del_req() deletes the specific proxy request.
 *
 * @param proxy_entry The current proxy entry object.
 * @param proxy_req The proxy request object to delete.
 *
 */
void coap_proxy_del_req(coap_proxy_list_t *proxy_entry,  coap_proxy_req_t *proxy_req);

/**
 * coap_delete_proxy_subscriber() removes a proxy set up subscription.  If token
 * is provided, then it is a token match, else a MID match.
 *
 * @param session Client session to delete proxy subscription from.
 * @param token Token to match if set, or NULL.
 * @param mid MID to match if @p token is not set.
 *
 */
void coap_delete_proxy_subscriber(coap_session_t *session, coap_bin_const_t *token,
                                  coap_mid_t mid, coap_proxy_subs_delete_t type);

/** @} */

#define PROXY_CACHE_ADD(e, obj) \
  HASH_ADD(hh, (e), cache_req, sizeof((obj)->cache_req), (obj))

#define PROXY_CACHE_DELETE(e, obj) \
  HASH_DELETE(hh, (e), (obj))

#define PROXY_CACHE_ITER(e, el, rtmp)  \
  HASH_ITER(hh, (e), el, rtmp)

#define PROXY_CACHE_ITER_SAFE(e, el, rtmp) \
  for ((el) = (e); (el) && ((rtmp) = (el)->hh.next, 1); (el) = (rtmp))

#define PROXY_CACHE_FIND(e, k, res) {                     \
    HASH_FIND(hh, (e), (k), sizeof(*k), (res)); \
  }

#endif /* COAP_PROXY_SUPPORT */

#ifdef __cplusplus
}
#endif

#endif /* COAP_PROXY_INTERNAL_H_ */
