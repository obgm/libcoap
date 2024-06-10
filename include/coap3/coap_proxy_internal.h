/*
 * coap_proxy_internal.h -- Proxy functions for libcoap
 *
 * Copyright (C) 2024 Jon Shallow <supjps-libcoap@jpshallow.com>
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

/**
 * @ingroup internal_api
 * @defgroup Proxy Support
 * Internal API for handling CoAP proxies
 * @{
 */

typedef struct coap_proxy_req_t {
  coap_pdu_t *pdu;
  coap_resource_t *resource;
  coap_session_t *incoming;
  coap_bin_const_t *token_used;
  coap_cache_key_t *cache_key;
} coap_proxy_req_t;

struct coap_proxy_list_t {
  coap_session_t *ongoing;   /**< Ongoing session */
  coap_session_t *incoming;  /**< Incoming session (used if client tracking( */
  coap_proxy_req_t *req_list; /**< Incoming list of request info */
  size_t req_count;          /**< Count of incoming request info */
  coap_uri_t uri;            /**< URI info for connection */
  coap_tick_t idle_timeout_ticks; /**< Idle timeout (0 == no timeout) */
  coap_tick_t last_used;     /**< Last time entry was used */
};

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

void coap_proxy_remove_association(coap_session_t *session, int send_failure);

/**
 * Forward incoming request upstream to the next proxy/server.
 *
 * Possible scenarios:
 *  Acting as a reverse proxy - connect to internal server
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

/** @} */

#endif /* COAP_PROXY_INTERNAL_H_ */
