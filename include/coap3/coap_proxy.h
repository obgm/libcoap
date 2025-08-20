/*
 * coap_proxy.h -- helper functions for proxy handling
 *
 * Copyright (C) 2024-2025 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_proxy.h
 * @brief Helper functions for proxy handling
 */

#ifndef COAP_PROXY_H_
#define COAP_PROXY_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup application_api
 * @defgroup proxy Proxy
 * API for Proxies
 * @{
 */

typedef enum {
  COAP_PROXY_REVERSE,               /**< Act as a reverse proxy */
  COAP_PROXY_REVERSE_STRIP,         /**< Act as a reverse proxy,
                                         strip out proxy options */
  COAP_PROXY_FORWARD_STATIC,        /**< Act as a forward-static proxy */
  COAP_PROXY_FORWARD_STATIC_STRIP,  /**< Act as a forward-static proxy,
                                         strip out proxy options */
  COAP_PROXY_FORWARD_DYNAMIC,       /**< Act as a forward-dynamic proxy
                                         using the request's Proxy-Uri or
                                         Proxy-Scheme options to determine
                                         server */
  COAP_PROXY_FORWARD_DYNAMIC_STRIP, /**< Act as a forward-dynamic proxy,
                                         strip out proxy options */
  /* For backward compatability */
  COAP_PROXY_FORWARD = COAP_PROXY_FORWARD_STATIC,
  COAP_PROXY_FORWARD_STRIP = COAP_PROXY_FORWARD_STATIC_STRIP,
  COAP_PROXY_DIRECT = COAP_PROXY_FORWARD_DYNAMIC,
  COAP_PROXY_DIRECT_STRIP = COAP_PROXY_FORWARD_DYNAMIC_STRIP,
} coap_proxy_t;

typedef struct coap_proxy_server_t {
  coap_uri_t uri;         /**< host and port define the server, scheme method */
  coap_dtls_pki_t *dtls_pki;       /**< PKI configuration to use if not NULL */
  coap_dtls_cpsk_t *dtls_cpsk;     /**< PSK configuration to use if not NULL */
  coap_oscore_conf_t *oscore_conf; /**< OSCORE configuration if not NULL */
} coap_proxy_server_t;

typedef struct coap_proxy_server_list_t {
  coap_proxy_server_t *entry; /**< Set of servers to connect to */
  size_t entry_count;         /**< The number of servers in entry list */
  size_t next_entry;          /**< Next server to use (% entry_count) */
  coap_proxy_t type;          /**< The proxy type */
  int track_client_session;   /**< If 1, track individual connections to upstream
                                   server, else 0 for all clients to be multiplexed
                                   over the same upstream session */
  unsigned int idle_timeout_secs; /**< Proxy upstream session idle timeout
                                       (0 is no timeout). Timeout is ignored
                                       if there are any active upstream Observe
                                       requests */
} coap_proxy_server_list_t;

/**
 * Proxy response handler that is used as callback held in coap_context_t.
 *
 * @param session CoAP session.
 * @param sent The PDU that was transmitted.
 * @param received The respose PDU that was received, or returned from cache.
 * @param cache_key Updated with the cache key pointer provided to
 *                  coap_proxy_forward_request().  The caller should
 *                  delete this cache key (unless the client request set up an
 *                  Observe and there will be unsolicited responses).
 *
 * @return The PDU to be sent back to the client (usually @c received) or NULL
 *         if error.  If NULL, this will cause sending a RST packet to the
 *         upstream server if the received PDU is a CON or NON.
 *         If the returned PDU is not @c received or @c NULL, then @c received
 *         must be freed off in the handler.
 */
typedef coap_pdu_t *(*coap_proxy_response_handler_t)(coap_session_t *session,
                                                     const coap_pdu_t *sent,
                                                     coap_pdu_t *received,
                                                     coap_cache_key_t *cache_key);

/**
 * Registers a new message handler that is called whenever a response is
 * received by the proxy logic.
 *
 * Note: If this is not defined, then the handler registered by
 * coap_register_response_handler() will be used.
 *
 * @param context The context to register the handler for.
 * @param handler The response handler to register.
 */
void coap_register_proxy_response_handler(coap_context_t *context,
                                          coap_proxy_response_handler_t handler);

/**
 * Verify that the CoAP Scheme is supported for an ongoing proxy connection.
 *
 * @param scheme The CoAP scheme to check.
 *
 * @return @c 1 if supported, or @c 0 if not supported.
 */
int coap_verify_proxy_scheme_supported(coap_uri_scheme_t scheme);

/**
 * Forward incoming request upstream to the next proxy/server.
 *
 * Possible scenarios:
 *  Acting as a reverse proxy - connect to defined internal server
 *   (possibly round robin load balancing over multiple servers).
 *  Acting as a forward-dynamic proxy - connect to host defined in Proxy-Uri
 *   or Proxy-Scheme with Uri-Host (and maybe Uri-Port).
 *  Acting as a forward-static proxy - connect to defined upstream server
 *   (possibly round robin load balancing over multiple servers).
 *
 * A request that should go direct to this server is not supported here.
 *
 * @param req_session The client session.
 * @param request The client's request PDU.
 * @param response The response PDU that will get sent back to the client.
 * @param resource The resource associated with this request.
 * @param cache_key A cache key generated from the request PDU or NULL.
 * @param server_list The upstream server list to connect to.
 *
 * @return @c 1 if success, or @c 0 if failure (@p response code set to
 *         appropriate value).
 */
COAP_API int coap_proxy_forward_request(coap_session_t *req_session,
                                        const coap_pdu_t *request,
                                        coap_pdu_t *response,
                                        coap_resource_t *resource,
                                        coap_cache_key_t *cache_key,
                                        coap_proxy_server_list_t *server_list);

/**
 * Forward the returning response back to the appropriate client.
 *
 * @param rsp_session The upstream session receiving the response.
 * @param received The received PDU.
 * @param cache_key Updated with the cache key pointer provided to
 *                  coap_proxy_forward_request().  The caller should
 *                  delete this cache key (unless the client request set up an
 *                  Observe and there will be unsolicited responses).
 *
 * @return One of COAP_RESPONSE_FAIL or COAP_RESPONSE_OK.
 */
coap_response_t COAP_API coap_proxy_forward_response(coap_session_t *rsp_session,
                                                     const coap_pdu_t *received,
                                                     coap_cache_key_t **cache_key);

/**
 * Creates a new client session to use the proxy logic going to the defined upstream
 * server.
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
COAP_API coap_session_t *coap_new_client_session_proxy(coap_context_t *context,
                                                       coap_proxy_server_list_t *server_list);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* COAP_PROXY_H_ */
