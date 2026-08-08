/*
 * coap_proxy.h -- helper functions for proxy handling
 *
 * Copyright (C) 2024-2026 Jon Shallow <supjps-libcoap@jpshallow.com>
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

/**
 * coap_proxy_t Proxy definitions.
 *
 *  0x00000007  Old 4.3.5 mappings for backward compatibility.
 *  0x00000038  New type mappings.
 *  0xffffffc0  Bitwise optional actions.
 *
 * Three types of proxy.
 *  reverse         Traffic forward to internal set of servers.
 *  forward-static  Traffic forwarded to defined set of servers.
 *  forward-dynamic Traffic forwarded to host defined by
 *                  Proxy-Uri / Proxy-Scheme options.
 * Additional options for each proxy type.
 *  strip           Remove Proxy-Uri and/or Proxy-Scheme options.
 *  mcast           Support forward-dynamic traffic to multicast addresses.
 */

typedef enum {
  /* Old entries, now updated for flexibility */
  COAP_PROXY_REVERSE,       /**< Old - do not use - Act as a reverse proxy */
  COAP_PROXY_REVERSE_STRIP, /**< Old - do not use - Act as a reverse proxy,
                                     strip out proxy options */
  COAP_PROXY_FORWARD,       /**< Old - do not use - Act as a forward-static proxy */
  COAP_PROXY_FORWARD_STRIP, /**< Old - do not use - Act as a forward-static proxy,
                                     strip out proxy options */
  COAP_PROXY_DIRECT,        /**< Old - do not use - Act as a forward-dynamic proxy */
  COAP_PROXY_DIRECT_STRIP,  /**< Old - do not use - Act as a forward-dynamic proxy,
                                    strip out proxy options */
  COAP_PROXY_FORWARD_DYNAMIC = COAP_PROXY_DIRECT,
  /**< Old - do not use - Act as a forward-dynamic proxy */
  COAP_PROXY_FORWARD_DYNAMIC_STRIP = COAP_PROXY_DIRECT_STRIP,
  /**< Old - do not use - Act as a forward-dynamic proxy, strip out proxy options */


  /* New style Proxy types */
  COAP_PROXY_REV = (1 << 3),         /**< reverse proxy. */
  COAP_PROXY_FWD_STATIC = (2 << 3),  /**< forward-static proxy. */
  COAP_PROXY_FWD_DYNAMIC = (3 << 3), /**< forward-dynamic proxy. */

  /* Start of additional optional bit mask mapping */
  COAP_PROXY_BIT_STRIP = (1 << 6),
  /**<
   * If COAP_PROXY_BIT_STRIP set, then remove any Proxy-Uri or Proxy-Scheme
   * as the PDU is forwarded, else leave them.
   */
  COAP_PROXY_BIT_MCAST = (1 << 7),
  /**<
   * If COAP_PROXY_BIT_MCAST set, then upstream servers can be multicast,
   * else only unicast.
   * [ Ignored if not COAP_PROXY_FWD_DYNAMIC ]
   */
  COAP_PROXY_DYN_DEFINED = (1 << 8),
  /**<
   * If COAP_PROXY_DYN_DEFINED set, then no new dynamic upstream servers will get
   * automatically added.  All dynamic upstream servers mut be pre-allocated by
   * using coap_proxy_fwd_add_client_session().
   * [ Ignored if not COAP_PROXY_FWD_DYNAMIC ]
   */
} coap_proxy_t;

#define COAP_PROXY_OLD_MASK 0x07 /**< Space used in coap_proxy_t for old types */
#define COAP_PROXY_NEW_MASK 0x38 /**< Space used in coap_proxy_t for new types */

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
  coap_proxy_t type;          /**< The proxy type and option controlling bits
                                   (if old type used, will get mapped into new + bits */
  int track_client_session;   /**< If 1, track individual connections to upstream
                                   server, else 0 for all clients to be multiplexed
                                   over the same upstream session */
  unsigned int idle_timeout_secs; /**< Proxy upstream session idle timeout
                                       (0 is no timeout). Timeout is ignored
                                       if there are any active upstream Observe
                                       requests or a CON upstream request has
                                       been sent with no response so far */
} coap_proxy_server_list_t;

/**
 * Proxy response handler that is used as callback held in coap_context_t.
 *
 * @param session CoAP session.
 * @param sent The PDU that was transmitted.
 * @param received The response PDU that was received, or returned from cache.
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
 * A request that should go direct to this next proxy/server is not
 * supported using this function - set up a new session using
 * coap_new_client_session_proxy().
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

/**
 * Add a previously setup proxy-client session to use the proxy logic for forwarding
 * subsequent dynamic proxy requests.
 *
 * The upstream server information is derived from @p session for the remote IP and
 * @p use_port for the port, and proxy connection type is derived from @p server_list
 * (track_client_session, and idle_timeout_secs are ignored and set to 0 and 0
 * respectively). type must contain at least COAP_PROXY_FWD_DYNAMIC, and @p server_list
 * must be the same as used in coap_proxy_forward_request().
 *
 * @param session The CoAP upstream proxy session previously set up (e.g. via call-home).
 * @param use_ip    The IP address to match on incoming proxy requests. If NULL, then
 *                  the IP address is determined from @p session.
 * @param use_port  The port number to match on incoming proxy requests. If 0, default
 *                  port for protocol is used.
 * @param server_list The upstream server connection characteristics.
 *
 * @return the proxy entry on success in adding session to the proxy list of upstream
 * servers, else NULL.
 */
COAP_API coap_proxy_entry_t *coap_proxy_fwd_add_client_session(coap_session_t *session,
    const char *use_ip, uint16_t use_port,
    coap_proxy_server_list_t *server_list);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* COAP_PROXY_H_ */
