/*
 * coap_proxy.h -- helper functions for proxy handling
 *
 * Copyright (C) 2024 Jon Shallow <supjps-libcoap@jpshallow.com>
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

/**
 * @ingroup application_api
 * @defgroup proxy Proxy
 * API for Proxies
 * @{
 */

typedef enum {
  COAP_PROXY_REVERSE,       /**< Act as a reverse proxy */
  COAP_PROXY_REVERSE_STRIP, /**< Act as a reverse proxy, strip out proxy options */
  COAP_PROXY_FORWARD,       /**< Act as a forward proxy */
  COAP_PROXY_FORWARD_STRIP, /**< Act as a forward proxy, strip out proxy options */
  COAP_PROXY_DIRECT,        /**< Act as a direct proxy */
  COAP_PROXY_DIRECT_STRIP,  /**< Act as a direct proxy, strip out proxy options */
} coap_proxy_t;

typedef struct coap_proxy_server_t {
  coap_uri_t uri;         /**< host and port define the server, scheme method */
  coap_dtls_pki_t *dtls_pki;       /**< PKI configuration to use if not NULL */
  coap_dtls_cpsk_t *dtls_cpsk;     /**< PSK configuration to use if not NULL */
  coap_oscore_conf_t *oscore_conf; /**< OSCORE configuration if not NULL */
} coap_proxy_server_t;

typedef struct coap_proxy_server_list_t {
  coap_proxy_server_t *entry; /**< Set of servers to connect to */
  size_t entry_count;         /**< The number of servers */
  size_t next_entry;          /**< Next server to us (% entry_count) */
  coap_proxy_t type;          /**< The proxy type */
  int track_client_session;   /**< If 1, track individual connections to upstream
                                   server, else 0 */
  unsigned int idle_timeout_secs; /**< Proxy session idle timeout (0 is no timeout) */
} coap_proxy_server_list_t;

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
 *  Acting as a reverse proxy - connect to internal server
 *   (possibly round robin load balancing over multiple servers).
 *  Acting as a forward proxy - connect to host defined in Proxy-Uri
 *   or Proxy-Scheme with Uri-Host (and maybe Uri-Port).
 *  Acting as a relay proxy - connect to defined upstream server
 *   (possibly round robin load balancing over multiple servers).
 *
 * A request that should go direct to this server is not supported here.
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
int COAP_API coap_proxy_forward_request(coap_session_t *session,
                                        const coap_pdu_t *request,
                                        coap_pdu_t *response,
                                        coap_resource_t *resource,
                                        coap_cache_key_t *cache_key,
                                        coap_proxy_server_list_t *server_list);

/**
 * Forward the returning response back to the appropriate client.
 *
 * @param session The session handling the response.
 * @param received The received PDU.
 * @param cache_key Updated with the cache key pointer provided to
 *                  coap_proxy_forward_request().  The caller should
 *                  delete this cach key (unless the client request set up an
 *                  Observe and there will be unsolicited responses).
 *
 * @return One of COAP_RESPONSE_FAIL or COAP_RESPONSE_OK.
 */
coap_response_t COAP_API coap_proxy_forward_response(coap_session_t *session,
                                                     const coap_pdu_t *received,
                                                     coap_cache_key_t **cache_key);

/** @} */

#endif /* COAP_PROXY_H_ */
