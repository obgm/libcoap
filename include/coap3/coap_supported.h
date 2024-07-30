/*
 * coap_supported.h -- CoAP optional functionality
 *
 * Copyright (C) 2024 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_supported.h
 * @brief CoAP optional functionality
 */

#ifndef COAP_SUPPORTED_H_
#define COAP_SUPPORTED_H_

/**
 * @ingroup application_api
 * @defgroup supported Optional functionality
 * API for determining functionality optionally compiled into libcoap
 * @{
 */

/**
 * Check whether socket type AF_UNIX is available.
 *
 * @return @c 1 if support for AF_UNIX is available, or @c 0 otherwise.
 */
int coap_af_unix_is_supported(void);

/**
 * Check whether ASYNC (separate responses) is available.
 *
 * @return @c 1 if support for ASYNC is available, or @c 0 otherwise.
 */
int coap_async_is_supported(void);

/**
 * Check whether Client code is available.
 *
 * @return @c 1 if support for Client is available, or @c 0 otherwise.
 */
int coap_client_is_supported(void);

/**
 * Check whether DTLS is available.
 *
 * @return @c 1 if support for DTLS is available, or @c 0 otherwise.
 */
int coap_dtls_is_supported(void);

/**
 * Check whether (D)TLS CID is available.
 *
 * @return @c 1 if support for (D)TLS CID is available, or @c 0 otherwise.
 */
int coap_dtls_cid_is_supported(void);

/**
 * Check whether (D)TLS PSK is available.
 *
 * @return @c 1 if support for (D)TLS PSK is available, or @c 0 otherwise.
 */
int coap_dtls_psk_is_supported(void);

/**
 * Check whether (D)TLS PKI is available.
 *
 * @return @c 1 if support for (D)TLS PKI is available, or @c 0 otherwise.
 */
int coap_dtls_pki_is_supported(void);

/**
 * Check whether (D)TLS PKCS11 is available.
 *
 * @return @c 1 if support for (D)TLS PKCS11 is available, or @c 0 otherwise.
 */
int coap_dtls_pkcs11_is_supported(void);

/**
 * Check whether (D)TLS RPK is available.
 *
 * @return @c 1 if support for (D)TLS RPK is available, or @c 0 otherwise.
 */
int coap_dtls_rpk_is_supported(void);

/**
 * Determine whether epoll is supported or not.
 *
 * @return @c 1 if libcoap is compiled with epoll support, @c 0 if not.
 */
int coap_epoll_is_supported(void);

/**
 * Check whether IPv4 is available.
 *
 * @return @c 1 if support for IPv4 is available, or @c 0 otherwise.
 */
int coap_ipv4_is_supported(void);

/**
 * Check whether IPv6 is available.
 *
 * @return @c 1 if support for IPv6 is available, or @c 0 otherwise.
 */
int coap_ipv6_is_supported(void);

/**
 * Check whether Observe Persist is available.
 *
 * @return @c 1 if support for Observe Persist is available, or @c 0 otherwise.
 */
int coap_observe_persist_is_supported(void);

/**
 * Check whether OSCORE is available.
 *
 * @return @c 1 if support for OSCORE is enabled, or @c 0 otherwise.
 */
int coap_oscore_is_supported(void);

/**
 * Check whether Proxy code is available.
 *
 * @return @c 1 if support for Proxy code is enabled, or @c 0 otherwise.
 */
int coap_proxy_is_supported(void);

/**
 * Check whether Q-BlockX is available.
 *
 * @return @c 1 if support for Q-BLockX is available, or @c 0 otherwise.
 */
int coap_q_block_is_supported(void);

/**
 * Check whether Server code is available.
 *
 * @return @c 1 if support for Server is available, or @c 0 otherwise.
 */
int coap_server_is_supported(void);

/**
 * Check whether TCP is available.
 *
 * @return @c 1 if support for TCP is enabled, or @c 0 otherwise.
 */
int coap_tcp_is_supported(void);

/**
 * Determine whether libcoap is threadsafe or not.
 *
 * @return @c 1 if libcoap is compiled with threadsafe support, @c 0 if not.
 */
int coap_threadsafe_is_supported(void);

/**
 * Check whether TLS is available.
 *
 * @return @c 1 if support for TLS is available, or @c 0 otherwise.
 */
int coap_tls_is_supported(void);

/**
 * Check whether WebSockets is available.
 *
 * @return @c 1 if support for WebSockets is available, or @c 0 otherwise.
 */
int coap_ws_is_supported(void);

/**
 * Check whether Secure WebSockets is available.
 *
 * @return @c 1 if support for Secure WebSockets is available, or @c 0 otherwise.
 */
int coap_wss_is_supported(void);

/**@}*/

#endif /* COAP_SUPPORTED_H_ */
