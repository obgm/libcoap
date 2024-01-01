/*
 * coap_ws.h -- WebSockets Transport Layer Support for libcoap
 *
 * Copyright (C) 2023-2024 Olaf Bergmann <bergmann@tzi.org>
 * Copyright (C) 2023-2024 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_ws.h
 * @brief CoAP WebSockets support
 */

#ifndef COAP_WS_H_
#define COAP_WS_H_

/**
 * @ingroup application_api
 * @defgroup ws WebSockets Support
 * API for interfacing with WebSockets (RFC8323)
 * @{
 */

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

/**
 * Set the host for the HTTP Host: Header in the WebSockets Request.
 *
 * @return @c 1 if successful, else @c 0 if failure of some sort.
 */
int coap_ws_set_host_request(coap_session_t *session, coap_str_const_t *ws_host);

/** @} */

#endif /* COAP_WS_H */
