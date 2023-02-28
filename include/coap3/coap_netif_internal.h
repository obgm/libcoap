/*
 * coap_netif_internal.h -- Netif Transport Layer Support for libcoap
 *
 * Copyright (C) 2023 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_netif_internal.h
 * @brief Internal CoAP Netif support
 */

#ifndef COAP_NETIF_INTERNAL_H_
#define COAP_NETIF_INTERNAL_H_

#include "coap_internal.h"

/**
 * @ingroup internal_api
 * @defgroup netif_internal Netif Support
 * Internal API for Netif Support
 * @{
 */

/**
 * Function interface to check whether netif for session is still available.
 *
 *  @param session          Session to check against.
 *
 * @return 1                If netif is available, else 0.
 */
int coap_netif_available(coap_session_t *session);

/**
 * Function interface for layer data datagram receiving for endpoints. This
 * function returns the number of bytes that have been read, or -1 on error.
 *
 * @param endpoint Endpoint to receive data on.
 * @param packet   Where to put the received information
 *
 * @return                 >=0 Number of bytes read.
 *                          -1 Error of some sort (see errno).
 *                          -2 ICMP error response
 */
ssize_t coap_netif_dgrm_read_ep(coap_endpoint_t *endpoint,
                                coap_packet_t *packet);

/**
 * Function interface for layer data datagram receiving for sessions. This
 * function returns the number of bytes that have been read, or -1 on error.
 *
 * @param session  Session to receive data on.
 * @param packet   Where to put the received information
 *
 * @return                 >=0 Number of bytes read.
 *                          -1 Error of some sort (see errno).
 *                          -2 ICMP error response
 */
ssize_t coap_netif_dgrm_read(coap_session_t *session, coap_packet_t *packet);

/**
 * Function interface for netif datagram data transmission. This function
 * returns the number of bytes that have been transmitted, or a value less
 * than zero on error.
 *
 * @param session          Session to send data on.
 * @param data             The data to send.
 * @param datalen          The actual length of @p data.
 *
 * @return                 The number of bytes written on success, or a value
 *                         less than zero on error.
 */
ssize_t coap_netif_dgrm_write(coap_session_t *session, const uint8_t *data,
                              size_t datalen);

/** @} */

#endif /* COAP_NETIF_INTERNAL_H */
