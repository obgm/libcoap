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
 * Internal API for Netif Support.
 * This provides a layer that sits between CoAP/DTLS and Sockets.
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
 * Function interface to check whether netif for endpoint is still available.
 *
 *  @param endpoint         Endpoint to check against.
 *
 * @return 1                If netif is available, else 0.
 */
int coap_netif_available_ep(coap_endpoint_t *endpoint);

/**
 * Layer function interface for Netif datagram listem (udp).
 *
 * @param endpoint  Endpoint to do the listen on.
 * @param listen_addr The local address to bind.
 *
 * @return                 @c 1 OK, 0 on failure.
 */
int coap_netif_dgrm_listen(coap_endpoint_t *endpoint,
                           const coap_address_t *listen_addr);

/**
 * Layer function interface for Netif datagram connect (udp).
 *
 * @param session  Session to do the connect on.
 * @param local_if The local interface to bind to or NULL.
 * @param server   The server to connect to.
 * @param default_port The Port to connect to if not defined.
 *
 * @return                 @c 1 OK, 0 on failure.
 */
int coap_netif_dgrm_connect(coap_session_t *session,
                            const coap_address_t *local_if,
                            const coap_address_t *server, int default_port);

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

/**
 * Layer function interface for Netif stream listem (tcp).
 *
 * @param endpoint  Endpoint to do the listen on.
 * @param listen_addr The local address to bind.
 *
 * @return                 @c 1 OK, 0 on failure.
 */
int coap_netif_strm_listen(coap_endpoint_t *endpoint,
                           const coap_address_t *listen_addr);

/**
 * Layer function interface for Netif stream accept.
 *
 * @param endpoint Endpoint to to do the accept on.
 * @param session  Session to to do the accept update on.
 *
 * @return                 @c 1 OK, 0 on failure.
 */
int coap_netif_strm_accept(coap_endpoint_t *endpoint, coap_session_t *session);

/**
 * Layer function interface for Netif stream connect (tcp).
 * Step 1 - initiate the connection.
 *
 * @param session  Session to do the connect on.
 * @param local_if The local interface to bind to or NULL.
 * @param server   The server to connect to.
 * @param default_port The Port to connect to if not defined.
 *
 * @return                 @c 1 OK, 0 on failure.
 */
int coap_netif_strm_connect1(coap_session_t *session,
                             const coap_address_t *local_if,
                             const coap_address_t *server, int default_port);

/**
 * Layer function interface for Netif stream connect (tcp).
 * Step 2 - complete the connection.
 *
 * @param session  Session to do the connect complete on.
 *
 * @return                 @c 1 OK, 0 on failure.
 */
int coap_netif_strm_connect2(coap_session_t *session);

/**
 * Function interface for layer data stream receiving. This function returns
 * the number of bytes that have been read, or -1 on error.
 *
 * @param session          Session to receive data on.
 * @param data             The data to receive.
 * @param datalen          The maximum length of @p data.
 *
 * @return                 >=0 Number of bytes read.
 *                         -1  Error of some sort (see errno).
 */
ssize_t coap_netif_strm_read(coap_session_t *session, uint8_t *data,
                             size_t datalen);

/**
 * Function interface for netif stream data transmission. This function returns
 * the number of bytes that have been transmitted, or a value less than zero
 * on error. The number of bytes written may be less than datalen because of
 * congestion control.
 *
 * @param session          Session to send data on.
 * @param data             The data to send.
 * @param datalen          The actual length of @p data.
 *
 * @return                 The number of bytes written on success, or a value
 *                         less than zero on error.
 */
ssize_t coap_netif_strm_write(coap_session_t *session,
                              const uint8_t *data, size_t datalen);

/**
 * Layer function interface for Netif close for a session.
 *
 * @param session  Session to do the netif close on.
 */
void coap_netif_close(coap_session_t *session);

/**
 * Layer function interface for Netif close for a endpoint.
 *
 * @param endpoint  Endpoint to do the netif close on.
 */
void coap_netif_close_ep(coap_endpoint_t *endpoint);

/** @} */

#endif /* COAP_NETIF_INTERNAL_H */
