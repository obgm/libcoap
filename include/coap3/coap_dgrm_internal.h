/*
 * coap_dgrm_internal.h -- Datagram (UDP) functions for libcoap
 *
 * Copyright (C) 2019--2025 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_dgrm_internal.h
 * @brief CoAP Datagram (UDP) internal information
 */

#ifndef COAP_DGRM_INTERNAL_H_
#define COAP_DGRM_INTERNAL_H_

#include "coap_internal.h"
#include "coap_io.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup internal_api
 * @defgroup dgrm Datagram (UDP) Support
 * Internal API for handling CoAP Datagrams (UDP) (RFC7252)
 * @{
 */

#if COAP_CLIENT_SUPPORT
/**
 * Create a new UDP socket and 'connect' it to the address tuple.
 *
 * Internal function.
 *
 * @param sock Where socket information is to be filled in.
 * @param local_if The local address to use or NULL.
 * @param server The address to connect to.
 * @param default_port The port to use if not set in @p server.
 * @param local_addr Filled in after connection initiation with
 *                   the local address.
 * @param remote_addr Filled in after connection initiation with
 *                    the remote address.
 *
 * @return @c 1 if succesful, @c 0 if failure of some sort.
*/
int coap_socket_connect_udp(coap_socket_t *sock,
                            const coap_address_t *local_if,
                            const coap_address_t *server,
                            int default_port,
                            coap_address_t *local_addr,
                            coap_address_t *remote_addr);
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT
/**
 * Create a new UDP socket and then listen for new incoming UDP sessions
 * to the specified IP address and port.
 *
 * Internal function.
 *
 * @param sock Where socket information is to be filled in.
 * @param listen_addr The address to be listening for new incoming sessions.
 * @param bound_addr Filled in with the address that the UDP layer.
 *                   is listening on for new incoming UDP sessions.
 *
 * @return @c 1 if succesful, @c 0 if failure of some sort
*/
int coap_socket_bind_udp(coap_socket_t *sock,
                         const coap_address_t *listen_addr,
                         coap_address_t *bound_addr);
#endif /* COAP_SERVER_SUPPORT */

#ifdef WITH_LWIP
ssize_t coap_socket_send_pdu(coap_socket_t *sock, coap_session_t *session,
                             coap_pdu_t *pdu);
#endif

/**
 * Function interface for data transmission. This function returns the number of
 * bytes that have been transmitted, or a value less than zero on error.
 *
 * Internal function.
 *
 * @param sock          Socket to send data over.
 * @param session       Addressing information for unconnected sockets, or NULL
 * @param data          The data to send.
 * @param datalen       The actual length of @p data.
 *
 * @return              The number of bytes written on success, or a value
 *                      less than zero on error.
 */
ssize_t coap_socket_send(coap_socket_t *sock, coap_session_t *session,
                         const uint8_t *data, size_t datalen);

/**
 * Function interface for reading data. This function returns the number of
 * bytes that have been read, or a value less than zero on error. In case of an
 * error, @p *packet is set to NULL.
 *
 * Internal function.
 *
 * @param sock   Socket to read data from.
 * @param packet Received packet metadata and payload. src and dst
 *               should be preset.
 *
 * @return       The number of bytes received on success, or a value less than
 *               zero on error.
 */
ssize_t coap_socket_recv(coap_socket_t *sock, coap_packet_t *packet);

/**
 * Function interface to close off a datagram socket.
 *
 * Internal function.
 *
 * @param sock             Socket to close.
 *
 */
void coap_socket_dgrm_close(coap_socket_t *sock);

/** @} */

#ifdef __cplusplus
extern "C" {
#endif

#endif /* COAP_DGRM_INTERNAL_H_ */
