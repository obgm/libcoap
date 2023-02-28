/*
 * coap_netif.c -- Netif functions for libcoap
 *
 * Copyright (C) 2023 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_netif.c
 * @brief CoAP Netif handling functions
 */

#include "coap3/coap_internal.h"
#include "coap3/coap_session_internal.h"

/*
 * return 1 netif still in use.
 *        0 netif no longer available.
 */
int
coap_netif_available(coap_session_t *session) {
  return session->sock.flags != COAP_SOCKET_EMPTY;
}

/*
 * dgram
 * return +ve Number of bytes written.
 *         -1 Error error in errno).
 */
ssize_t
coap_netif_dgrm_write(coap_session_t *session, const uint8_t *data,
                      size_t datalen) {
  ssize_t bytes_written;
  int keep_errno;

  coap_socket_t *sock = &session->sock;
#if COAP_SERVER_SUPPORT
  if (sock->flags == COAP_SOCKET_EMPTY) {
    assert(session->endpoint != NULL);
    sock = &session->endpoint->sock;
  }
#endif /* COAP_SERVER_SUPPORT */

  bytes_written = coap_socket_send(sock, session, data, datalen);
  keep_errno = errno;
  if (bytes_written <= 0) {
    coap_log_debug( "*  %s: failed to send %zd bytes (%s) state %d\n",
                   coap_session_str(session), datalen,
                   coap_socket_strerror(), session->state);
  } else if (bytes_written == (ssize_t)datalen) {
    coap_ticks(&session->last_rx_tx);
    coap_log_debug("*  %s: sent %zd bytes\n",
             coap_session_str(session), datalen);
  } else {
    coap_ticks(&session->last_rx_tx);
    coap_log_debug("*  %s: sent %zd bytes of %zd\n",
             coap_session_str(session), bytes_written, datalen);
    errno = keep_errno;
  }
  return bytes_written;
}

#if COAP_SERVER_SUPPORT
/*
 * dgram
 * return +ve Number of bytes written.
 *         -1 Error error in errno).
 *         -2 ICMP error response
 */
ssize_t
coap_netif_dgrm_read_ep(coap_endpoint_t *endpoint, coap_packet_t *packet) {
  ssize_t bytes_read;
  int keep_errno;

  bytes_read = coap_network_read(&endpoint->sock, packet);
  keep_errno = errno;
  if (bytes_read == -1) {
    coap_log_debug( "*  %s: failed to read %zd bytes (%s)\n",
                   coap_endpoint_str(endpoint), packet->length,
                   coap_socket_strerror());
    errno = keep_errno;
  } else if (bytes_read > 0) {
    coap_log_debug("*  %s: read %zd bytes\n",
             coap_endpoint_str(endpoint), bytes_read);
    errno = keep_errno;
  }
  return bytes_read;
}
#endif /* COAP_SERVER_SUPPORT */

/*
 * dgram
 * return +ve Number of bytes written.
 *         -1 Error error in errno).
 *         -2 ICMP error response
 */
ssize_t
coap_netif_dgrm_read(coap_session_t *session, coap_packet_t *packet) {
  ssize_t bytes_read;
  int keep_errno;

  bytes_read = coap_network_read(&session->sock, packet);
  keep_errno = errno;
  if (bytes_read == -1) {
    coap_log_debug( "*  %s: failed to read %zd bytes (%s) state %d\n",
                   coap_session_str(session), packet->length,
                   coap_socket_strerror(), session->state);
    errno = keep_errno;
  } else if (bytes_read > 0) {
    coap_ticks(&session->last_rx_tx);
    coap_log_debug("*  %s: read %zd bytes\n",
             coap_session_str(session), bytes_read);
    errno = keep_errno;
  }
  return bytes_read;
}
