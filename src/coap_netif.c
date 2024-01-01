/*
 * coap_netif.c -- Netif functions for libcoap
 *
 * Copyright (C) 2023-2024 Jon Shallow <supjps-libcoap@jpshallow.com>
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

#if COAP_SERVER_SUPPORT
/*
 * return 1 netif still in use.
 *        0 netif no longer available.
 */
int
coap_netif_available_ep(coap_endpoint_t *endpoint) {
  return endpoint->sock.flags != COAP_SOCKET_EMPTY;
}

int
coap_netif_dgrm_listen(coap_endpoint_t *endpoint,
                       const coap_address_t *listen_addr) {
  if (!coap_socket_bind_udp(&endpoint->sock, listen_addr,
                            &endpoint->bind_addr)) {
    return 0;
  }
  endpoint->sock.flags |= COAP_SOCKET_NOT_EMPTY | COAP_SOCKET_BOUND | COAP_SOCKET_WANT_READ;
  return 1;
}
#endif /* COAP_SERVER_SUPPORT */

#if COAP_CLIENT_SUPPORT
int
coap_netif_dgrm_connect(coap_session_t *session, const coap_address_t *local_if,
                        const coap_address_t *server, int default_port) {
  if (!coap_socket_connect_udp(&session->sock, local_if, server,
                               default_port,
                               &session->addr_info.local,
                               &session->addr_info.remote)) {
    return 0;
  }
  return 1;
}
#endif /* COAP_CLIENT_SUPPORT */

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

  bytes_read = coap_socket_recv(&session->sock, packet);
  keep_errno = errno;
  if (bytes_read == -1) {
    coap_log_debug("*  %s: netif: failed to read %zd bytes (%s) state %d\n",
                   coap_session_str(session), packet->length,
                   coap_socket_strerror(), session->state);
    errno = keep_errno;
  } else if (bytes_read > 0) {
    coap_ticks(&session->last_rx_tx);
    coap_log_debug("*  %s: netif: recv %4zd bytes\n",
                   coap_session_str(session), bytes_read);
  }
  return bytes_read;
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

  bytes_read = coap_socket_recv(&endpoint->sock, packet);
  keep_errno = errno;
  if (bytes_read == -1) {
    coap_log_debug("*  %s: netif: failed to read %zd bytes (%s)\n",
                   coap_endpoint_str(endpoint), packet->length,
                   coap_socket_strerror());
    errno = keep_errno;
  } else if (bytes_read > 0) {
    /* Let the caller do the logging as session available by then */
  }
  return bytes_read;
}
#endif /* COAP_SERVER_SUPPORT */

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
    coap_log_debug("*  %s: netif: failed to send %zd bytes (%s) state %d\n",
                   coap_session_str(session), datalen,
                   coap_socket_strerror(), session->state);
    errno = keep_errno;
  } else {
    coap_ticks(&session->last_rx_tx);
    if (bytes_written == (ssize_t)datalen)
      coap_log_debug("*  %s: netif: sent %4zd bytes\n",
                     coap_session_str(session), bytes_written);
    else
      coap_log_debug("*  %s: netif: sent %4zd of %4zd bytes\n",
                     coap_session_str(session), bytes_written, datalen);
  }
  return bytes_written;
}

#if !COAP_DISABLE_TCP
#if COAP_SERVER_SUPPORT
int
coap_netif_strm_listen(coap_endpoint_t *endpoint,
                       const coap_address_t *listen_addr) {
  if (!coap_socket_bind_tcp(&endpoint->sock, listen_addr,
                            &endpoint->bind_addr)) {
    return 0;
  }
  endpoint->sock.flags |= COAP_SOCKET_NOT_EMPTY | COAP_SOCKET_BOUND |
                          COAP_SOCKET_WANT_ACCEPT;
  return 1;
}

int
coap_netif_strm_accept(coap_endpoint_t *endpoint, coap_session_t *session, void *extra) {
  if (!coap_socket_accept_tcp(&endpoint->sock, &session->sock,
                              &session->addr_info.local,
                              &session->addr_info.remote, extra)) {
    return 0;
  }
  session->sock.flags |= COAP_SOCKET_NOT_EMPTY | COAP_SOCKET_CONNECTED |
                         COAP_SOCKET_WANT_READ;
  return 1;
}
#endif /* COAP_SERVER_SUPPORT */

#if COAP_CLIENT_SUPPORT
int
coap_netif_strm_connect1(coap_session_t *session,
                         const coap_address_t *local_if,
                         const coap_address_t *server, int default_port) {
  if (!coap_socket_connect_tcp1(&session->sock, local_if, server,
                                default_port,
                                &session->addr_info.local,
                                &session->addr_info.remote)) {
    return 0;
  }
  return 1;
}

int
coap_netif_strm_connect2(coap_session_t *session) {
  if (!coap_socket_connect_tcp2(&session->sock,
                                &session->addr_info.local,
                                &session->addr_info.remote)) {
    return 0;
  }
  return 1;
}
#endif /* COAP_CLIENT_SUPPORT */

/*
 * strm
 * return >=0 Number of bytes read.
 *         -1 Error (error in errno).
 */
ssize_t
coap_netif_strm_read(coap_session_t *session, uint8_t *data, size_t datalen) {
  ssize_t bytes_read = coap_socket_read(&session->sock, data, datalen);
  int keep_errno = errno;

  if (bytes_read >= 0) {
    coap_log_debug("*  %s: netif: recv %4zd bytes\n",
                   coap_session_str(session), bytes_read);
  } else if (bytes_read == -1 && errno != EAGAIN) {
    coap_log_debug("*  %s: netif: failed to receive any bytes (%s) state %d\n",
                   coap_session_str(session), coap_socket_strerror(), session->state);
    errno = keep_errno;
  }
  return bytes_read;
}

/*
 * strm
 * return +ve Number of bytes written.
 *         -1 Error (error in errno).
 */
ssize_t
coap_netif_strm_write(coap_session_t *session, const uint8_t *data,
                      size_t datalen) {
  ssize_t bytes_written = coap_socket_write(&session->sock, data, datalen);
  int keep_errno = errno;

  if (bytes_written <= 0) {
    coap_log_debug("*  %s: netif: failed to send %zd bytes (%s) state %d\n",
                   coap_session_str(session), datalen,
                   coap_socket_strerror(), session->state);
    errno = keep_errno;
  } else {
    coap_ticks(&session->last_rx_tx);
    if (bytes_written == (ssize_t)datalen)
      coap_log_debug("*  %s: netif: sent %4zd bytes\n",
                     coap_session_str(session), bytes_written);
    else
      coap_log_debug("*  %s: netif: sent %4zd of %4zd bytes\n",
                     coap_session_str(session), bytes_written, datalen);
  }
  return bytes_written;
}
#endif /* COAP_DISABLE_TCP */

void
coap_netif_close(coap_session_t *session) {
  if (coap_netif_available(session))
    coap_socket_close(&session->sock);
}

#if COAP_SERVER_SUPPORT
void
coap_netif_close_ep(coap_endpoint_t *endpoint) {
  coap_socket_close(&endpoint->sock);
}
#endif /* COAP_SERVER_SUPPORT */
