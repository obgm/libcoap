/*
 * coap_io.h -- Default network I/O functions for libcoap
 *
 * Copyright (C) 2012-2022 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_io_internal.h
 * @brief Internal network I/O functions
 */

#ifndef COAP_IO_INTERNAL_H_
#define COAP_IO_INTERNAL_H_

#include "coap_internal.h"
#include <sys/types.h>

#include "coap_address.h"

#ifdef RIOT_VERSION
#include "net/gnrc.h"
#endif /* RIOT_VERSION */

struct coap_socket_t {
#if defined(WITH_LWIP)
  struct udp_pcb *pcb;
#elif defined(WITH_CONTIKI)
  void *conn;
#else
  coap_fd_t fd;
#endif /* WITH_LWIP */
#if defined(RIOT_VERSION)
  gnrc_pktsnip_t *pkt; /* pointer to received packet for processing */
#endif /* RIOT_VERSION */
  coap_socket_flags_t flags;
  coap_session_t *session; /* Used by the epoll logic for an active session. */
  coap_endpoint_t *endpoint; /* Used by the epoll logic for a listening
                                endpoint. */
};

/**
 * coap_socket_flags_t values
 */
#define COAP_SOCKET_EMPTY        0x0000  /**< the socket is not used */
#define COAP_SOCKET_NOT_EMPTY    0x0001  /**< the socket is not empty */
#define COAP_SOCKET_BOUND        0x0002  /**< the socket is bound */
#define COAP_SOCKET_CONNECTED    0x0004  /**< the socket is connected */
#define COAP_SOCKET_WANT_READ    0x0010  /**< non blocking socket is waiting for reading */
#define COAP_SOCKET_WANT_WRITE   0x0020  /**< non blocking socket is waiting for writing */
#define COAP_SOCKET_WANT_ACCEPT  0x0040  /**< non blocking server socket is waiting for accept */
#define COAP_SOCKET_WANT_CONNECT 0x0080  /**< non blocking client socket is waiting for connect */
#define COAP_SOCKET_CAN_READ     0x0100  /**< non blocking socket can now read without blocking */
#define COAP_SOCKET_CAN_WRITE    0x0200  /**< non blocking socket can now write without blocking */
#define COAP_SOCKET_CAN_ACCEPT   0x0400  /**< non blocking server socket can now accept without blocking */
#define COAP_SOCKET_CAN_CONNECT  0x0800  /**< non blocking client socket can now connect without blocking */
#define COAP_SOCKET_MULTICAST    0x1000  /**< socket is used for multicast communication */

#if COAP_SERVER_SUPPORT
coap_endpoint_t *coap_malloc_endpoint( void );
void coap_mfree_endpoint( coap_endpoint_t *ep );
#endif /* COAP_SERVER_SUPPORT */

const char *coap_socket_format_errno(int error);

#if COAP_CLIENT_SUPPORT
int
coap_socket_connect_udp(coap_socket_t *sock,
                        const coap_address_t *local_if,
                        const coap_address_t *server,
                        int default_port,
                        coap_address_t *local_addr,
                        coap_address_t *remote_addr);
#endif /* COAP_CLIENT_SUPPORT */

int
coap_socket_bind_udp(coap_socket_t *sock,
                     const coap_address_t *listen_addr,
                     coap_address_t *bound_addr );

void coap_socket_close(coap_socket_t *sock);

ssize_t
coap_socket_send( coap_socket_t *sock, coap_session_t *session,
                  const uint8_t *data, size_t data_len );

ssize_t
coap_socket_write(coap_socket_t *sock, const uint8_t *data, size_t data_len);

ssize_t
coap_socket_read(coap_socket_t *sock, uint8_t *data, size_t data_len);

void
coap_epoll_ctl_mod(coap_socket_t *sock, uint32_t events, const char *func);

/**
 * Update the epoll timer fd as to when it is to trigger.
 *
 * @param context The context to update the epoll timer on.
 * @param delay The time to delay before the epoll timer fires.
 */
void coap_update_epoll_timer(coap_context_t *context, coap_tick_t delay);

#ifdef WITH_LWIP
ssize_t
coap_socket_send_pdu( coap_socket_t *sock, coap_session_t *session,
                      coap_pdu_t *pdu );
#endif

/**
 * Function interface for data transmission. This function returns the number of
 * bytes that have been transmitted, or a value less than zero on error.
 *
 * @param sock             Socket to send data with
 * @param session          Addressing information for unconnected sockets, or NULL
 * @param data             The data to send.
 * @param datalen          The actual length of @p data.
 *
 * @return                 The number of bytes written on success, or a value
 *                         less than zero on error.
 */
ssize_t coap_network_send( coap_socket_t *sock, const coap_session_t *session, const uint8_t *data, size_t datalen );

/**
 * Function interface for reading data. This function returns the number of
 * bytes that have been read, or a value less than zero on error. In case of an
 * error, @p *packet is set to NULL.
 *
 * @param sock   Socket to read data from
 * @param packet Received packet metadata and payload. src and dst should be preset.
 *
 * @return       The number of bytes received on success, or a value less than
 *               zero on error.
 */
ssize_t coap_network_read( coap_socket_t *sock, coap_packet_t *packet );

#ifndef coap_mcast_interface
# define coap_mcast_interface(Local) 0
#endif

/**
 * Given a packet, set msg and msg_len to an address and length of the packet's
 * data in memory.
 * */
void coap_packet_get_memmapped(coap_packet_t *packet,
                               unsigned char **address,
                               size_t *length);

#ifdef WITH_LWIP
/**
 * Get the pbuf of a packet. The caller takes over responsibility for freeing
 * the pbuf.
 */
struct pbuf *coap_packet_extract_pbuf(coap_packet_t *packet);
#endif

#if defined(WITH_LWIP)
/*
 * This is only included in coap_io.h instead of .c in order to be available for
 * sizeof in lwippools.h.
 * Simple carry-over of the incoming pbuf that is later turned into a node.
 *
 * Source address data is currently side-banded via ip_current_dest_addr & co
 * as the packets have limited lifetime anyway.
 */
struct coap_packet_t {
  struct pbuf *pbuf;
  const coap_endpoint_t *local_interface;
  coap_addr_tuple_t addr_info; /**< local and remote addresses */
  int ifindex;                /**< the interface index */
//  uint16_t srcport;
};
#else
struct coap_packet_t {
  coap_addr_tuple_t addr_info; /**< local and remote addresses */
  int ifindex;                /**< the interface index */
  size_t length;              /**< length of payload */
  unsigned char payload[COAP_RXBUFFER_SIZE]; /**< payload */
};
#endif

#endif /* COAP_IO_INTERNAL_H_ */
