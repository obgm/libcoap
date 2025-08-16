/*
 * coap_io.h -- Default network I/O functions for libcoap
 *
 * Copyright (C) 2012-2025 Olaf Bergmann <bergmann@tzi.org>
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
#include "coap_layers_internal.h"
#include <sys/types.h>

#include "coap_address.h"

#ifdef WITH_CONTIKI
struct uip_udp_conn;
#endif /* WITH_CONTIKI */

#ifdef RIOT_VERSION
#include "net/gnrc.h"
#include "net/sock/udp.h"
#if ! COAP_DISABLE_TCP
#include "net/sock/tcp.h"
#endif /* ! COAP_DISABLE_TCP */
#endif /* RIOT_VERSION */

#ifdef __cplusplus
extern "C" {
#endif

struct coap_socket_t {
#if defined(WITH_LWIP)
  struct pbuf *p;
  struct udp_pcb *udp_pcb;
#if ! COAP_DISABLE_TCP
  struct tcp_pcb *tcp_pcb;
#endif /* ! COAP_DISABLE_TCP */

#elif defined(WITH_CONTIKI)
  struct uip_udp_conn *udp_conn;
  coap_context_t *context;

#elif defined(RIOT_VERSION)
  sock_udp_t udp;
#if ! COAP_DISABLE_TCP
  sock_tcp_t tcp;
#endif /* ! COAP_DISABLE_TCP */
  coap_fd_t fd;
#else
  coap_fd_t fd;
#endif /* ! WITH_LWIP && !WITH_CONTIKI && ! RIOT_VERSION */
  coap_socket_flags_t flags; /**< 1 or more of COAP_SOCKET* flag values */
  coap_session_t *session; /**< Used to determine session owner. */
#if COAP_SERVER_SUPPORT
  coap_endpoint_t *endpoint; /**< Used by the epoll logic for a listening
                                  endpoint. */
#endif /* COAP_SERVER_SUPPORT */
#if COAP_CLIENT_SUPPORT
  coap_address_t mcast_addr; /**< remote address and port (multicast track) */
#endif /* COAP_CLIENT_SUPPORT */
  coap_layer_func_t lfunc[COAP_LAYER_LAST]; /**< Layer functions to use */
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
#define COAP_SOCKET_SLAVE        0x2000  /**< socket is a slave socket - do not close */

#if COAP_SERVER_SUPPORT
coap_endpoint_t *coap_malloc_endpoint(void);
void coap_mfree_endpoint(coap_endpoint_t *ep);
#endif /* COAP_SERVER_SUPPORT */

const char *coap_socket_format_errno(int error);

#ifdef _WIN32
void coap_win_error_to_errno(void);
#endif /* _WIN32 */

/**
 * Epoll specific function to add the state of events that epoll is to track
 * for the appropriate file descriptor.
 *
 * @param sock    Socket information.
 * @param events  The Epoll events to update
 * @param func    Function that this function was called from.
 *
 */
void coap_epoll_ctl_add(coap_socket_t *sock, uint32_t events, const char *func);

/**
 * Epoll specific function to modify the state of events that epoll is tracking
 * on the appropriate file descriptor.
 *
 * @param sock    Socket information.
 * @param events  The Epoll events to update
 * @param func    Function that this function was called from.
 *
 */
void coap_epoll_ctl_mod(coap_socket_t *sock, uint32_t events, const char *func);

/**
 * Update when to continue with I/O processing, unless packets come in in the
 * meantime. Typically, this timeout triggers retransmissions.
 *
 * @param context The CoAP context.
 * @param delay The time to delay before continuing with I/O processing.
 */
void coap_update_io_timer(coap_context_t *context, coap_tick_t delay);

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
void coap_io_process_timeout(void *arg);
void coap_io_lwip_init(void);
void coap_io_lwip_cleanup(void);
#endif

struct coap_packet_t {
  coap_addr_tuple_t addr_info; /**< local and remote addresses */
  int ifindex;                /**< the interface index */
  size_t length;             /**< length of payload */
  unsigned char *payload;    /**< payload */
};

#ifdef WITH_CONTIKI
void coap_start_io_process(void);
void coap_stop_io_process(void);
#endif /* WITH_CONTIKI */

#ifdef __cplusplus
}
#endif

#endif /* COAP_IO_INTERNAL_H_ */
