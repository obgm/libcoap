/*
 * coap_io.h -- Default network I/O functions for libcoap
 *
 * Copyright (C) 2012-2013 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#ifndef _COAP_IO_H_
#define _COAP_IO_H_

#include <assert.h>
#include <sys/types.h>

#include "address.h"

#ifdef _WIN32
typedef SOCKET coap_fd_t;
#define coap_closesocket closesocket
#define COAP_SOCKET_ERROR SOCKET_ERROR
#define COAP_INVALID_SOCKET INVALID_SOCKET
#else
typedef int coap_fd_t;
#define coap_closesocket close
#define COAP_SOCKET_ERROR (-1)
#define COAP_INVALID_SOCKET (-1)
#endif

struct coap_packet_t;
typedef struct coap_packet_t coap_packet_t;

struct coap_session_t;
typedef struct coap_session_t coap_session_t;

struct coap_context_t;
typedef struct coap_context_t coap_context_t;

struct coap_pdu_t;
typedef struct coap_pdu_t coap_pdu_t;

typedef uint16_t coap_socket_flags_t;

typedef struct coap_socket_t {
#if defined(WITH_LWIP)
  struct udp_pcb *pcb;
#elif defined(WITH_CONTIKI)
  void *conn;
#else
  coap_fd_t fd;
#endif /* WITH_LWIP */
  coap_socket_flags_t flags;
} coap_socket_t;

/**
 * coap_socket_flags_t values
 */
#define COAP_SOCKET_EMPTY       0x0000  /**< the socket is not used */
#define COAP_SOCKET_NOT_EMPTY   0x0001  /**< the socket is not empty */
#define COAP_SOCKET_BOUND       0x0002  /**< the socket is bound */
#define COAP_SOCKET_CONNECTED   0x0004  /**< the socket is connected */
#define COAP_SOCKET_WANT_DATA   0x0010  /**< non blocking socket is waiting for reading */
#define COAP_SOCKET_WANT_WRITE  0x0020  /**< non blocking socket is waiting for writing */
#define COAP_SOCKET_HAS_DATA    0x0100  /**< non blocking socket can now read without blocking */
#define COAP_SOCKET_CAN_WRITE   0x0200  /**< non blocking socket can now write without blocking */

struct coap_endpoint_t *coap_malloc_endpoint( void );
void coap_mfree_endpoint( struct coap_endpoint_t *ep );

int
coap_socket_connect_udp( coap_socket_t *sock,
                         const coap_address_t *local_if,
                         const coap_address_t *server,
                         int default_port,
                         coap_address_t *local_addr,
                         coap_address_t *remote_addr );

int
coap_socket_bind_udp( coap_socket_t *sock,
                      const coap_address_t *listen_addr,
                      coap_address_t *bound_addr );

void coap_socket_close( coap_socket_t *sock );

ssize_t
coap_socket_send( coap_socket_t *sock, coap_session_t *session,
                  const uint8_t *data, size_t data_len );


#ifdef WITH_LWIP
ssize_t
coap_socket_send_pdu( coap_socket_t *sock, coap_session_t *session,
                      coap_pdu_t *pdu );
#endif

const char *coap_socket_strerror();

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
 * @param packet A result parameter where a pointer to the received packet
 *               structure is stored. The caller must call coap_free_packet to
 *               release the storage used by this packet.
 *
 * @return       The number of bytes received on success, or a value less than
 *               zero on error.
 */
ssize_t coap_network_read( coap_socket_t *sock, coap_packet_t **packet );

#ifndef coap_mcast_interface
# define coap_mcast_interface(Local) 0
#endif

/**
 * Releases the storage allocated for @p packet.
 */
void coap_free_packet(coap_packet_t *packet);

/**
 * Given a packet, set msg and msg_len to an address and length of the packet's
 * data in memory.
 * */
void coap_packet_get_memmapped(coap_packet_t *packet,
                               unsigned char **address,
                               size_t *length);

void coap_packet_set_addr( coap_packet_t *packet, const coap_address_t *src,
                           const coap_address_t *dst );

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
  uint16_t srcport;
};
#else
struct coap_packet_t {
  coap_address_t src;	      /**< the packet's source address */
  coap_address_t dst;	      /**< the packet's destination address */
  int ifindex;                /**< the interface index */
  size_t length;              /**< length of payload */
  unsigned char payload[];    /**< payload */
};
#endif

#endif /* _COAP_IO_H_ */
