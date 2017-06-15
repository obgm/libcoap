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

typedef uint8_t coap_proto_t;
 /**
 * coap_proto_t values
 */
#define COAP_PROTO_NONE	  0
#define COAP_PROTO_UDP	  1
#define COAP_PROTO_DTLS	  2

typedef uint8_t coap_session_type_t;
/**
* coap_session_type_t values
*/
#define COAP_SESSION_TYPE_CLIENT 1
#define COAP_SESSION_TYPE_SERVER 2

typedef uint8_t coap_session_state_t;
/**
* coap_session_state_t values
*/
#define COAP_SESSION_STATE_NONE		0
#define COAP_SESSION_STATE_CONNECTING	1
#define COAP_SESSION_STATE_HANDSHAKE	2
#define COAP_SESSION_STATE_ESTABLISHED	3

/**
 * Abstraction of virtual endpoint that can be attached to coap_context_t. The
 * tuple (handle, addr) must uniquely identify this endpoint.
 */
typedef struct coap_endpoint_t {
  struct coap_endpoint_t *next;
  coap_context_t *context;	  /**< endpoint's context */
  coap_proto_t proto;		  /**< protocol used on this interface */
  coap_socket_t sock;		  /**< socket object for the interface, if any */
  coap_address_t bind_addr;	  /**< local interface address */
  coap_session_t *sessions;	  /**< list of active sessions */
} coap_endpoint_t;

/**
 * Create a new endpoint for communicating with peers.
 *
 * @param context	The coap context that will own the new endpoint
 * @param listen_addr	Address the endpoint will listen for incoming requests on or originate outgoing requests from. Use NULL to specify that no incoming request will be accepted and use a random endpoint.
 * @param proto		Protocol used on this endpoint
*/

coap_endpoint_t *coap_new_endpoint( coap_context_t *context, const coap_address_t *listen_addr, coap_proto_t proto );

typedef struct coap_session_t {
  struct coap_session_t *next;
  coap_proto_t proto;		  /**< protocol used */
  coap_session_type_t type;	  /**< client or server side socket */
  coap_session_state_t state;	  /**< current state of relationaship with peer */
  int ref;			  /**< reference count from queues */
  coap_address_t local_addr;	  /**< local address and port */
  coap_address_t remote_addr;     /**< remote address and port */
  int ifindex;                    /**< interface index */
  coap_socket_t sock;		  /**< socket object for the session, if any */
  coap_endpoint_t *endpoint;	  /**< session's endpoint */
  coap_context_t *context;	  /**< session's context */
  void *tls;			  /**< security parameters */
} coap_session_t;

/**
 * Increment reference counter on a session.
 *
 * @param session The CoAP session.
 * @return same as session
*/
coap_session_t *coap_session_reference( coap_session_t *session );

/**
* Decrement reference counter on a session.
*
* @param session The CoAP session.
*/
void coap_session_release( coap_session_t *session );

/**
 * Lookup the server session for the packet received on an endpoint, or create
 * a new one.
 *
 * @param endpoint Active endpoint the packet was received on.
 * @param packet Received packet.
 * @return The CoAP session.
*/
coap_session_t *coap_endpoint_get_session( coap_endpoint_t *endpoint, const coap_packet_t *packet );

/**
 * Creates a new client session to the designated server.
 * @param ctx The CoAP context.
 * @param local_if Address of local interface. It is recommended to use NULL to let the operating system choose a suitable local interface. If an address is specified, the port number should be zero, which means that a free port is automatically selected.
 * @param server The server's address. If the port number is zero, the default port for the protocol will be used.
 * @param proto Protocol.
 *
 * @return A new CoAP session or NULL if failed. Call coap_session_release to free.
 */
coap_session_t *coap_new_client_session(
  coap_context_t *ctx,
  coap_address_t *local_if,
  coap_address_t *server,
  coap_proto_t proto
);

/**
* Creates a new client session to the designated server with PSK credentials
* @param ctx The CoAP context.
* @param local_if Address of local interface. It is recommended to use NULL to let the operating system choose a suitable local interface. If an address is specified, the port number should be zero, which means that a free port is automatically selected.
* @param server The server's address. If the port number is zero, the default port for the protocol will be used.
* @param identity PSK client identity
* @param identity_len Length PSK client identity
* @param key PSK shared key
* @param key_len PSK shared key length
* @param proto Protocol.
*
* @return A new CoAP session or NULL if failed. Call coap_session_release to free.
*/
coap_session_t *coap_new_client_session_psk(
  coap_context_t *ctx,
  coap_address_t *local_if,
  coap_address_t *server,
  coap_proto_t proto,
  const uint8_t *identity,
  size_t identity_len,
  const uint8_t *key,
  size_t key_len
);

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
ssize_t coap_network_send( coap_socket_t *sock, const coap_session_t *session, uint8_t *data, size_t datalen );

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

#ifdef WITH_CONTIKI
/*
 * This is only included in coap_io.h instead of .c in order to be available for
 * sizeof in mem.c.
 */
struct coap_packet_t {
  coap_address_t src;           /**< the packet's source address */
  coap_address_t dst;           /**< the packet's destination address */
  int ifindex;
  size_t length;                /**< length of payload */
  unsigned char payload[];      /**< payload */
};
#endif

#ifdef WITH_LWIP
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
#endif

#endif /* _COAP_IO_H_ */
