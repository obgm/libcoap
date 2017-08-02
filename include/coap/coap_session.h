/* coap_session.h -- Session management for libcoap
*
* Copyright (C) 2017 Jean-Claue Michelou <jcm@spinetix.com>
*
* This file is part of the CoAP library libcoap. Please see
* README for terms of use.
*/

#ifndef _SESSION_H_
#define _SESSION_H_


#include "coap_io.h"
#include "coap_time.h"
#include "pdu.h"

struct coap_endpoint_t;
struct coap_contex_t;
struct coap_queue_t;

#define COAP_DEFAULT_SESSION_TIMEOUT 300

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
#define COAP_SESSION_TYPE_CLIENT 1  /**< client-side */
#define COAP_SESSION_TYPE_SERVER 2  /**< server-side */
#define COAP_SESSION_TYPE_HELLO  3  /**< server-side ephemeral session for responding to a client hello */

typedef uint8_t coap_session_state_t;
/**
 * coap_session_state_t values
 */
#define COAP_SESSION_STATE_NONE		0
#define COAP_SESSION_STATE_CONNECTING	1
#define COAP_SESSION_STATE_HANDSHAKE	2
#define COAP_SESSION_STATE_ESTABLISHED	3

typedef struct coap_session_t {
  struct coap_session_t *next;
  coap_proto_t proto;		  /**< protocol used */
  coap_session_type_t type;	  /**< client or server side socket */
  coap_session_state_t state;	  /**< current state of relationaship with peer */
  uint8_t ref;			  /**< reference count from queues */
  uint16_t mtu;			  /**< path mtu */
  uint16_t tls_overhead;	  /**< overhead of TLS layer */
  coap_address_t remote_addr;     /**< remote address and port */
  coap_address_t local_addr;	  /**< local address and port */
  int ifindex;                    /**< interface index */
  coap_socket_t sock;		  /**< socket object for the session, if any */
  struct coap_endpoint_t *endpoint;	  /**< session's endpoint */
  struct coap_context_t *context;	  /**< session's context */
  void *tls;			  /**< security parameters */
  uint16_t tx_mid;                /**< the last message id that was used in this session */
  struct coap_queue_t *sendqueue; /**< list of messages waiting to be sent */
  coap_tick_t last_rx_tx;
  uint8_t *psk_identity;
  size_t psk_identity_len;
  uint8_t *psk_key;
  size_t psk_key_len;
} coap_session_t;

/**
* Increment reference counter on a session.
*
* @param session The CoAP session.
* @return same as session
*/
coap_session_t *coap_session_reference(coap_session_t *session);

/**
* Decrement reference counter on a session.
* Note that the session may be deleted as a result and should not be used
* after this call.
*
* @param session The CoAP session.
*/
void coap_session_release(coap_session_t *session);

/**
* Notify session that it has failed connecting or has been disconnected.
*
* @param session The CoAP session.
*/
void coap_session_disconnected(coap_session_t *session);

/**
* Notify session that the remote peer is no longer listening.
*
* @param session The CoAP session.
*/
void coap_session_reset(coap_session_t *session);

/**
* Notify session that it has just connected or reconnected.
*
* @param session The CoAP session.
*/
void coap_session_connected(coap_session_t *session);

/**
* Set the session MTU. This is the maximum message size that can be sent,
* excluding IP and UDP overhead.
*
* @param session The CoAP session.
* @param mtu maximum message size
*/
void coap_session_set_mtu(coap_session_t *session, unsigned mtu);

/**
 * Get maximum acceptable PDU size
 *
 * @param session The CoAP session.
 * @return maximum PDU size
 */
unsigned int coap_session_max_pdu_size(coap_session_t *session);

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
  struct coap_context_t *ctx,
  const coap_address_t *local_if,
  const coap_address_t *server,
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
  struct coap_context_t *ctx,
  const coap_address_t *local_if,
  const coap_address_t *server,
  coap_proto_t proto,
  const char *identity,
  const uint8_t *key,
  unsigned key_len
);

/**
* Function interface for data transmission. This function returns the number of
* bytes that have been transmitted, or a value less than zero on error.
*
* @param session          Session to send data on.
* @param data             The data to send.
* @param datalen          The actual length of @p data.
*
* @return                 The number of bytes written on success, or a value
*                         less than zero on error.
*/
ssize_t coap_session_send(coap_session_t *session,
  const uint8_t *data, size_t datalen);

/**
 * Get session description.
 *
 * @param session  The CoAP session.
 * @return description string
 */
const char *coap_session_str(const coap_session_t *session);

ssize_t
coap_session_delay_pdu(coap_session_t *session, coap_pdu_t *pdu,
                       struct coap_queue_t *node);
/**
* Abstraction of virtual endpoint that can be attached to coap_context_t. The
* tuple (handle, addr) must uniquely identify this endpoint.
*/
typedef struct coap_endpoint_t {
  struct coap_endpoint_t *next;
  struct coap_context_t *context; /**< endpoint's context */
  coap_proto_t proto;		  /**< protocol used on this interface */
  uint16_t default_mtu; 	  /**< default mtu for this interface */
  coap_socket_t sock;		  /**< socket object for the interface, if any */
  coap_address_t bind_addr;	  /**< local interface address */
  coap_session_t *sessions;	  /**< list of active sessions */
  coap_session_t hello;		  /**< special session of DTLS hello messages */
} coap_endpoint_t;

/**
* Create a new endpoint for communicating with peers.
*
* @param context	The coap context that will own the new endpoint
* @param listen_addr	Address the endpoint will listen for incoming requests on or originate outgoing requests from. Use NULL to specify that no incoming request will be accepted and use a random endpoint.
* @param proto		Protocol used on this endpoint
*/

coap_endpoint_t *coap_new_endpoint(struct coap_context_t *context, const coap_address_t *listen_addr, coap_proto_t proto);

/**
* Set the endpoint's default MTU. This is the maximum message size that can be
* sent, excluding IP and UDP overhead.
*
* @param session The CoAP session.
* @param mtu maximum message size
*/
void coap_endpoint_set_default_mtu(coap_endpoint_t *ep, unsigned mtu);

void coap_free_endpoint(coap_endpoint_t *ep);


/**
* Get endpoint description.
*
* @param session  The CoAP endpoint.
* @return description string
*/
const char *coap_endpoint_str(const coap_endpoint_t *endpoint);

/**
* Lookup the server session for the packet received on an endpoint, or create
* a new one.
*
* @param endpoint Active endpoint the packet was received on.
* @param packet Received packet.
* @return The CoAP session.
*/
coap_session_t *coap_endpoint_get_session(coap_endpoint_t *endpoint,
  const struct coap_packet_t *packet, coap_tick_t now);

coap_session_t *coap_endpoint_new_dtls_session(coap_endpoint_t *endpoint,
  const struct coap_packet_t *packet, coap_tick_t now);

coap_session_t *coap_session_get_by_peer(struct coap_context_t *ctx,
  const struct coap_address_t *remote_addr, int ifindex);

void coap_session_free(coap_session_t *session);


#endif  /* _SESSION_H */
