/* coap_io.h -- Default network I/O functions for libcoap
 *
 * Copyright (C) 2012--2013 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

#ifndef _COAP_IO_H_
#define _COAP_IO_H_

#include "config.h"

#ifdef HAVE_ASSERT_H
#include <assert.h>
#else
#ifndef assert
#warning "assertions are disabled"
#  define assert(x)
#endif
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include "address.h"

/**
 * Abstract handle that is used to identify a local network interface.
 */
typedef int coap_if_handle_t;

/** Invalid interface handle */
#define COAP_IF_INVALID -1

typedef struct coap_packet_t {
  coap_if_handle_t hnd;	      /**< the interface handle */
  coap_address_t src;	      /**< the packet's source address */
  coap_address_t dst;	      /**< the packet's destination address */
  
  int ifindex;
  void *session;		/**< opaque session data */

  size_t length;		/**< length of payload */
  unsigned char payload[];	/**< payload */
} coap_packet_t;

struct coap_context_t;

/**
 * Abstraction of virtual endpoint that can be attached to
 * coap_context_t. The tuple (handle, addr) must uniquely identify
 * this endpoint.
 */
typedef struct coap_endpoint_t {
  int handle;	       /**< opaque handle to identify this endpoint */
  coap_address_t addr; /**< local interface address */
  int ifindex;
  int flags;
} coap_endpoint_t;

#define COAP_ENDPOINT_NOSEC 0x00
#define COAP_ENDPOINT_DTLS  0x01

coap_endpoint_t *coap_new_endpoint(const coap_address_t *addr, int flags);
void coap_free_endpoint(coap_endpoint_t *ep);

/**
 * Function interface for data transmission. This function returns the number
 * of bytes that have been transmitted, or a value less than zero on error.
 *
 * @param context The calling CoAP context.
 * @param local_interface  The local interface to send the data
 * @param dst     The address of the receiver.
 * @param data    The data to send.
 * @param datalen The actual length of @p data.
 * @return The number of bytes written on success, or a value less than zero 
 *        on error.
 */
ssize_t coap_network_send(struct coap_context_t *context,
			  const coap_endpoint_t *local_interface,
			  const coap_address_t *dst,
			  unsigned char *data, size_t datalen);

/**
 * Function interface for reading data. This function returns the number
 * of bytes that have been read, or a value less than zero on error. In
 * case of an error, @p *packet is set to NULL.
 *
 * @param local_interface The local endpoint where data is read.
 * @param packet A result parameter where a pointer to the received
 *               packet structure is stored. The caller must call
 *               coap_free_packet to release the storage used by this
 *               packet.
 * @return The number of bytes received on success, or a value less than zero 
 *        on error.
 */
ssize_t coap_network_read(coap_endpoint_t *ep, coap_packet_t **packet);

#ifndef coap_mcast_interface
# define coap_mcast_interface(Local) 0
#endif

/** Releases the storage allocated for @p packet */
void coap_free_packet(coap_packet_t *packet);

#endif /* _COAP_IO_H_ */
