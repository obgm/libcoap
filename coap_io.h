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
 * of bytes that have been transmitted, or a value less than zero on error.
 *
 * @param local_interface The local endpoint where data is read.
 * @param remote    Output parameter: filled with the sender's interface address
 * @param data      
 * @param datalen The actual length of @p data.
 * @return The number of bytes written on success, or a value less than zero 
 *        on error.
 */
ssize_t coap_network_read(coap_endpoint_t *local_interface,
			  coap_address_t *remote, 
			  unsigned char *buf, size_t buflen);

#ifndef coap_mcast_interface
# define coap_mcast_interface(Local) 0
#endif


#endif /* _COAP_IO_H_ */
