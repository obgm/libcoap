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
 * Abstraction of virtual endpoint that can be attached to
 * coap_context_t. The tuple (handle, addr) must uniquely identify
 * this endpoint.
 */
typedef struct coap_endpoint_t {
  int handle;	       /**< opaque handle to identify this endpoint */
  coap_address_t addr; /**< local interface address */
} coap_endpoint_t;

coap_endpoint_t *coap_new_endpoint(const coap_address_t *addr);
void coap_free_endpoint(coap_endpoint_t *ep);

/**
 * Function interface for data transmission. This function returns the number
 * of bytes that have been transmitted, or a value less than zero on error.
 *
 * @param ep      The local interface to send the data
 * @param dst     The address of the receiver.
 * @param data    The data to send.
 * @param datalen The actual length of @p data.
 * @return The number of bytes written on success, or a value less than zero 
 *        on error.
 */
ssize_t coap_network_send(const coap_endpoint_t *local_interface,
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
