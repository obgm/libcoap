/*
 * coap_session_internal.h -- Structures, Enums & Functions that are not
 * exposed to application programming
 *
 * Copyright (C) 2010-2019 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_session_internal.h
 * @brief COAP session internal information
 */

#ifndef COAP_SESSION_INTERNAL_H_
#define COAP_SESSION_INTERNAL_H_

/**
 * @defgroup session_internal Sessions (Internal)
 * Structures, Enums and Functions that are not exposed to applications
 * @{
 */

/**
* Abstraction of virtual endpoint that can be attached to coap_context_t. The
* tuple (handle, addr) must uniquely identify this endpoint.
*/
struct coap_endpoint_t {
  struct coap_endpoint_t *next;
  struct coap_context_t *context; /**< endpoint's context */
  coap_proto_t proto;             /**< protocol used on this interface */
  uint16_t default_mtu;           /**< default mtu for this interface */
  coap_socket_t sock;             /**< socket object for the interface, if any */
  coap_address_t bind_addr;       /**< local interface address */
  struct coap_session_t *sessions; /**< hash table or list of active sessions */
};

/** @} */

#endif /* COAP_SESSION_INTERNAL_H_ */
