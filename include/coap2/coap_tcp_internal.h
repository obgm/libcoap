/*
 * coap_tcp_internal.h -- TCP functions for libcoap
 *
 * Copyright (C) 2019--2020 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_tcp_internal.h
 * @brief COAP tcp internal information
 */

#ifndef COAP_TCP_INTERNAL_H_
#define COAP_TCP_INTERNAL_H_

#include "coap_io.h"

/**
 * @defgroup tcp TCP Support
 * Internal API functions for interfacing with the system TCP stack.
 * @{
 */

int
coap_socket_connect_tcp1(coap_socket_t *sock,
                         const coap_address_t *local_if,
                         const coap_address_t *server,
                         int default_port,
                         coap_address_t *local_addr,
                         coap_address_t *remote_addr);

int
coap_socket_connect_tcp2(coap_socket_t *sock,
                         coap_address_t *local_addr,
                         coap_address_t *remote_addr);

int
coap_socket_bind_tcp(coap_socket_t *sock,
                     const coap_address_t *listen_addr,
                     coap_address_t *bound_addr);

int
coap_socket_accept_tcp(coap_socket_t *server,
                       coap_socket_t *new_client,
                       coap_address_t *local_addr,
                       coap_address_t *remote_addr);

/** @} */

#endif /* COAP_TCP_INTERNAL_H_ */
