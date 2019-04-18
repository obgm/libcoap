/*
 * coap_tcp.h -- TCP functions for libcoap
 *
 * Copyright (C) 2019 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#ifndef COAP_TCP_H_
#define COAP_TCP_H_

#include "coap_io.h"

/**
 * @defgroup tcp TCP Support
 * API functions for interfacing with the system TCP stack.
 * @{
 */

/**
 * Check whether TCP is available.
 *
 * @return @c 1 if support for TCP is enabled, or @c 0 otherwise.
 */
int coap_tcp_is_supported(void);

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

#endif /* COAP_TCP_H_ */
