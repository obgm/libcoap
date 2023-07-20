/*
 * coap_layers_internal.h -- Internal layer functions for libcoap
 *
 * Copyright (C) 2023 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_layers_internal.h
 * @brief Internal layer I/O functions
 */

#ifndef COAP_LAYERS_INTERNAL_H_
#define COAP_LAYERS_INTERNAL_H_

#include "coap_internal.h"

typedef enum {
  COAP_LAYER_SESSION,
  COAP_LAYER_WS,
  COAP_LAYER_TLS,
  COAP_LAYER_LAST
} coap_layer_t;

/**
 * Function read interface for layer data receiving.
 *
 * If a called lower layer returned value is 0 or less, this must get passed
 * back to the caller.
 *
 * If the layer function consumes all the data (i.e. to handle the protocol
 * layer requirements), then the function must return 0 to indicate no data.
 *
 * Otherwise data must get updated (limited by datalen) and the number of bytes
 * available returned.
 *
 * Note: If the number of returned bytes is less that read in, then
 * COAP_SOCKET_CAN_READ must be dropped from session->sock.flags.
 *
 * @param session  Session to receive data on.
 * @param data     The data to receive.
 * @param datalen  The maximum length of @p data.
 *
 * @return         >=0 Number of bytes read.
 *                 -1  Error error in errno).
 *                 -2  Recieved ICMP unreachable.
 */
typedef ssize_t (*coap_layer_read_t)(coap_session_t *session,
                                     uint8_t *data, size_t datalen);

/**
 * Function write interface for layer data sending.
 *
 * If a called lower layer returned value is 0 or less, this must get passed
 * back to the caller.
 *
 * If the layer function cannot transmit any data (congestion control etc.),
 * then the function must return 0 to indicate no data sent.
 *
 * It is possible that not all the data is sent (congestion control etc.),
 * and bytes written is less that datalen.
 *
 * Note: If the number of returned bytes is less that to be written,
 * COAP_SOCKET_WANT_WRITE must be added to session->sock.flags.
 *
 * @param session  Session to receive data on.
 * @param data     The data to write out.
 * @param datalen  The maximum length of @p data.
 *
 * @return         >=0 Number of bytes written.
 *                 -1  Error error in errno).
 */
typedef ssize_t (*coap_layer_write_t)(coap_session_t *session,
                                      const uint8_t *data, size_t datalen);
/**
 * Function establish interface for layer establish handling.
 *
 * If this layer is properly established on invocation, then the next layer
 * must get called by calling
 *   session->lfunc[_this_layer_].l_establish(session)
 * (or done at any point when layer is established).
 * If the establishment of a layer fails, then
 *   coap_session_disconnected(session, COAP_NACK_xxx_LAYER_FAILED) must be
 *   called.
 *
 * @param session Session being established
 */
typedef void (*coap_layer_establish_t)(coap_session_t *session);

/**
 * Function close interface for layer closing.
 *
 * When this layer is properly closed, then the next layer
 * must get called by calling
 *   session->lfunc[_this_layer_].l_close(session)
 * (or done at any point when layer is closed).
 *
 * @param session Session being closed.
 */
typedef void (*coap_layer_close_t)(coap_session_t *session);

typedef struct {
  coap_layer_read_t l_read;   /* Get data from next layer (TCP) */
  coap_layer_write_t l_write; /* Output data to next layer */
  coap_layer_establish_t l_establish; /* Layer establish */
  coap_layer_close_t l_close; /* Connection close */
} coap_layer_func_t;

extern coap_layer_func_t coap_layers_coap[COAP_PROTO_LAST][COAP_LAYER_LAST];

#endif /* COAP_LAYERS_INTERNAL_H_ */
