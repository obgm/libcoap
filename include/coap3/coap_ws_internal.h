/*
 * coap_ws_internal.h -- WebSockets Transport Layer Support for libcoap
 *
 * Copyright (C) 2023 Olaf Bergmann <bergmann@tzi.org>
 * Copyright (C) 2023 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_ws_internal.h
 * @brief Internal CoAP WebSockets support
 */

#ifndef COAP_WS_INTERNAL_H_
#define COAP_WS_INTERNAL_H_

#include "coap_internal.h"

/**
 * @ingroup internal_api
 * @defgroup ws_internal WebSockets Support
 * Internal API for WebSockets Support (RFC8323)
 * @{
 */


/* Frame size:  Min Header + (Opt) Ext payload length + (Opt) Masking key */
#define COAP_MAX_FS (2 + 8 + 4)

/**
 * WebSockets session state
 */
typedef struct coap_ws_state_t {
  coap_session_type_t state; /**< Client or Server */
  uint8_t up;           /**< WebSockets established */
  uint8_t seen_first;   /**< Seen first request/response HTTP header */
  uint8_t seen_host;    /**< Seen Host: HTTP header (server) */
  uint8_t seen_upg;     /**< Seen Upgrade: HTTP header */
  uint8_t seen_conn;    /**< Seen Connection: HTTP header */
  uint8_t seen_key;     /**< Seen Key: HTTP header */
  uint8_t seen_proto;   /**< Seen Protocol: HTTP header */
  uint8_t seen_ver;     /**< Seen version: HTTP header (server) */
  uint8_t sent_close;   /**< Close has been sent */
  uint8_t recv_close;   /**< Close has been received */
  uint16_t close_reason; /**< Reason for closing */
  int all_hdr_in;       /**< Frame header available */
  int hdr_ofs;          /**< Current offset into rd_header */
  uint8_t rd_header[COAP_MAX_FS]; /**< (Partial) frame */
  uint8_t mask_key[4];  /**< Masking key */
  uint32_t http_ofs;    /**< Current offset into http_hdr */
  uint8_t http_hdr[80]; /**< (Partial) HTTP header */
  size_t data_ofs;      /**< Offset into user provided buffer */
  size_t data_size;     /**< Data size as indicated by WebSocket frame */
  uint8_t key[16];      /**< Random, but agreed key value */
} coap_ws_state_t;

/*
 * WebSockets Frame
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-------+-+-------------+-------------------------------+
 *   |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
 *   |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
 *   |N|V|V|V|       |S|             |   (if payload len==126/127)   |
 *   | |1|2|3|       |K|             |                               |
 *   +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
 *   |     Extended payload length continued, if payload len == 127  |
 *   + - - - - - - - - - - - - - - - +-------------------------------+
 *   |                               |Masking-key, if MASK set to 1  |
 *   +-------------------------------+-------------------------------+
 *   | Masking-key (continued)       |          Payload Data         |
 *   +-------------------------------- - - - - - - - - - - - - - - - +
 *   :                     Payload Data continued ...                :
 *   + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
 *   |                     Payload Data continued ...                |
 *   +---------------------------------------------------------------+
 */

#define WS_B0_FIN_BIT  0x80
#define WS_B0_RSV_MASK 0x70
#define WS_B0_OP_MASK  0x0f

#define WS_B1_MASK_BIT 0x80
#define WS_B1_LEN_MASK 0x7f

typedef enum {
  WS_OP_CONT = 0x0,
  WS_OP_TEXT,
  WS_OP_BINARY,
  WS_OP_CLOSE = 0x8,
  WS_OP_PING,
  WS_OP_PONG
} coap_ws_opcode_t;

/**
 * Function interface for websockets data transmission. This function returns
 * the number of bytes that have been transmitted, or a value less than zero
 * on error. The number of bytes written may be less than datalen because of
 * congestion control.
 *
 * @param session          Session to send data on.
 * @param data             The data to send.
 * @param datalen          The actual length of @p data.
 *
 * @return                 The number of bytes written on success, or a value
 *                         less than zero on error.
 */
ssize_t coap_ws_write(coap_session_t *session,
                      const uint8_t *data, size_t datalen);

/**
 * Function interface for websockets data receiving. This function returns
 * the number of bytes that have been read, or a value less than zero
 * on error. The number of bytes read may be less than datalen because of
 * congestion control.
 *
 * @param session          Session to receive data on.
 * @param data             The data to receive.
 * @param datalen          The maximum length of @p data.
 *
 * @return                 The number of bytes read on success, or a value
 *                         less than zero on error.
 */
ssize_t coap_ws_read(coap_session_t *session, uint8_t *data,
                     size_t datalen);

/**
 * Layer function interface for layer below WebSockets accept/connect being
 * established. This function initiates the WebSockets layer.
 *
 * If this layer is properly established on invocation, then the next layer
 * must get called by calling
 *   session->lfunc[COAP_LAYER_WS].establish(session)
 * (or done at any point when WebSockets is established).
 *
 * @param session Session that the lower layer accept/connect was done on.
 *
 */
void coap_ws_establish(coap_session_t *session);

/**
 * Layer function interface for WebSockets close for a session.
 *
 * @param session  Session to do the WebSockets close on.
 */
void coap_ws_close(coap_session_t *session);

/** @} */

#endif /* COAP_WS_INTERNAL_H */
