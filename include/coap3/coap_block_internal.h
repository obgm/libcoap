/*
 * coap_block_internal.h -- Structures, Enums & Functions that are not
 * exposed to application programming
 *
 * Copyright (C) 2010-2024 Olaf Bergmann <bergmann@tzi.org>
 * Copyright (C) 2021-2024 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_block_internal.h
 * @brief CoAP block internal information
 */

#ifndef COAP_BLOCK_INTERNAL_H_
#define COAP_BLOCK_INTERNAL_H_

#include "coap_internal.h"
#include "coap_pdu_internal.h"
#include "coap_resource.h"

/**
 * @ingroup internal_api
 * @defgroup block_internal Block Transfer
 * Internal API for Block Transfer (RC7959)
 * @{
 */

#if COAP_Q_BLOCK_SUPPORT
/* Internal use only and are dropped when setting block_mode */
#define COAP_BLOCK_HAS_Q_BLOCK   0x4000 /* Set when Q_BLOCK supported */
#define COAP_BLOCK_PROBE_Q_BLOCK 0x8000 /* Set when Q_BLOCK probing */

#define set_block_mode_probe_q(block_mode) \
  do { \
    block_mode |= COAP_BLOCK_PROBE_Q_BLOCK; \
    block_mode &= ~(COAP_BLOCK_TRY_Q_BLOCK | COAP_BLOCK_HAS_Q_BLOCK); \
  } while (0)

#define set_block_mode_has_q(block_mode) \
  do { \
    block_mode |= COAP_BLOCK_HAS_Q_BLOCK; \
    block_mode &= ~(COAP_BLOCK_TRY_Q_BLOCK | COAP_BLOCK_PROBE_Q_BLOCK); \
  } while (0)

#define set_block_mode_drop_q(block_mode) \
  do { \
    block_mode &= ~(COAP_BLOCK_TRY_Q_BLOCK |\
                    COAP_BLOCK_PROBE_Q_BLOCK |\
                    COAP_BLOCK_HAS_Q_BLOCK | \
                    COAP_BLOCK_USE_M_Q_BLOCK); \
  } while (0)

#define COAP_SINGLE_BLOCK_OR_Q (COAP_BLOCK_SINGLE_BODY|COAP_BLOCK_HAS_Q_BLOCK)
#else /* ! COAP_Q_BLOCK_SUPPORT */
#define COAP_SINGLE_BLOCK_OR_Q (COAP_BLOCK_SINGLE_BODY)
#endif /* ! COAP_Q_BLOCK_SUPPORT */

typedef enum {
  COAP_RECURSE_OK,
  COAP_RECURSE_NO
} coap_recurse_t;

struct coap_lg_range {
  uint32_t begin;
  uint32_t end;
};

#define COAP_RBLOCK_CNT 4
/**
 * Structure to keep track of received blocks
 */
typedef struct coap_rblock_t {
  uint32_t used;
  uint32_t retry;
#if COAP_Q_BLOCK_SUPPORT
  uint32_t processing_payload_set;
  uint32_t latest_payload_set;
#endif /* COAP_Q_BLOCK_SUPPORT */
  struct coap_lg_range range[COAP_RBLOCK_CNT];
  coap_tick_t last_seen;
} coap_rblock_t;

/**
 * Structure to keep track of block1 specific information
 * (Requests)
 */
typedef struct coap_l_block1_t {
  coap_binary_t *app_token; /**< original PDU token */
  uint64_t state_token;  /**< state token */
  size_t bert_size;      /**< size of last BERT block */
  uint32_t count;        /**< the number of packets sent for payload */
} coap_l_block1_t;

/**
 * Structure to keep track of block2 specific information
 * (Responses)
 */
typedef struct coap_l_block2_t {
  coap_resource_t *resource; /**< associated resource */
  coap_string_t *query;  /**< Associated query for the resource */
  uint64_t etag;         /**< ETag value */
  coap_pdu_code_t request_method; /**< Method used to request this data */
  uint8_t rtag_set;      /**< Set if RTag is in receive PDU */
  uint8_t rtag_length;   /**< RTag length */
  uint8_t rtag[8];       /**< RTag for block checking */
  coap_time_t maxage_expire; /**< When this entry expires */
} coap_l_block2_t;

/**
 * Structure to hold large body (many blocks) transmission information
 */
struct coap_lg_xmit_t {
  struct coap_lg_xmit_t *next;
  uint8_t blk_size;      /**< large block transmission size */
  uint16_t option;       /**< large block transmisson CoAP option */
  int last_block;        /**< last acknowledged block number Block1
                              last transmitted Q-Block2 */
  const uint8_t *data;   /**< large data ptr */
  size_t length;         /**< large data length */
  size_t offset;         /**< large data next offset to transmit */
  union {
    coap_l_block1_t b1;
    coap_l_block2_t b2;
  } b;
  coap_pdu_t pdu;        /**< skeletal PDU */
  coap_tick_t last_payload; /**< Last time MAX_PAYLOAD was sent or 0 */
  coap_tick_t last_sent; /**< Last time any data sent */
  coap_tick_t last_all_sent; /**< Last time all data sent or 0 */
  coap_tick_t last_obs; /**< Last time used (Observe tracking) or 0 */
#if COAP_Q_BLOCK_SUPPORT
  coap_tick_t non_timeout_random_ticks; /** Used for Q-Block */
#endif /* COAP_Q_BLOCK_SUPPORT */
  coap_release_large_data_t release_func; /**< large data de-alloc function */
  void *app_ptr;         /**< applicaton provided ptr for de-alloc function */
};

#if COAP_CLIENT_SUPPORT
/**
 * Structure to hold large body (many blocks) client receive information
 */
struct coap_lg_crcv_t {
  struct coap_lg_crcv_t *next;
  uint8_t observe[3];    /**< Observe data (if observe_set) (only 24 bits) */
  uint8_t observe_length;/**< Length of observe data */
  uint8_t observe_set;   /**< Set if this is an observe receive PDU */
  uint8_t szx;           /**< size of individual blocks */
  uint8_t etag_set;      /**< Set if ETag is in receive PDU */
  uint8_t etag_length;   /**< ETag length */
  uint8_t etag[8];       /**< ETag for block checking */
  uint16_t content_format; /**< Content format for the set of blocks */
  uint8_t last_type;     /**< Last request type (CON/NON) */
  uint8_t initial;       /**< If set, has not been used yet */
  uint16_t block_option; /**< Block option in use */
  uint16_t retry_counter; /**< Retry counter (part of state token) */
  size_t total_len;      /**< Length as indicated by SIZE2 option */
  coap_binary_t *body_data; /**< Used for re-assembling entire body */
  coap_binary_t *app_token; /**< app requesting PDU token */
  coap_bin_const_t **obs_token; /**< Tokens used in setting up Observe
                                  (to handle large FETCH) */
  size_t obs_token_cnt; /**< number of tokens used to set up Observe */
  uint64_t state_token; /**< state token */
  coap_pdu_t pdu;        /**< skeletal PDU */
  coap_rblock_t rec_blocks; /** < list of received blocks */
  coap_tick_t last_used; /**< Last time all data sent or 0 */
};
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT
/**
 * Structure to hold large body (many blocks) server receive information
 */
struct coap_lg_srcv_t {
  struct coap_lg_srcv_t *next;
  uint8_t observe[3];    /**< Observe data (if set) (only 24 bits) */
  uint8_t observe_length;/**< Length of observe data */
  uint8_t observe_set;   /**< Set if this is an observe receive PDU */
  uint8_t rtag_set;      /**< Set if RTag is in receive PDU */
  uint8_t rtag_length;   /**< RTag length */
  uint8_t rtag[8];       /**< RTag for block checking */
  uint16_t content_format; /**< Content format for the set of blocks */
  uint8_t last_type;     /**< Last request type (CON/NON) */
  uint8_t szx;           /**< size of individual blocks */
  size_t total_len;      /**< Length as indicated by SIZE1 option */
  coap_binary_t *body_data; /**< Used for re-assembling entire body */
  size_t amount_so_far;  /**< Amount of data seen so far */
  coap_resource_t *resource; /**< associated resource */
  coap_str_const_t *uri_path; /** set to uri_path if unknown resource */
  coap_rblock_t rec_blocks; /** < list of received blocks */
#if COAP_Q_BLOCK_SUPPORT
  coap_bin_const_t *last_token; /**< last used token */
#endif /* COAP_Q_BLOCK_SUPPORT */
  coap_mid_t last_mid;   /**< Last received mid for this set of packets */
  coap_tick_t last_used; /**< Last time data sent or 0 */
  uint16_t block_option; /**< Block option in use */
};
#endif /* COAP_SERVER_SUPPORT */

#if COAP_Q_BLOCK_SUPPORT
typedef enum {
  COAP_SEND_SKIP_PDU,
  COAP_SEND_INC_PDU
} coap_send_pdu_t;
#endif /* COAP_Q_BLOCK_SUPPORT */

#if COAP_CLIENT_SUPPORT
coap_lg_crcv_t *coap_block_new_lg_crcv(coap_session_t *session,
                                       coap_pdu_t *pdu,
                                       coap_lg_xmit_t *lg_xmit);

void coap_block_delete_lg_crcv(coap_session_t *session,
                               coap_lg_crcv_t *lg_crcv);

int coap_block_check_lg_crcv_timeouts(coap_session_t *session,
                                      coap_tick_t now,
                                      coap_tick_t *tim_rem);

#if COAP_Q_BLOCK_SUPPORT
coap_mid_t coap_send_q_block1(coap_session_t *session,
                              coap_block_b_t block,
                              coap_pdu_t *request,
                              coap_send_pdu_t send_request);

coap_tick_t coap_block_check_q_block1_xmit(coap_session_t *session,
                                           coap_tick_t now);

coap_mid_t coap_block_test_q_block(coap_session_t *session, coap_pdu_t *actual);
#endif /* COAP_Q_BLOCK_SUPPORT */

#endif /* COAP_CLIENT_SUPPORT */

#if COAP_Q_BLOCK_SUPPORT
coap_mid_t coap_send_q_blocks(coap_session_t *session,
                              coap_lg_xmit_t *lg_xmit,
                              coap_block_b_t block,
                              coap_pdu_t *pdu,
                              coap_send_pdu_t send_pdu);
#endif /* COAP_Q_BLOCK_SUPPORT */

#if COAP_SERVER_SUPPORT
void coap_block_delete_lg_srcv(coap_session_t *session,
                               coap_lg_srcv_t *lg_srcv);

int coap_block_check_lg_srcv_timeouts(coap_session_t *session,
                                      coap_tick_t now,
                                      coap_tick_t *tim_rem);

#if COAP_Q_BLOCK_SUPPORT
coap_tick_t coap_block_check_q_block2_xmit(coap_session_t *session,
                                           coap_tick_t now);

coap_mid_t coap_send_q_block2(coap_session_t *session,
                              coap_resource_t *resource,
                              const coap_string_t *query,
                              coap_pdu_code_t request_method,
                              coap_block_b_t block,
                              coap_pdu_t *response,
                              coap_send_pdu_t send_response);
#endif /* COAP_Q_BLOCK_SUPPORT */

int coap_handle_request_send_block(coap_session_t *session,
                                   coap_pdu_t *pdu,
                                   coap_pdu_t *response,
                                   coap_resource_t *resource,
                                   coap_string_t *query);

int coap_handle_request_put_block(coap_context_t *context,
                                  coap_session_t *session,
                                  coap_pdu_t *pdu,
                                  coap_pdu_t *response,
                                  coap_resource_t *resource,
                                  coap_string_t *uri_path,
                                  coap_opt_t *observe,
                                  int *added_block,
                                  coap_lg_srcv_t **free_lg_srcv);

coap_lg_xmit_t *coap_find_lg_xmit_response(const coap_session_t *session,
                                           const coap_pdu_t *request,
                                           const coap_resource_t *resource,
                                           const coap_string_t *query);
#endif /* COAP_SERVER_SUPPORT */

#if COAP_CLIENT_SUPPORT
int coap_handle_response_send_block(coap_session_t *session, coap_pdu_t *sent,
                                    coap_pdu_t *rcvd);

int coap_handle_response_get_block(coap_context_t *context,
                                   coap_session_t *session,
                                   coap_pdu_t *sent,
                                   coap_pdu_t *rcvd,
                                   coap_recurse_t recursive);
coap_mid_t coap_retransmit_oscore_pdu(coap_session_t *session,
                                      coap_pdu_t *pdu,
                                      coap_opt_t *echo);
#endif /* COAP_CLIENT_SUPPORT */

void coap_block_delete_lg_xmit(coap_session_t *session,
                               coap_lg_xmit_t *lg_xmit);

int coap_block_check_lg_xmit_timeouts(coap_session_t *session,
                                      coap_tick_t now,
                                      coap_tick_t *tim_rem);

#if COAP_Q_BLOCK_SUPPORT
int coap_block_drop_resp_q_block_xmit(coap_session_t *session,
                                      coap_lg_xmit_t *lg_xmit);

int coap_block_drop_resp_q_block2_crcv(coap_session_t *session,
                                       coap_lg_crcv_t *lg_crcv,
                                       coap_pdu_t *sent);
#endif /* COAP_Q_BLOCK_SUPPORT */

/**
 * The function checks that the code in a newly formed lg_xmit created by
 * coap_add_data_large_response() is updated.
 *
 * @param session  The session.
 * @param request  The request PDU to to check.
 * @param response The response PDU to to update with response->code.
 * @param resource The requested resource.
 * @param query    The requested query.
 */
void coap_check_code_lg_xmit(const coap_session_t *session,
                             const coap_pdu_t *request,
                             coap_pdu_t *response,
                             const coap_resource_t *resource,
                             const coap_string_t *query);

#if COAP_CLIENT_SUPPORT
/**
 * The function checks if the token needs to be updated before PDU is
 * presented to the application (only relevant to clients).
 *
 * @param session The session.
 * @param pdu     The PDU to to check for updating.
 */
void coap_check_update_token(coap_session_t *session, coap_pdu_t *pdu);
#else /* ! COAP_CLIENT_SUPPORT */
#define coap_check_update_token(a,b)
#endif /* ! COAP_CLIENT_SUPPORT */

/** @} */

#endif /* COAP_BLOCK_INTERNAL_H_ */
