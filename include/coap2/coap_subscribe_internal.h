/*
 * coap_subscribe_internal.h -- Structures, Enums & Functions that are not
 * exposed to application programming
 *
 * Copyright (C) 2010-2019 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_subscribe_internal.h
 * @brief COAP subscribe internal information
 */

#ifndef COAP_SUBSCRIBE_INTERNAL_H_
#define COAP_SUBSCRIBE_INTERNAL_H_

/**
 * @defgroup subscribe_internal Subscribe (Internal)
 * Structures, Enums and Functions that are not exposed to applications
 * @{
 */

#ifndef COAP_OBS_MAX_NON
/**
 * Number of notifications that may be sent non-confirmable before a confirmable
 * message is sent to detect if observers are alive. The maximum allowed value
 * here is @c 15.
 */
#define COAP_OBS_MAX_NON   5
#endif /* COAP_OBS_MAX_NON */

#ifndef COAP_OBS_MAX_FAIL
/**
 * Number of confirmable notifications that may fail (i.e. time out without
 * being ACKed) before an observer is removed. The maximum value for
 * COAP_OBS_MAX_FAIL is @c 3.
 */
#define COAP_OBS_MAX_FAIL  3
#endif /* COAP_OBS_MAX_FAIL */

/** Subscriber information */
struct coap_subscription_t {
  struct coap_subscription_t *next; /**< next element in linked list */
  struct coap_session_t *session;   /**< subscriber session */

  unsigned int non_cnt:4;  /**< up to 15 non-confirmable notifies allowed */
  unsigned int fail_cnt:2; /**< up to 3 confirmable notifies can fail */
  unsigned int dirty:1;    /**< set if the notification temporarily could not be
                            *   sent (in that case, the resource's partially
                            *   dirty flag is set too) */
  unsigned int has_block2:1; /**< GET request had Block2 definition */
  uint16_t tid;             /**< transaction id, if any, in regular host byte order */
  coap_block_t block2;     /**< GET request Block2 definition */
  size_t token_length;     /**< actual length of token */
  unsigned char token[8];  /**< token used for subscription */
  struct coap_string_t *query; /**< query string used for subscription, if any */
};

void coap_subscription_init(coap_subscription_t *);

/** @} */

#endif /* COAP_SUBSCRIBE_INTERNAL_H_ */
