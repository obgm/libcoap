/*
 * coap_uri_internal.h -- URI functions for libcoap
 *
 * Copyright (C) 2019--2023 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_uri_internal.h
 * @brief CoAP URI internal information
 */

#ifndef COAP_URI_INTERNAL_H_
#define COAP_URI_INTERNAL_H_

#include "coap_internal.h"

/**
 * @ingroup internal_api
 * @defgroup uri URI Support
 * Internal API for handling CoAP URIs
 * @{
 */

typedef struct {
  const char *name;         /**< scheme name */
  uint16_t port;            /**< default scheme port */
  uint16_t proxy_only;      /**< set if proxy support only */
  coap_uri_scheme_t scheme; /**< scheme */
} coap_uri_info_t;

extern coap_uri_info_t coap_uri_scheme[COAP_URI_SCHEME_LAST];

/** @} */

#endif /* COAP_URI_INTERNAL_H_ */
