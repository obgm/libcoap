/*
 * coap_libcoap_build.h -- libcoap library build specifics
 *
 * Copyright (C) 2019-2024 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/*
 * All libcoap library files should include this file which then pulls in all
 * of the other appropriate header files.
 *
 * Here can be added in specific checks to make sure that the libcoap library
 * is built as expected.
 *
 * Note: This file should never be included in application code.
 */

/**
 * @file coap_libcoap_build.h
 * @brief Library specific build wrapper for coap_internal.h
 */

#ifndef COAP_LIBCOAP_BUILD_H_
#define COAP_LIBCOAP_BUILD_H_

#include "coap_config.h"

#include "coap_internal.h"

#endif /* COAP_LIBCOAP_BUILD_H_ */
