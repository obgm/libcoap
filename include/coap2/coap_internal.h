/*
 * coap_internal.h -- Structures, Enums & Functions that are not exposed to
 * application programming
 *
 * Copyright (C) 2019 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/*
 * All libcoap library files should include this file which then pulls in all
 * of the other appropriate header files.
 *
 * Note: This file should never be included in application code (with the
 * possible exception of internal test suites).
 */

/**
 * @file coap_internal.h
 * @brief Pulls together all the internal only header files
 */

#ifndef COAP_INTERNAL_H_
#define COAP_INTERNAL_H_

#include "coap_config.h"

/*
 * Correctly set up assert() based on NDEBUG for libcoap
 */
#if defined(HAVE_ASSERT_H) && !defined(assert)
# include <assert.h>
#endif

#include "coap.h"

/*
 * Include all the header files that are for internal use only.
 */

/* Not defined in coap.h - internal usage .h files */
#include "utlist.h"
#include "uthash.h"
#include "coap_hashkey.h"
#include "coap_mutex.h"

/* Specifically defined internal .h files */
#include "coap_session_internal.h"
#include "coap_subscribe_internal.h"

#endif /* COAP_INTERNAL_H_ */
