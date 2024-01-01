/*
 * coap_internal.h -- Structures, Enums & Functions that are not exposed to
 * application programming
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

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#else /* ! HAVE_INTTYPES_H */
#ifndef PRIx32
#define PRIx32 "x"
#endif /* ! PRIx32 */
#ifndef PRIu32
#define PRIu32 "u"
#endif /* ! PRIu32 */
#ifndef PRIx64
#define PRIx64 "lx"
#endif /* ! PRIx64 */
#ifndef PRIu64
#define PRIu64 "lu"
#endif /* ! PRIu64 */
#endif /* ! HAVE_INTTYPES_H */

#if defined(HAVE_ERRNO_H)
# include <errno.h>
#endif

/* By default without either configured, these need to be set */
#ifndef COAP_SERVER_SUPPORT
#ifndef COAP_CLIENT_SUPPORT
#define COAP_SERVER_SUPPORT 1
#define COAP_CLIENT_SUPPORT 1
#endif /* ! COAP_CLIENT_SUPPORT */
#endif /* ! COAP_SERVER_SUPPORT */

/* By default without either configured, these need to be set */
#ifndef COAP_IPV4_SUPPORT
#ifndef COAP_IPV6_SUPPORT
#define COAP_IPV4_SUPPORT 1
#define COAP_IPV6_SUPPORT 1
#endif /* ! COAP_IPV6_SUPPORT */
#endif /* ! COAP_IPV4_SUPPORT */

#if ! COAP_SERVER_SUPPORT
#if COAP_ASYNC_SUPPORT
/* ASYNC is only there for Server code */
#undef COAP_ASYNC_SUPPORT
#define COAP_ASYNC_SUPPORT 0
#endif /* COAP_ASYNC_SUPPORT */
#endif /* ! COAP_SERVER_SUPPORT */

#include "coap3/coap.h"

/*
 * Include all the header files that are for internal use only.
 */

#if defined(COAP_OSCORE_SUPPORT) || defined(COAP_WS_SUPPORT)
/* Specific OSCORE general .h files */
typedef struct oscore_ctx_t oscore_ctx_t;
#include "oscore/oscore.h"
#include "oscore/oscore_cbor.h"
#include "oscore/oscore_cose.h"
#include "oscore/oscore_context.h"
#include "oscore/oscore_crypto.h"
#endif /* COAP_OSCORE_SUPPORT || COAP_WS_SUPPORT */

/* Specifically defined internal .h files */
#include "coap_asn1_internal.h"
#include "coap_async_internal.h"
#include "coap_block_internal.h"
#include "coap_cache_internal.h"
#if defined(COAP_OSCORE_SUPPORT) || defined(COAP_WS_SUPPORT)
#include "coap_crypto_internal.h"
#endif /* COAP_OSCORE_SUPPORT || COAP_WS_SUPPORT */
#include "coap_debug_internal.h"
#include "coap_dtls_internal.h"
#include "coap_hashkey_internal.h"
#include "coap_io_internal.h"
#include "coap_layers_internal.h"
#include "coap_mutex_internal.h"
#include "coap_net_internal.h"
#include "coap_netif_internal.h"
#if COAP_OSCORE_SUPPORT
#include "coap_oscore_internal.h"
#endif /* COAP_OSCORE_SUPPORT */
#include "coap_pdu_internal.h"
#include "coap_resource_internal.h"
#include "coap_session_internal.h"
#include "coap_sha1_internal.h"
#include "coap_subscribe_internal.h"
#include "coap_tcp_internal.h"
#include "coap_threadsafe_internal.h"
#include "coap_uri_internal.h"
#include "coap_utlist_internal.h"
#include "coap_uthash_internal.h"
#include "coap_ws_internal.h"

#endif /* COAP_INTERNAL_H_ */
