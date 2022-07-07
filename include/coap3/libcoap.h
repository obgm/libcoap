/*
 * libcoap.h -- platform specific header file for CoAP stack
 *
 * Copyright (C) 2015 Carsten Schoenert <c.schoenert@t-online.de>
 *               2022 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file libcoap.h
 * @brief Platform specific header file for CoAP stack
 */

#ifndef COAP_LIBCOAP_H_
#define COAP_LIBCOAP_H_

#ifndef COAP_STATIC_INLINE
#  if defined(__cplusplus)
#    define COAP_STATIC_INLINE inline
#  else
#    if defined(_MSC_VER)
#      define COAP_STATIC_INLINE static __inline
#    else
#      define COAP_STATIC_INLINE static inline
#    endif
#  endif
#endif
#ifndef COAP_DEPRECATED
#  if defined(_MSC_VER)
#    define COAP_DEPRECATED __declspec(deprecated)
#  else
#    define COAP_DEPRECATED __attribute__ ((deprecated))
#  endif
#endif
#ifndef COAP_UNUSED
#  ifdef __GNUC__
#    define COAP_UNUSED __attribute__((unused))
#  else /* __GNUC__ */
#    define COAP_UNUSED
#  endif /* __GNUC__ */
#endif /* COAP_UNUSED */

/*
 * Add in the necessary header files for the different build types so
 * that the correct ones are pulled in when building the libcoap objects.
 */
#if defined(_WIN32)
#include "coap_include_windows.h"
#elif defined (WITH_LWIP)
#include "coap_include_lwip.h"
#elif defined (WITH_RIOT)
#include "coap_include_riot.h"
#elif defined (WITH_CONTIKI)
#include "coap_include_contiki.h"
#else
#include "coap_include_posix.h"
#endif

void coap_startup(void);

void coap_cleanup(void);

#endif /* COAP_LIBCOAP_H_ */
