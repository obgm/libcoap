/*
 * coap_mutex.h -- mutex utilities
 *
 * Copyright (C) 2019-2023 Jon Shallow <supjps-libcoap@jpshallow.com>
 *               2019      Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_mutex_internal.h
 * @brief CoAP mutex mechanism wrapper
 */

#ifndef COAP_MUTEX_INTERNAL_H_
#define COAP_MUTEX_INTERNAL_H_

/*
 * Mutexes are currently only used if there is a constrained stack,
 * and large static variables (instead of the large variable being on
 * the stack) need to be protected.
 */
#if COAP_CONSTRAINED_STACK

#if defined(HAVE_PTHREAD_H) && defined(HAVE_PTHREAD_MUTEX_LOCK)
#include <pthread.h>

typedef pthread_mutex_t coap_mutex_t;

#define coap_mutex_init(a)    pthread_mutex_init(a, NULL)
#define coap_mutex_destroy(a) pthread_mutex_destroy(a)
#define coap_mutex_lock(a)    pthread_mutex_lock(a)
#define coap_mutex_trylock(a) pthread_mutex_trylock(a)
#define coap_mutex_unlock(a)  pthread_mutex_unlock(a)

#elif defined(RIOT_VERSION)
/* use RIOT's mutex API */
#include <mutex.h>

typedef mutex_t coap_mutex_t;

#define coap_mutex_init(a)    mutex_init(a)
#define coap_mutex_destroy(a)
#define coap_mutex_lock(a)    mutex_lock(a)
#define coap_mutex_trylock(a) mutex_trylock(a)
#define coap_mutex_unlock(a)  mutex_unlock(a)

#elif defined(WITH_LWIP)
/* Use LwIP's mutex API */

#if NO_SYS
/* Single threaded, no-op'd in lwip/sys.h */
typedef int coap_mutex_t;

#define coap_mutex_init(a)    *(a) = 0
#define coap_mutex_destroy(a) *(a) = 0
#define coap_mutex_lock(a)    *(a) = 1
#define coap_mutex_trylock(a) *(a) = 1
#define coap_mutex_unlock(a)  *(a) = 0

#else /* !NO SYS */
#include <lwip/sys.h>
typedef sys_mutex_t coap_mutex_t;

#define coap_mutex_init(a)    sys_mutex_new(a)
#define coap_mutex_destroy(a) sys_mutex_set_invalid(a)
#define coap_mutex_lock(a)    sys_mutex_lock(a)
#define coap_mutex_trylock(a) sys_mutex_lock(a)
#define coap_mutex_unlock(a)  sys_mutex_unlock(a)
#endif /* !NO SYS */

#elif defined(WITH_CONTIKI)
/* Contiki does not have a mutex API, used as single thread */
typedef int coap_mutex_t;

#define coap_mutex_init(a)    *(a) = 0
#define coap_mutex_destroy(a) *(a) = 0
#define coap_mutex_lock(a)    *(a) = 1
#define coap_mutex_trylock(a) *(a) = 1
#define coap_mutex_unlock(a)  *(a) = 0

#elif defined(__ZEPHYR__)
#include <zephyr/sys/mutex.h>

typedef struct sys_mutex coap_mutex_t;

#define coap_mutex_init(a)    sys_mutex_init(a)
#define coap_mutex_destroy(a)
#define coap_mutex_lock(a)    sys_mutex_lock(a, K_FOREVER)
#define coap_mutex_trylock(a) sys_mutex_lock(a, K_NO_WAIT)
#define coap_mutex_unlock(a)  sys_mutex_unlock(a)

#else /* !__ZEPYR__ && !WITH_CONTIKI && !WITH_LWIP && !RIOT_VERSION && !HAVE_PTHREAD_H && !HAVE_PTHREAD_MUTEX_LOCK */
/* define stub mutex functions */
#warning "stub mutex functions"
typedef int coap_mutex_t;

#define coap_mutex_init(a)    *(a) = 0
#define coap_mutex_destroy(a) *(a) = 0
#define coap_mutex_lock(a)    *(a) = 1
#define coap_mutex_trylock(a) *(a) = 1
#define coap_mutex_unlock(a)  *(a) = 0

#endif /* !WITH_CONTIKI && !WITH_LWIP && !RIOT_VERSION && !HAVE_PTHREAD_H && !HAVE_PTHREAD_MUTEX_LOCK */

extern coap_mutex_t m_show_pdu;
extern coap_mutex_t m_log_impl;
extern coap_mutex_t m_dtls_recv;
extern coap_mutex_t m_read_session;
extern coap_mutex_t m_read_endpoint;
extern coap_mutex_t m_persist_add;

#endif /* COAP_CONSTRAINED_STACK */

#endif /* COAP_MUTEX_INTERNAL_H_ */
