/*
 * coap_mutex.h -- mutex utilities
 *
 * Copyright (C) 2019-2024 Jon Shallow <supjps-libcoap@jpshallow.com>
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
 * Mutexes are used for
 * 1) If there is a constrained stack, and large static variables (instead
 *    of the large variable being on the stack) need to be protected.
 * 2) libcoap if built with thread safe support.
 */
#if defined(HAVE_PTHREAD_H) && defined(HAVE_PTHREAD_MUTEX_LOCK)
#include <pthread.h>

typedef pthread_mutex_t coap_mutex_t;

#define coap_mutex_init(a)    pthread_mutex_init(a, NULL)
#define coap_mutex_destroy(a) pthread_mutex_destroy(a)
#define coap_mutex_lock(a)    pthread_mutex_lock(a)
#define coap_mutex_trylock(a) pthread_mutex_trylock(a)
#define coap_mutex_unlock(a)  pthread_mutex_unlock(a)
#if defined(ESPIDF_VERSION)
#define coap_thread_pid_t     TaskHandle_t
#define coap_thread_pid       xTaskGetCurrentTaskHandle()
#else /* !ESPIDF_VERSION */
#define coap_thread_pid_t     pthread_t
#define coap_thread_pid       pthread_self()
#endif /* !ESPIDF_VERSION */

#elif defined(RIOT_VERSION)
/* use RIOT's mutex API */
#include <mutex.h>

typedef mutex_t coap_mutex_t;

#define coap_mutex_init(a)    mutex_init(a)
#define coap_mutex_destroy(a)
#define coap_mutex_lock(a)    mutex_lock(a)
#define coap_mutex_trylock(a) mutex_trylock(a)
#define coap_mutex_unlock(a)  mutex_unlock(a)
#define coap_thread_pid_t     kernel_pid_t
#define coap_thread_pid       thread_getpid()

#elif defined(WITH_LWIP)
/* Use LwIP's mutex API */

#if NO_SYS
#if COAP_THREAD_SAFE
#error Multi-threading not supported (no mutex support)
#endif /* ! COAP_THREAD_SAFE */
/* Single threaded, no-op'd in lwip/sys.h */
typedef int coap_mutex_t;

#define coap_mutex_init(a)    *(a) = 0
#define coap_mutex_destroy(a) *(a) = 0
#define coap_mutex_lock(a)    *(a) = 1
#define coap_mutex_trylock(a) *(a) = 1
#define coap_mutex_unlock(a)  *(a) = 0
#define coap_thread_pid_t     int
#define coap_thread_pid       1

#else /* !NO_SYS */
#include <lwip/sys.h>
#ifdef LWIP_UNIX_LINUX
#include <pthread.h>
typedef pthread_mutex_t coap_mutex_t;

#define coap_mutex_init(a)    pthread_mutex_init(a, NULL)
#define coap_mutex_destroy(a) pthread_mutex_destroy(a)
#define coap_mutex_lock(a)    pthread_mutex_lock(a)
#define coap_mutex_trylock(a) pthread_mutex_trylock(a)
#define coap_mutex_unlock(a)  pthread_mutex_unlock(a)
#define coap_thread_pid_t     pthread_t
#define coap_thread_pid       pthread_self()
#else /* ! LWIP_UNIX_LINUX */
typedef sys_mutex_t coap_mutex_t;

#define coap_mutex_init(a)    sys_mutex_new(a)
#define coap_mutex_destroy(a) sys_mutex_set_invalid(a)
#define coap_mutex_lock(a)    sys_mutex_lock(a)
#define coap_mutex_unlock(a)  sys_mutex_unlock(a)
#define coap_thread_pid_t     sys_thread_t
#define coap_thread_pid       (coap_thread_pid_t)1

#if COAP_THREAD_RECURSIVE_CHECK
#error COAP_THREAD_RECURSIVE_CHECK not supported (no coap_mutex_trylock())
#endif /* COAP_THREAD_RECURSIVE_CHECK */
#endif /* !LWIP_UNIX_LINUX */
#endif /* !NO_SYS */

#elif defined(WITH_CONTIKI)
#if COAP_THREAD_SAFE
#error Multi-threading not supported (no mutex support)
#endif /* ! COAP_THREAD_SAFE */
/* Contiki does not have a mutex API, used as single thread */
typedef int coap_mutex_t;

#define coap_mutex_init(a)    *(a) = 0
#define coap_mutex_destroy(a) *(a) = 0
#define coap_mutex_lock(a)    *(a) = 1
#define coap_mutex_trylock(a) *(a) = 1
#define coap_mutex_unlock(a)  *(a) = 0
#define coap_thread_pid_t     int
#define coap_thread_pid       1

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
#if COAP_THREAD_SAFE
#error Multi-threading not supported (no mutex support)
#else /* ! COAP_THREAD_SAFE */
#if COAP_CONSTRAINED_STACK
#warning "stub mutex functions"
#endif /* COAP_CONSTRAINED_STACK */
#endif /* ! COAP_THREAD_SAFE */
typedef int coap_mutex_t;

#define coap_mutex_init(a)    *(a) = 0
#define coap_mutex_destroy(a) *(a) = 0
#define coap_mutex_lock(a)    *(a) = 1
#define coap_mutex_trylock(a) *(a) = 1
#define coap_mutex_unlock(a)  *(a) = 0
#define coap_thread_pid_t     int
#define coap_thread_pid       1

#endif /* !WITH_CONTIKI && !WITH_LWIP && !RIOT_VERSION && !HAVE_PTHREAD_H && !HAVE_PTHREAD_MUTEX_LOCK */

#endif /* COAP_MUTEX_INTERNAL_H_ */
