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
#define coap_thread_pid_t     pthread_t
#define coap_thread_pid       pthread_self()

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
#define coap_thread_pid       thread_getpid(void)

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

#if COAP_CONSTRAINED_STACK

extern coap_mutex_t m_show_pdu;
extern coap_mutex_t m_log_impl;
extern coap_mutex_t m_dtls_recv;
extern coap_mutex_t m_read_session;
extern coap_mutex_t m_read_endpoint;
extern coap_mutex_t m_persist_add;

#endif /* COAP_CONSTRAINED_STACK */

/*
 * Support thread safe access into libcoap
 *
 * Locking at different component levels (i.e context and session) is
 * problematic in that coap_process_io() needs to lock the context as
 * it scans for all the sessions and then could lock the session being
 * processed as well - but context needs to remain locked as a list is
 * being scanned.
 *
 * Then if the session process needs to update context ( e.g. delayqueue),
 * context needs to be locked. So, if coap_send() is done on a session,
 * it has to be locked, but a retransmission of a PDU by coap_process_io()
 * has the context already locked.
 *
 * So the initial support for thread safe is done at the context level.
 *
 * Any public API call needs to potentially lock context, as there may be
 * multiple contexts. If a public API needs thread safe protection, a
 * locking wrapper for coap_X() is added to src/coap_threadsafe.c which then
 * calls the coap_X_locked() function of coap_X() having locked context.
 *
 * Then an entry is added to include/coap3/coap_threadsafe_internal.h to map
 * all the coap_X() definitions and calls within the libcoap code to
 * coap_X_locked() (with the exception of src/coap_threadsafe.c).
 *
 * A second entry is added to include/coap3/coap_threadsafe_internal.h which
 * defines the coap_X_locked() function header.
 *
 * Any call-back into app space must be done by using the coap_lock_callback()
 * (or coap_lock_callback_ret()) wrapper.
 *
 * Note:
 * libcoap may call a handler, which may in turn call into libcoap, which may
 * then call a handler.  context will remain locked thoughout this process.
 *
 * Any wait on select() or equivalent when a thread is waiting on an event
 * must be preceded by unlock context, and then context re-locked after
 * return;
 *
 * To check for recursive deadlocks, COAP_THREAD_RECURSIVE_CHECK needs to be
 * defined.
 *
 * If thread safe is not enabled, then coap_threadsafe.c and
 * coap_threadsafe_internal.h do nothing.
 */
#if COAP_THREAD_SAFE
# if COAP_THREAD_RECURSIVE_CHECK

typedef void (*coap_free_func_t)(void *stucture);

/*
 * Locking, with deadlock detection
 */
typedef struct coap_lock_t {
  coap_mutex_t mutex;
  coap_thread_pid_t pid;
  coap_thread_pid_t freeing_pid;
  const char *lock_file;
  uint32_t lock_line;
  const char *unlock_file;
  uint32_t unlock_line;
  const char *callback_file;
  uint32_t callback_line;
  uint32_t being_freed;
  uint32_t in_callback;
  volatile uint32_t lock_count;
} coap_lock_t;

void coap_lock_unlock_func(coap_lock_t *lock, const char *file, int line);
int coap_lock_lock_func(coap_lock_t *lock, const char *file, int line);

#define coap_lock_lock(s,failed) do { \
    if (!coap_lock_lock_func(&(s)->lock, __FILE__, __LINE__)) { \
      failed; \
    } \
  } while (0)

#define coap_lock_unlock(s) do { \
    coap_lock_unlock_func(&(s)->lock,  __FILE__, __LINE__); \
  } while (0)

#define coap_lock_init(s) do { \
    memset(&((s)->lock), 0, sizeof((s)->lock)); \
    coap_mutex_init(&(s)->lock.mutex); \
  } while (0)

#define coap_lock_being_freed(s,failed) do { \
    coap_lock_lock(s,failed); \
    (s)->lock.being_freed = 1; \
    (s)->lock.freeing_pid = coap_thread_pid; \
    coap_lock_unlock(s); \
  } while (0)

#define coap_lock_check_locked(s) do { \
    assert ((s)->lock.being_freed ? coap_thread_pid == (s)->lock.freeing_pid: coap_thread_pid == (s)->lock.pid); \
  } while (0)

#define coap_lock_callback(s,func) do { \
    (s)->lock.in_callback++; \
    (s)->lock.callback_file = __FILE__; \
    (s)->lock.callback_line = __LINE__; \
    func; \
    (s)->lock.in_callback--; \
  } while (0)

#define coap_lock_callback_ret(r,s,func) do { \
    (s)->lock.in_callback++; \
    (s)->lock.callback_file = __FILE__; \
    (s)->lock.callback_line = __LINE__; \
    r = func; \
    (s)->lock.in_callback--; \
  } while (0)

#define coap_lock_invert(s,func,f) do { \
    if (!(s)->lock.being_freed) { \
      coap_lock_unlock(s); \
      func; \
      coap_lock_lock(s,f); \
    } else { \
      func; \
    } \
  } while (0)

# else /* ! COAP_THREAD_RECURSIVE_CHECK */

/*
 * Locking, but no deadlock detection
 */
typedef struct coap_lock_t {
  coap_mutex_t mutex;
  uint32_t being_freed;
  uint32_t in_callback;
  volatile uint32_t lock_count;
} coap_lock_t;

void coap_lock_unlock_func(coap_lock_t *lock);
int coap_lock_lock_func(coap_lock_t *lock);

#define coap_lock_lock(s,failed) do { \
    if (!coap_lock_lock_func(&(s)->lock)) { \
      failed; \
    } \
  } while (0)

#define coap_lock_unlock(s) do { \
    coap_lock_unlock_func(&(s)->lock); \
  } while (0)

#define coap_lock_init(s) do { \
    memset(&((s)->lock), 0, sizeof((s)->lock)); \
    coap_mutex_init(&(s)->lock.mutex); \
  } while (0)

#define coap_lock_being_freed(s,failed) do { \
    coap_lock_lock(s,failed); \
    (s)->lock.being_freed = 1; \
    coap_lock_unlock(s); \
  } while (0)

#define coap_lock_callback(s,func) do { \
    (s)->lock.in_callback++; \
    func; \
    (s)->lock.in_callback--; \
  } while (0)

#define coap_lock_callback_ret(r,s,func) do { \
    (s)->lock.in_callback++; \
    r = func; \
    (s)->lock.in_callback--; \
  } while (0)

#define coap_lock_invert(s,func,f) do { \
    if (!(s)->lock.being_freed) { \
      coap_lock_unlock(s); \
      func; \
      coap_lock_lock(s,f); \
    } else { \
      func; \
    } \
  } while (0)

#define coap_lock_check_locked(s) {}

# endif /* ! COAP_THREAD_RECURSIVE_CHECK */

#else /* ! COAP_THREAD_SAFE */

/*
 * No locking - single thread
 */
typedef coap_mutex_t coap_lock_t;

#define coap_lock_lock(s,failed)
#define coap_lock_unlock(s)
#define coap_lock_init(s)
#define coap_lock_being_freed(s,failed)
#define coap_lock_check_locked(s) {}
#define coap_lock_callback(s,func) func
#define coap_lock_callback_ret(r,s,func) ret = func
#define coap_lock_invert(s,func,f) func

#endif /* ! COAP_THREAD_SAFE */

#endif /* COAP_MUTEX_INTERNAL_H_ */
