/*
 * coap_threadsafe_internal.h -- Mapping of threadsafe functions
 *
 * Copyright (C) 2023-2024 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_threadsafe_internal.h
 * @brief CoAP mapping of locking functions
 */

#ifndef COAP_THREADSAFE_INTERNAL_H_
#define COAP_THREADSAFE_INTERNAL_H_

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
 * multiple contexts. If a public API needs thread safe protection, the
 * coap_X() function locks the context lock, calls the coap_X_lkd() function
 * that does all the work and on return unlocks the context before returning
 * to the caller of coap_X().
 *
 * Any internal libcoap calls that are to the public API coap_X() must call
 * coap_X_lkd() if the calling code is already locked.
 *
 * Any call-back into app space must be done by using the coap_lock_callback()
 * (or coap_lock_callback_ret()) wrapper where the context remains locked.
 *
 * Note:
 * libcoap may call a handler, which may in turn call into libcoap, which may
 * then call a handler.  context will remain locked thoughout this process.
 *
 * Alternatively, coap_lock_callback_release() (or
 * coap_lock_callback_ret_release()), is used where the context is unlocked
 * for the duration of the call-back. Used for things like a request
 * handler which could be busy for some time.
 *
 * Note: On return from the call-back, the code has to be careful not to
 * use memory locations that make have been updated in the call-back by
 * calling a Public API.
 *
 * Any wait on select() or equivalent when a thread is waiting on an event
 * must be preceded by unlock context, and then context re-locked after
 * return;
 *
 * To check for recursive deadlocks, COAP_THREAD_RECURSIVE_CHECK needs to be
 * defined.
 *
 * If thread safe is not enabled, then locking of the context does not take
 * place.
 */
#if COAP_THREAD_SAFE
# if COAP_THREAD_RECURSIVE_CHECK

/*
 * Locking, with deadlock detection
 */
typedef struct coap_lock_t {
  coap_mutex_t mutex;
  coap_thread_pid_t pid;
  coap_thread_pid_t freeing_pid;
  const char *lock_file;
  unsigned int lock_line;
  unsigned int unlock_line;
  const char *unlock_file;
  const char *callback_file;
  unsigned int callback_line;
  unsigned int being_freed;
  unsigned int in_callback;
  unsigned int lock_count;
} coap_lock_t;

void coap_lock_unlock_func(coap_lock_t *lock, const char *file, int line);
int coap_lock_lock_func(coap_lock_t *lock, const char *file, int line);

#define coap_lock_lock(s,failed) do { \
    assert(s); \
    if (!coap_lock_lock_func(&(s)->lock, __FILE__, __LINE__)) { \
      failed; \
    } \
  } while (0)

#define coap_lock_unlock(s) do { \
    assert(s); \
    coap_lock_unlock_func(&(s)->lock, __FILE__, __LINE__); \
  } while (0)

#define coap_lock_callback(s,func) do { \
    coap_lock_check_locked(s); \
    (s)->lock.in_callback++; \
    (s)->lock.callback_file = __FILE__; \
    (s)->lock.callback_line = __LINE__; \
    func; \
    (s)->lock.in_callback--; \
  } while (0)

#define coap_lock_callback_ret(r,s,func) do { \
    coap_lock_check_locked(s); \
    (s)->lock.in_callback++; \
    (s)->lock.callback_file = __FILE__; \
    (s)->lock.callback_line = __LINE__; \
    r = func; \
    (s)->lock.in_callback--; \
  } while (0)

#define coap_lock_callback_release(s,func,fail) do { \
    coap_lock_check_locked(s); \
    coap_lock_unlock(s); \
    func; \
    coap_lock_lock(s,fail); \
  } while (0)

#define coap_lock_callback_ret_release(r,s,func,fail) do { \
    coap_lock_check_locked(s); \
    coap_lock_unlock(s); \
    r = func; \
    coap_lock_lock(s,fail); \
  } while (0)

# else /* ! COAP_THREAD_RECURSIVE_CHECK */

/*
 * Locking, but no deadlock detection
 */
typedef struct coap_lock_t {
  coap_mutex_t mutex;
  coap_thread_pid_t pid;
  coap_thread_pid_t freeing_pid;
  uint32_t being_freed;
  uint32_t in_callback;
  volatile uint32_t lock_count;
} coap_lock_t;

void coap_lock_unlock_func(coap_lock_t *lock);
int coap_lock_lock_func(coap_lock_t *lock);

#define coap_lock_lock(s,failed) do { \
    assert(s); \
    if (!coap_lock_lock_func(&(s)->lock)) { \
      failed; \
    } \
  } while (0)

#define coap_lock_unlock(s) do { \
    assert(s); \
    coap_lock_unlock_func(&(s)->lock); \
  } while (0)

#define coap_lock_callback(s,func) do { \
    coap_lock_check_locked(s); \
    (s)->lock.in_callback++; \
    func; \
    (s)->lock.in_callback--; \
  } while (0)

#define coap_lock_callback_ret(r,s,func) do { \
    coap_lock_check_locked(s); \
    (s)->lock.in_callback++; \
    r = func; \
    (s)->lock.in_callback--; \
  } while (0)

#define coap_lock_callback_release(s,func,fail) do { \
    coap_lock_check_locked(s); \
    coap_lock_unlock(s); \
    func; \
    coap_lock_lock(s,fail); \
  } while (0)

#define coap_lock_callback_ret_release(r,s,func,fail) do { \
    coap_lock_check_locked(s); \
    coap_lock_unlock(s); \
    r = func; \
    coap_lock_lock(s,fail); \
  } while (0)

# endif /* ! COAP_THREAD_RECURSIVE_CHECK */

#define coap_lock_init(s) do { \
    assert(s); \
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
    assert((s) && \
           coap_thread_pid == ((s)->lock.being_freed ? (s)->lock.freeing_pid : \
                               (s)->lock.pid)); \
  } while (0)

#define coap_lock_invert(s,func,f) do { \
    coap_lock_check_locked(s); \
    if (!(s)->lock.being_freed) { \
      coap_lock_unlock(s); \
      func; \
      coap_lock_lock(s,f); \
    } else { \
      func; \
    } \
  } while (0)

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
#define coap_lock_callback_release(s,func,fail) func
#define coap_lock_callback_ret_release(r,s,func,fail) ret = func
#define coap_lock_invert(s,func,f) func

#endif /* ! COAP_THREAD_SAFE */

#endif /* COAP_THREADSAFE_INTERNAL_H_ */
