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
 * then call a handler.  context will remain locked thoughout this process
 * by the same thread.
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
 * To check for recursive deadlock coding errors, COAP_THREAD_RECURSIVE_CHECK
 * needs to be defined.
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

/**
 * Unlock the (context) lock.
 * If this is a nested lock (Public API - libcoap - app call-back - Public API),
 * then the lock remains locked, but lock->in_callback is decremented.
 *
 * @param lock The lock to unlock.
 * @param file The file from which coap_lock_unlock_func() is getting called.
 * @param line The line no from which coap_lock_unlock_func() is getting called.
 */
void coap_lock_unlock_func(coap_lock_t *lock, const char *file, int line);

/**
 * Lock the (context) lock.
 * If this is a nested lock (Public API - libcoap - app call-back - Public API),
 * then increment the lock->in_callback.
 * If lock->being_freed is set and @p force is not set, then lock ends up unlocked.
 *
 * @param lock The lock to unlock.
 * @param force If set, then lock even if lock->being_freed is set.
 * @param file The file from which coap_lock_unlock_func() is getting called.
 * @param line The line no from which coap_lock_unlock_func() is getting called.
 *
 * @return @c 0 if lock->being_freed is set (and @p force is not set), else @c 1.
 */
int coap_lock_lock_func(coap_lock_t *lock, int force, const char *file, int line);

/**
 * Invoked when
 *   Not locked at all
 *   Not locked, context being freed
 *   Locked, app call-back, call from app call-back
 *   Locked, app call-back, call from app call-back, app call-back, call from app call-back
 * Result
 *   context locked
 *   context not locked if context being freed and @p failed is executed. @p failed must
 *   be code that skips doing the lock protected code.
 *
 * @param c Context to lock.
 * @param failed Code to execute on lock failure
 *
 */
#define coap_lock_lock(c,failed) do { \
    assert(c); \
    if (!coap_lock_lock_func(&(c)->lock, 0, __FILE__, __LINE__)) { \
      failed; \
    } \
  } while (0)

/**
 * Unlocked when
 *   Same thread locked context
 *   Not when called from app call-back
 *
 * @param c Context to unlock.
 */
#define coap_lock_unlock(c) do { \
    assert(c); \
    coap_lock_unlock_func(&(c)->lock, __FILE__, __LINE__); \
  } while (0)

/**
 * Called when
 *   Locked
 *   Unlocked by thread free'ing off context (need to lock over app call-back)
 *
 * @param c Context to lock if not locked
 * @param func app call-back function to invoke
 *
 */
#define coap_lock_callback(c,func) do { \
    int being_freed = (c)->lock.being_freed && coap_thread_pid == (c)->lock.freeing_pid; \
    if (being_freed) { \
      coap_lock_lock_func(&(c)->lock, 1, __FILE__, __LINE__); \
    } else { \
      coap_lock_check_locked(c); \
    } \
    (c)->lock.in_callback++; \
    (c)->lock.callback_file = __FILE__; \
    (c)->lock.callback_line = __LINE__; \
    func; \
    (c)->lock.in_callback--; \
    if (being_freed) { \
      coap_lock_unlock_func(&(c)->lock, __FILE__, __LINE__); \
    } \
  } while (0)

/**
 * Called when
 *   Locked
 *   Unlocked by thread free'ing off context (need to lock over app call-back)
 *
 * @param r Return value from @func.
 * @param c Context to lock.
 * @param func app call-back function to invoke
 *
 */
#define coap_lock_callback_ret(r,c,func) do { \
    int being_freed = (c)->lock.being_freed && coap_thread_pid == (c)->lock.freeing_pid; \
    if (being_freed) { \
      coap_lock_lock_func(&(c)->lock, 1, __FILE__, __LINE__); \
    } else { \
      coap_lock_check_locked(c); \
    } \
    (c)->lock.in_callback++; \
    (c)->lock.callback_file = __FILE__; \
    (c)->lock.callback_line = __LINE__; \
    (r) = func; \
    (c)->lock.in_callback--; \
    if (being_freed) { \
      coap_lock_unlock_func(&(c)->lock, __FILE__, __LINE__); \
    } \
  } while (0)

/**
 * Called when
 *   Locked (need to unlock over app call-back)
 *   Unlocked by thread free'ing off context
 *
 * @param c Context to unlock.
 * @param func app call-back function to invoke
 * @param failed Code to execute on lock failure
 *
 */
#define coap_lock_callback_release(c,func,failed) do { \
    int being_freed = (c)->lock.being_freed && coap_thread_pid == (c)->lock.freeing_pid; \
    if (!being_freed) { \
      coap_lock_check_locked(c); \
      coap_lock_unlock(c); \
      func; \
      coap_lock_lock(c,failed); \
    } else { \
      func; \
    } \
  } while (0)

/**
 * Called when
 *   Locked (need to unlock over app call-back)
 *   Unlocked by thread free'ing off context
 *
 * @param r Return value from @func.
 * @param c Context to unlock.
 * @param func app call-back function to invoke
 * @param failed Code to execute on lock failure
 *
 */
#define coap_lock_callback_ret_release(r,c,func,failed) do { \
    int being_freed = (c)->lock.being_freed && coap_thread_pid == (c)->lock.freeing_pid; \
    if (!being_freed) { \
      coap_lock_check_locked(c); \
      coap_lock_unlock(c); \
      (r) = func; \
      coap_lock_lock(c,failed); \
    } else { \
      (r) = func; \
    } \
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

/**
 * Unlock the (context) lock.
 * If this is a nested lock (Public API - libcoap - app call-back - Public API),
 * then the lock remains locked, but lock->in_callback is decremented.
 *
 * @param lock The lock to unlock.
 */
void coap_lock_unlock_func(coap_lock_t *lock);

/**
 * Lock the (context) lock.
 * If this is a nested lock (Public API - libcoap - app call-back - Public API),
 * then increment the lock->in_callback.
 * If lock->being_freed is set and @p force is not set, then lock ends up unlocked.
 *
 * @param lock The lock to unlock.
 * @param force If set, then lock even if lock->being_freed is set.
 *
 * @return @c 0 if lock->being_freed is set (and @p force is not set), else @c 1.
 */
int coap_lock_lock_func(coap_lock_t *lock, int force);

/**
 * Invoked when
 *   Not locked at all
 *   Not locked, context being freed
 *   Locked, app call-back, call from app call-back
 *   Locked, app call-back, call from app call-back, app call-back, call from app call-back
 * Result
 *   context locked
 *   context not locked if context being freed and @p failed is executed. @p failed must
 *   be code that skips doing the lock protected code.
 *
 * @param c Context to lock.
 * @param failed Code to execute on lock failure
 *
 */
#define coap_lock_lock(c,failed) do { \
    assert(c); \
    if (!coap_lock_lock_func(&(c)->lock, 0)) { \
      failed; \
    } \
  } while (0)

/**
 * Unlocked when
 *   Same thread locked context
 *   Not when called from app call-back
 *
 * @param c Context to unlock.
 */
#define coap_lock_unlock(c) do { \
    assert(c); \
    coap_lock_unlock_func(&(c)->lock); \
  } while (0)

/**
 * Called when
 *   Locked
 *   Unlocked by thread free'ing off context (need to lock over app call-back)
 *
 * @param c Context to lock.
 * @param func app call-back function to invoke
 *
 */
#define coap_lock_callback(c,func) do { \
    int being_freed = (c)->lock.being_freed && coap_thread_pid == (c)->lock.freeing_pid; \
    if (being_freed) { \
      coap_lock_lock_func(&(c)->lock, 1); \
    } else { \
      coap_lock_check_locked(c); \
    } \
    (c)->lock.in_callback++; \
    func; \
    (c)->lock.in_callback--; \
    if (being_freed) { \
      coap_lock_unlock_func(&(c)->lock); \
    } \
  } while (0)

/**
 * Called when
 *   Locked
 *   Unlocked by thread free'ing off context (need to lock over app call-back)
 *
 * @param r Return value from @func.
 * @param c Context to lock.
 * @param func app call-back function to invoke
 *
 */
#define coap_lock_callback_ret(r,c,func) do { \
    int being_freed = (c)->lock.being_freed && coap_thread_pid == (c)->lock.freeing_pid; \
    if (being_freed) { \
      coap_lock_lock_func(&(c)->lock, 1); \
    } else { \
      coap_lock_check_locked(c); \
    } \
    (c)->lock.in_callback++; \
    (c)->lock.in_callback++; \
    (r) = func; \
    (c)->lock.in_callback--; \
    if (being_freed) { \
      coap_lock_unlock_func(&(c)->lock); \
    } \
  } while (0)

/**
 * Called when
 *   Locked (need to unlock over app call-back)
 *   Unlocked by thread free'ing off context
 *
 * @param c Context to unlock.
 * @param func app call-back function to invoke
 * @param failed Code to execute on lock failure
 *
 */
#define coap_lock_callback_release(c,func,failed) do { \
    int being_freed = (c)->lock.being_freed && coap_thread_pid == (c)->lock.freeing_pid; \
    if (!being_freed) { \
      coap_lock_check_locked(c); \
      coap_lock_unlock(c); \
      func; \
      coap_lock_lock(c,failed); \
    } else { \
      func; \
    } \
  } while (0)

/**
 * Called when
 *   Locked (need to unlock over app call-back)
 *   Unlocked by thread free'ing off context
 *
 * @param r Return value from @func.
 * @param c Context to unlock.
 * @param func app call-back function to invoke
 * @param failed Code to execute on lock failure
 *
 */
#define coap_lock_callback_ret_release(r,c,func,failed) do { \
    int being_freed = (c)->lock.being_freed && coap_thread_pid == (c)->lock.freeing_pid; \
    if (!being_freed) { \
      coap_lock_check_locked(c); \
      coap_lock_unlock(c); \
      (r) = func; \
      coap_lock_lock(c,failed); \
    } else { \
      (r) = func; \
    } \
  } while (0)

# endif /* ! COAP_THREAD_RECURSIVE_CHECK */

#define coap_lock_init(c) do { \
    assert(c); \
    memset(&((c)->lock), 0, sizeof((c)->lock)); \
    coap_mutex_init(&(c)->lock.mutex); \
  } while (0)

#define coap_lock_being_freed(c,failed) do { \
    coap_lock_lock(c,failed); \
    (c)->lock.being_freed = 1; \
    (c)->lock.freeing_pid = coap_thread_pid; \
    coap_lock_unlock(c); \
  } while (0)

#define coap_lock_check_locked(c) do { \
    assert((c) && \
           coap_thread_pid == ((c)->lock.being_freed ? (c)->lock.freeing_pid : \
                               (c)->lock.pid)); \
  } while (0)

#define coap_lock_invert(c,func,f) do { \
    coap_lock_check_locked(c); \
    if (!(c)->lock.being_freed) { \
      coap_lock_unlock(c); \
      func; \
      coap_lock_lock(c,f); \
    } else { \
      func; \
    } \
  } while (0)

#else /* ! COAP_THREAD_SAFE */

/*
 * No locking - single thread
 */
typedef coap_mutex_t coap_lock_t;

#define coap_lock_lock(c,failed)
#define coap_lock_unlock(c)
#define coap_lock_init(c)
#define coap_lock_being_freed(c,failed)
#define coap_lock_check_locked(c) {}
#define coap_lock_callback(c,func) func
#define coap_lock_callback_ret(r,c,func) (r) = func
#define coap_lock_callback_release(c,func,failed) func
#define coap_lock_callback_ret_release(r,c,func,failed) (r) = func
#define coap_lock_invert(c,func,f) func

#endif /* ! COAP_THREAD_SAFE */

#endif /* COAP_THREADSAFE_INTERNAL_H_ */
