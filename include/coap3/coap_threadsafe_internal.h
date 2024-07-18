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

/**
 * @ingroup internal_api
 * @defgroup locking_internal Multi-thread Support
 * Internal API for Multi-thread Locking Support
 * @{
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
 * However, when the context is going away (coap_free_context()), other
 * threads may still be access the lock in what is now freed memory.
 * A solution (by flagging being freed), worked, but still with a timing
 * window wen the context was finally de-allocated.  Coverity Scan did
 * not like the solution.
 *
 * So the initial support for thread safe is done at global lock level
 * using global_lock. However, context is provided as a parameter should
 * context level locking be subsequently used.
 *
 * Any public API call needs to potentially lock global_lock.
 *
 * If a public API needs thread safe protection, the coap_X() function
 * locks the global_lock lock, calls the coap_X_lkd() function
 * that does all the work and on return unlocks the global_lock before
 * returning to the caller of coap_X().  These coap_X() functions
 * need COAP_API in their definitions.
 *
 * Any internal libcoap calls that are to the public API coap_X() must call
 * coap_X_lkd() if the calling code is already locked.
 * [The compiler will throw out a deprecation warning against any internal
 * libcoap call to a COAP_API labelled function]
 *
 * Any call-back into app space must be done by using the coap_lock_callback()
 * (or coap_lock_callback_ret()) wrapper where the global_lock remains locked.
 *
 * Note:
 * libcoap may call a handler, which may in turn call into libcoap, which may
 * then call a handler. global_lock will remain locked thoughout this process
 * by the same thread.
 *
 * Alternatively, coap_lock_callback_release() (or
 * coap_lock_callback_ret_release()), is used where the global_lock is unlocked
 * for the duration of the call-back. Used for things like a request
 * handler which could be busy for some time.
 *
 * Note: On return from the call-back, the code has to be careful not to
 * use memory locations that may have been updated in the call-back by
 * calling a Public API.
 *
 * Any wait on select() or equivalent when a thread is waiting on an event
 * must be preceded by unlock global_lock, and then global_lock re-locked after
 * return;
 *
 * To check for recursive deadlock coding errors, COAP_THREAD_RECURSIVE_CHECK
 * needs to be defined.
 *
 * If thread safe is not enabled, then locking of the global_lock does not take
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
  const char *lock_file;
  unsigned int lock_line;
  unsigned int unlock_line;
  const char *unlock_file;
  const char *callback_file;
  unsigned int callback_line;
  unsigned int in_callback;
  unsigned int lock_count;
} coap_lock_t;

/**
 * Unlock the global_lock lock.
 *
 * If this is a nested lock (Public API - libcoap - app call-back - Public API),
 * then the lock remains locked, but global_lock.in_callback is decremented.
 *
 * Note: Invoked by wrapper macro, not used directly.
 *
 * @param file The file from which coap_lock_unlock_func() is getting called.
 * @param line The line no from which coap_lock_unlock_func() is getting called.
 */
void coap_lock_unlock_func(const char *file, int line);

/**
 * Lock the global_lock lock.
 *
 * If this is a nested lock (Public API - libcoap - app call-back - Public API),
 * then increment the global_lock.in_callback.
 *
 * Note: Invoked by wrapper macro, not used directly.
 *
 * @param file The file from which coap_lock_lock_func() is getting called.
 * @param line The line no from which coap_lock_lock_func() is getting called.
 *
 * @return @c 0 if libcoap has not started (coap_startup() not called), else @c 1.
 */
int coap_lock_lock_func(const char *file, int line);

/**
 * libcoap library code. Lock The global_lock.
 *
 * Invoked when
 *   Not locked at all
 *   Locked, app call-back, call from app call-back
 *   Locked, app call-back, call from app call-back, app call-back, call from app call-back
 * Result
 *   global_lock locked.
 *   global_lock not locked if libcoap not started and @p failed is executed. @p failed must
 *   be code that skips doing the lock protected code.
 *
 * @param c Context.
 * @param failed Code to execute on lock failure.
 *
 */
#define coap_lock_lock(c,failed) do { \
    if (!coap_lock_lock_func(__FILE__, __LINE__)) { \
      failed; \
    } \
  } while (0)

/**
 * libcoap library code. Unlock The global_lock.
 *
 * Unlocked when
 *   Same thread locked context
 *   Not when called from app call-back
 *
 * @param c Context.
 */
#define coap_lock_unlock(c) do { \
    coap_lock_unlock_func(__FILE__, __LINE__); \
  } while (0)

/**
 * libcoap library code. Invoke an app callback, leaving global_lock locked.
 *
 * Called when
 *   Locked
 *
 * @param c Context.
 * @param func app call-back function to invoke.
 *
 */
#define coap_lock_callback(c,func) do { \
    coap_lock_check_locked(c); \
    global_lock.in_callback++; \
    global_lock.callback_file = __FILE__; \
    global_lock.callback_line = __LINE__; \
    func; \
    global_lock.in_callback--; \
  } while (0)

/**
 * libcoap library code. Invoke an app callback that has a return value,
 * leaving global_lock locked.
 *
 * Called when
 *   Locked
 *
 * @param r Return value from @p func.
 * @param c Context.
 * @param func app call-back function to invoke.
 *
 */
#define coap_lock_callback_ret(r,c,func) do { \
    coap_lock_check_locked(c); \
    global_lock.in_callback++; \
    global_lock.callback_file = __FILE__; \
    global_lock.callback_line = __LINE__; \
    (r) = func; \
    global_lock.in_callback--; \
  } while (0)

/**
 * libcoap library code. Invoke an app callback, unlocking global_lock first.
 *
 * Called when
 *   Locked
 *
 * @param c Context.
 * @param func app call-back function to invoke.
 * @param failed Code to execute on (re-)lock failure.
 *
 */
#define coap_lock_callback_release(c,func,failed) do { \
    coap_lock_check_locked(c); \
    coap_lock_unlock(c); \
    func; \
    coap_lock_lock(c,failed); \
  } while (0)

/**
 * libcoap library code. Invoke an app callback that has a return value,
 * unlocking global_lock first.
 *
 * Called when
 *   Locked (need to unlock over app call-back)
 *
 * @param r Return value from @p func.
 * @param c Context to unlock.
 * @param func app call-back function to invoke.
 * @param failed Code to execute on lock failure
 *
 */
#define coap_lock_callback_ret_release(r,c,func,failed) do { \
    coap_lock_check_locked(c); \
    coap_lock_unlock(c); \
    (r) = func; \
    coap_lock_lock(c,failed); \
  } while (0)

extern coap_lock_t global_lock;

# else /* ! COAP_THREAD_RECURSIVE_CHECK */

/*
 * Locking, but no deadlock detection
 */
typedef struct coap_lock_t {
  coap_mutex_t mutex;
  coap_thread_pid_t pid;
  uint32_t in_callback;
  volatile uint32_t lock_count;
} coap_lock_t;

/**
 * Unlock the global_lock lock.
 *
 * If this is a nested lock (Public API - libcoap - app call-back - Public API),
 * then the lock remains locked, but global_lock.in_callback is decremented.
 *
 * Note: Invoked by wrapper macro, not used directly.
 *
 */
void coap_lock_unlock_func(void);

/**
 * Lock the global_lock lock.
 *
 * If this is a nested lock (Public API - libcoap - app call-back - Public API),
 * then increment the global_lock.in_callback.
 *
 * Note: Invoked by wrapper macro, not used directly.
 *
 * @return @c 0 if libcoap has not started (coap_startup() not called), else @c 1.
 */
int coap_lock_lock_func(void);

/**
 * libcoap library code. Lock The global_lock.
 *
 * Invoked when
 *   Not locked at all
 *   Locked, app call-back, call from app call-back
 *   Locked, app call-back, call from app call-back, app call-back, call from app call-back
 * Result
 *   global_lock locked.
 *   global not locked if libcoap not started and @p failed is executed. @p failed must
 *   be code that skips doing the lock protected code.
 *
 * @param c Contex.
 * @param failed Code to execute on lock failure
 *
 */
#define coap_lock_lock(c,failed) do { \
    if (!coap_lock_lock_func()) { \
      failed; \
    } \
  } while (0)

/**
 *  libcoap library code. Unlock The global_lock.
 *
 * Unlocked when
 *   Same thread locked context.
 *   Not when called from app call-back.
 *
 * @param c Context.
 */
#define coap_lock_unlock(c) do { \
    assert(c); \
    coap_lock_unlock_func(); \
  } while (0)

/**
 * libcoap library code. Invoke an app callback, leaving global_lock locked.
 *
 * Called when
 *   Locked
 *
 * @param c Context.
 * @param func app call-back function to invoke.
 *
 */
#define coap_lock_callback(c,func) do { \
    coap_lock_check_locked(c); \
    global_lock.in_callback++; \
    func; \
    global_lock.in_callback--; \
  } while (0)

/**
 * libcoap library code. Invoke an app callback that has a return value,
 * leaving global_lock locked.
 *
 * Called when
 *   Locked
 *
 * @param r Return value from @p func.
 * @param c Context.
 * @param func app call-back function to invoke.
 *
 */
#define coap_lock_callback_ret(r,c,func) do { \
    coap_lock_check_locked(c); \
    global_lock.in_callback++; \
    global_lock.in_callback++; \
    (r) = func; \
    global_lock.in_callback--; \
  } while (0)

/**
 * libcoap library code. Invoke an app callback, unlocking global_lock first.
 *
 * Called when
 *   Locked (need to unlock over app call-back)
 *
 * @param c Context.
 * @param func app call-back function to invoke.
 * @param failed Code to execute on (re-)lock failure.
 *
 */
#define coap_lock_callback_release(c,func,failed) do { \
    coap_lock_check_locked(c); \
    coap_lock_unlock(c); \
    func; \
    coap_lock_lock(c,failed); \
  } while (0)

/**
 * libcoap library code. Invoke an app callback that has a return value,
 * unlocking global_lock first.
 *
 * Called when
 *   Locked (need to unlock over app call-back)
 *
 * @param r Return value from @p func.
 * @param c Context.
 * @param func app call-back function to invoke.
 * @param failed Code to execute on lock failure.
 *
 */
#define coap_lock_callback_ret_release(r,c,func,failed) do { \
    coap_lock_check_locked(c); \
    coap_lock_unlock(c); \
    (r) = func; \
    coap_lock_lock(c,failed); \
  } while (0)

# endif /* ! COAP_THREAD_RECURSIVE_CHECK */

/**
 * libcoap library code. Initialize the global_lock.
 */
#define coap_lock_init() do { \
    memset(&global_lock.mutex, 0, sizeof(global_lock.mutex)); \
    coap_mutex_init(&global_lock.mutex); \
  } while (0)

/**
 * libcoap library code. Check that global_lock is locked.
 */
#define coap_lock_check_locked(c) do { \
    assert(coap_thread_pid == global_lock.pid); \
  } while (0)

/**
 * libcoap library code. Lock an alternative lock. To prevent
 * locking order issues, global_lock is unlocked, the alternative
 * lock is locked and then global_lock is re-locked.
 *
 * Called when
 *   Locked (need to unlock over locking of alternative lock)
 *
 * @param c Context.
 * @param alt_lock Alternative lock locking code.
 * @param failed Code to execute on lock failure.
 *
 */
#define coap_lock_invert(c,alt_lock,failed) do { \
    coap_lock_check_locked(c); \
    coap_lock_unlock(c); \
    alt_lock; \
    coap_lock_lock(c,failed); \
  } while (0)

extern coap_lock_t global_lock;

#else /* ! COAP_THREAD_SAFE */

/*
 * No locking - single thread
 */
typedef coap_mutex_t coap_lock_t;

/**
 * Dummy for no thread-safe code
 *
 * libcoap library code. Lock The global_lock.
 *
 * Invoked when
 *   Not locked at all
 *   Locked, app call-back, call from app call-back
 *   Locked, app call-back, call from app call-back, app call-back, call from app call-back
 * Result
 *   global_lock locked.
 *   global_lock not locked if libcoap not started and @p failed is executed. @p failed must
 *   be code that skips doing the lock protected code.
 *
 * @param c Context.
 * @param failed Code to execute on lock failure.
 *
 */
#define coap_lock_lock(c,failed)

/**
 * Dummy for no thread-safe code
 *
 * libcoap library code. Unlock The global_lock.
 *
 * Unlocked when
 *   Same thread locked context
 *
 * @param c Context.
 */
#define coap_lock_unlock(c)

/**
 * Dummy for no thread-safe code
 *
 * libcoap library code. Initialize the global_lock.
 */
#define coap_lock_init()

/**
 * Dummy for no thread-safe code
 *
 * libcoap library code. Check that global_lock is locked.
 */
#define coap_lock_check_locked(c) {}

/**
 * Dummy for no thread-safe code
 *
 * libcoap library code. Invoke an app callback, leaving global_lock locked.
 *
 * Called when
 *   Locked
 *
 * @param c Context.
 * @param func app call-back function to invoke.
 *
 */
#define coap_lock_callback(c,func) func

/**
 * Dummy for no thread-safe code
 *
 * libcoap library code. Invoke an app callback that has a return value,
 * leaving global_lock locked.
 *
 * Called when
 *   Locked
 *
 * @param r Return value from @p func.
 * @param c Context.
 * @param func app call-back function to invoke.
 *
 */
#define coap_lock_callback_ret(r,c,func) (r) = func

/**
 * Dummy for no thread-safe code
 *
 * libcoap library code. Invoke an app callback, unlocking global_lock first.
 *
 * Called when
 *   Locked
 *
 * @param c Context.
 * @param func app call-back function to invoke.
 * @param failed Code to execute on (re-)lock failure.
 *
 */
#define coap_lock_callback_release(c,func,failed) func

/**
 * Dummy for no thread-safe code
 *
 * libcoap library code. Invoke an app callback that has a return value,
 * unlocking global_lock first.
 *
 * Called when
 *   Locked (need to unlock over app call-back)
 *   Unlocked by thread free'ing off context
 *
 * @param r Return value from @p func.
 * @param c Context to unlock.
 * @param func app call-back function to invoke.
 * @param failed Code to execute on lock failure
 *
 */
#define coap_lock_callback_ret_release(r,c,func,failed) (r) = func

/**
 * Dummy for no thread-safe code
 *
 * libcoap library code. Lock an alternative lock. To prevent
 * locking order issues, global_lock is unlocked, the alternative
 * lock is locked and then global_lock is re-locked.
 *
 * Called when
 *   Locked (need to unlock over locking of alternative lock)
 *
 * @param c Context.
 * @param alt_lock Alternative lock locking code.
 * @param failed Code to execute on lock failure.
 *
 */
#define coap_lock_invert(c,alt_lock,failed) func

#endif /* ! COAP_THREAD_SAFE */

/** @} */

#endif /* COAP_THREADSAFE_INTERNAL_H_ */
