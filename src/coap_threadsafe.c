/* coap_threadsafe.c -- Thread safe function locking wrappers
 *
 * Copyright (C) 2023-2024 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file coap_threadsafe.c
 * @brief CoAP multithreading locking check functions
 */

#include "coap3/coap_libcoap_build.h"

#if COAP_THREAD_SAFE
#if COAP_THREAD_RECURSIVE_CHECK
void
coap_lock_unlock_func(coap_lock_t *lock, const char *file, int line) {
  assert(coap_thread_pid == lock->pid);
  if (lock->in_callback) {
    assert(lock->lock_count > 0);
    lock->lock_count--;
  } else {
    lock->pid = 0;
    lock->unlock_file = file;
    lock->unlock_line = line;
    coap_mutex_unlock(&lock->mutex);
  }
}

int
coap_lock_lock_func(coap_lock_t *lock, int force, const char *file, int line) {
  if (!force && lock->being_freed) {
    /* context is going away */
    return 0;
  }
  if (coap_mutex_trylock(&lock->mutex)) {
    if (coap_thread_pid == lock->pid) {
      /* This thread locked the mutex */
      if (lock->in_callback) {
        /* This is called from within an app callback */
        lock->lock_count++;
        assert(lock->in_callback == lock->lock_count);
        return 1;
      } else {
        coap_log_alert("Thread Deadlock: Last %s: %u, this %s: %u\n",
                       lock->lock_file, lock->lock_line, file, line);
        assert(0);
      }
    }
    /* Wait for the other thread to unlock */
    coap_mutex_lock(&lock->mutex);
  }
  /* Just got the lock, so should not be in a locked callback */
  assert(!lock->in_callback);
  lock->pid = coap_thread_pid;
  lock->lock_file = file;
  lock->lock_line = line;
#ifndef __COVERITY__
  if (!force && lock->being_freed) {
    /*
     * lock->being_freed set when previous thread had lock locked.
     * Have to unlock to let the next context locking user clean up.
     */
    coap_lock_unlock_func(lock, file, line);
    return 0;
  }
#endif /* __COVERITY__ */
  return 1;
}

#else /* ! COAP_THREAD_RECURSIVE_CHECK */

void
coap_lock_unlock_func(coap_lock_t *lock) {
  assert(coap_thread_pid == lock->pid);
  if (lock->in_callback) {
    assert(lock->lock_count > 0);
    lock->lock_count--;
  } else {
    lock->pid = 0;
    coap_mutex_unlock(&lock->mutex);
  }
}

int
coap_lock_lock_func(coap_lock_t *lock, int force) {
  if (!force && lock->being_freed) {
    /* context is going away */
    return 0;
  }
  /*
   * Some OS do not have support for coap_mutex_trylock() so
   * cannot use that here and have to rely on lock-pid being stable
   */
  if (lock->in_callback && coap_thread_pid == lock->pid) {
    lock->lock_count++;
    assert(lock->in_callback == lock->lock_count);
    return 1;
  }
  coap_mutex_lock(&lock->mutex);
  /* Just got the lock, so should not be in a locked callback */
  assert(!lock->in_callback);
  lock->pid = coap_thread_pid;
#ifndef __COVERITY__
  if (!force && lock->being_freed) {
    /*
     * lock->being_freed set when previous thread had lock locked.
     * Have to unlock to let the next context locking user clean up.
     */
    coap_lock_unlock_func(lock);
    return 0;
  }
#endif /* __COVERITY__ */
  return 1;
}
#endif /* ! COAP_THREAD_RECURSIVE_CHECK */

#else /* ! COAP_THREAD_SAFE */

#ifdef __clang__
/* Make compilers happy that do not like empty modules. As this function is
 * never used, we ignore -Wunused-function at the end of compiling this file
 */
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
static inline void
dummy(void) {
}

#endif /* ! COAP_THREAD_SAFE */
