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
coap_lock_unlock_func(const char *file, int line) {
  assert(coap_thread_pid == global_lock.pid);
  if (global_lock.in_callback) {
    assert(global_lock.lock_count > 0);
    global_lock.lock_count--;
  } else {
    global_lock.pid = 0;
    global_lock.unlock_file = file;
    global_lock.unlock_line = line;
    coap_mutex_unlock(&global_lock.mutex);
  }
}

int
coap_lock_lock_func(const char *file, int line) {
  if (!coap_started) {
    /* libcoap not initialized with coap_startup() */
    return 0;
  }
  if (coap_mutex_trylock(&global_lock.mutex)) {
    if (coap_thread_pid == global_lock.pid) {
      /* This thread locked the mutex */
      if (global_lock.in_callback) {
        /* This is called from within an app callback */
        global_lock.lock_count++;
        assert(global_lock.in_callback == global_lock.lock_count);
        return 1;
      } else {
        coap_log_alert("Thread Deadlock: Last %s: %u, this %s: %u\n",
                       global_lock.lock_file, global_lock.lock_line, file, line);
        assert(0);
      }
    }
    /* Wait for the other thread to unlock */
    coap_mutex_lock(&global_lock.mutex);
  }
  /* Just got the lock, so should not be in a locked callback */
  assert(!global_lock.in_callback);
  global_lock.pid = coap_thread_pid;
  global_lock.lock_file = file;
  global_lock.lock_line = line;
  return 1;
}

#else /* ! COAP_THREAD_RECURSIVE_CHECK */

void
coap_lock_unlock_func(void) {
  assert(coap_thread_pid == global_lock.pid);
  if (global_lock.in_callback) {
    assert(global_lock.lock_count > 0);
    global_lock.lock_count--;
  } else {
    global_lock.pid = 0;
    coap_mutex_unlock(&global_lock.mutex);
  }
}

int
coap_lock_lock_func(void) {
  if (!coap_started) {
    /* libcoap not initialized with coap_startup() */
    return 0;
  }
  /*
   * Some OS do not have support for coap_mutex_trylock() so
   * cannot use that here and have to rely on lock-pid being stable
   */
  if (global_lock.in_callback && coap_thread_pid == global_lock.pid) {
    global_lock.lock_count++;
    assert(global_lock.in_callback == global_lock.lock_count);
    return 1;
  }
  coap_mutex_lock(&global_lock.mutex);
  /* Just got the lock, so should not be in a locked callback */
  assert(!global_lock.in_callback);
  global_lock.pid = coap_thread_pid;
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
