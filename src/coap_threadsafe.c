/* coap_threadsafe.c -- Thread safe function locking wrappers
 *
 * Copyright (C) 2023-2026 Jon Shallow <supjps-libcoap@jpshallow.com>
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
coap_lock_lock_func(coap_lock_t *lock, const char *file, int line) {
  if (!coap_started) {
    /* libcoap not initialized with coap_startup() */
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
coap_lock_lock_func(coap_lock_t *lock) {
  if (!coap_started) {
    /* libcoap not initialized with coap_startup() */
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
  return 1;
}
#endif /* ! COAP_THREAD_RECURSIVE_CHECK */

#if !WITH_LWIP
extern COAP_THREAD_LOCAL_VAR volatile int coap_thread_quit;

/* Visible to only this thread */
COAP_THREAD_LOCAL_VAR uint32_t thread_no = 0;
/* Visible across all threads */
uint32_t max_thread_no = 0;

typedef struct {
  coap_context_t *context;
  uint32_t thread_no;
} coap_thread_param_t;

static void *
coap_io_process_worker_thread(void *arg) {
  coap_thread_param_t *thread_param = (coap_thread_param_t *)arg;
  coap_context_t *context = thread_param->context;
#if (COAP_MAX_LOGGING_LEVEL >= _COAP_LOG_DEBUG)
  long unsigned int thread_pid = (long unsigned int)coap_thread_pid;
#endif

  thread_no = thread_param->thread_no;
  coap_free_type(COAP_STRING, thread_param);

  coap_log_debug("Thread %lx start\n", thread_pid);

  while (!coap_thread_quit) {
    int result;

    coap_lock_lock(return 0);
#ifndef __ZEPHYR__
    result = coap_io_process_lkd(context, COAP_IO_WAIT);
#else /* __ZEPHYR__ */
    result = coap_io_process_lkd(context, 1000);
#endif /* __ZEPHYR__ */
    coap_lock_unlock();
    if (result < 0 || coap_thread_quit)
      break;
  }
  coap_dtls_thread_shutdown();
  coap_log_debug("Thread %lx exit\n", thread_pid);
  return 0;
}

#if defined(HAVE_SIGNAL_H) || defined(__ZEPHYR__)
#include <signal.h>
#endif /* HAVE_SIGNAL_H || __ZEPHYR__ */

/* sighandler_t is not defined is all OS */
typedef void (*coap_sig_handler_t)(int);

static coap_sig_handler_t old_sigint_handler = SIG_IGN;

static void
coap_thread_sigint_handler(int signum) {
  coap_thread_quit = 1;
  if (old_sigint_handler != SIG_IGN && old_sigint_handler != SIG_DFL) {
    old_sigint_handler(signum);
  }
}

#ifndef _WIN32
typedef void (*coap_sig_action_t)(int, siginfo_t *, void *);
static coap_sig_action_t old_sigint_action = NULL;

static void
coap_thread_sigint_action(int signum, siginfo_t *siginfo, void *ptr) {
  coap_thread_quit = 1;
  if (old_sigint_action != NULL) {
    old_sigint_action(signum, siginfo, ptr);
  }
}
#endif /*! _WIN32 */

/* Must be run upder the protection of mutex m_io_threads */
static void
coap_io_process_kill_threads(coap_context_t *context) {
  uint32_t i;

#ifndef __ZEPHYR__
  for (i = 0; i < context->thread_id_count ; i++) {
    int s = pthread_kill(context->thread_id[i], COAP_THREAD_KILL_SIG);
    if (s != 0) {
      coap_log_err("thread kill failure\n");
    }
  }
#else /* __ZEPHYR__ */
  coap_thread_quit = 1;
  coap_send_recv_terminate();
#endif /* __ZEPHYR__ */

  for (i = 0; i < context->thread_id_count ; i++) {
    void *retval;
    int s = pthread_join(context->thread_id[i], &retval);

    if (s != 0) {
      coap_log_err("thread join failure\n");
    }
  }
  coap_free_type(COAP_STRING, context->thread_id);
  context->thread_id = NULL;
  context->thread_id_count = 0;
}

int
coap_io_process_configure_threads(coap_context_t *context, uint32_t thread_count) {
  uint32_t i;
  uint32_t base_thread;

  if (thread_count == 0)
    return 0;

  coap_mutex_lock(&m_io_threads);
  /* Need to make sure it is non zero incase coap_log*() is called */
  if (thread_no == 0) {
    thread_no = ++max_thread_no;
  }
#ifdef _WIN32
  old_sigint_handler = signal(COAP_THREAD_KILL_SIG, coap_thread_sigint_handler);
#else /* ! _WIN32 */
  struct sigaction oldact;
  struct sigaction newact;

  /* Get the old handler / action */
  if (sigaction(COAP_THREAD_KILL_SIG, NULL, &oldact) != -1) {
    if (oldact.sa_flags & SA_SIGINFO) {
      if (oldact.sa_sigaction != coap_thread_sigint_action) {
        memset(&newact, 0, sizeof(newact));
        sigemptyset(&newact.sa_mask);
        newact.sa_sigaction = coap_thread_sigint_action;
        newact.sa_flags = SA_SIGINFO;
        if (sigaction(COAP_THREAD_KILL_SIG, &newact, &oldact) != -1) {
          old_sigint_action = oldact.sa_sigaction;
        }
      }
    } else {
      if (oldact.sa_handler != coap_thread_sigint_handler) {
        memset(&newact, 0, sizeof(newact));
        sigemptyset(&newact.sa_mask);
        newact.sa_handler = coap_thread_sigint_handler;
        newact.sa_flags = 0;
        if (sigaction(COAP_THREAD_KILL_SIG, &newact, &oldact) != -1) {
          old_sigint_handler = oldact.sa_handler;
        }
      }
    }
  }
#endif /* ! _WIN32 */

  if (context->thread_id_count) {
    coap_io_process_kill_threads(context);
  }

  base_thread = max_thread_no + 1;
  max_thread_no = base_thread + thread_count - 1;
  context->thread_id = coap_malloc_type(COAP_STRING, thread_count * sizeof(pthread_t));
  if (!context->thread_id) {
    coap_log_err("thread start up memory allocate failure\n");
    coap_mutex_unlock(&m_io_threads);
    return 0;
  }
  for (i = 0; i < thread_count ; i++) {
    coap_thread_param_t *thread_param = coap_malloc_type(COAP_STRING, sizeof(coap_thread_param_t));
    int s;

    thread_param->context = context;
    thread_param->thread_no = i + base_thread;
    s = pthread_create(&context->thread_id[i], NULL,
                       &coap_io_process_worker_thread, thread_param);
    if (s != 0) {
      coap_log_err("thread start up failure (%s)\n", coap_socket_strerror());
      coap_mutex_unlock(&m_io_threads);
      return 0;
    }
    context->thread_id_count++;
  }
  coap_mutex_unlock(&m_io_threads);
  return 1;
}

COAP_API void
coap_io_process_remove_threads(coap_context_t *context) {
  coap_lock_lock();
  coap_io_process_remove_threads_lkd(context);
  coap_lock_unlock();
}

void
coap_io_process_remove_threads_lkd(coap_context_t *context) {
  coap_lock_unlock();
  coap_mutex_lock(&m_io_threads);
  /* Need to make sure it is non zero incase coap_log*() is called */
  if (thread_no == 0) {
    thread_no = ++max_thread_no;
  }

  if (context->thread_id_count) {
    coap_io_process_kill_threads(context);
  }

  coap_mutex_unlock(&m_io_threads);
  coap_lock_lock(return);
}
#endif /* !WITH_LWIP */

#else /* ! COAP_THREAD_SAFE */

int
coap_io_process_configure_threads(coap_context_t *context, uint32_t thread_count) {
  (void)context;
  (void)thread_count;
  return 0;
}

void
coap_io_process_remove_threads(coap_context_t *context) {
  (void)context;
}

#endif /* ! COAP_THREAD_SAFE */
