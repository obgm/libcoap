/* coap_io_posix.c -- Network I/O functions for libcoap using Posix
 *
 * Copyright (C) 2012,2014,2016-2025 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file coap_io_posix.c
 * @brief Posix specific Network I/O functions
 */

#include "coap3/coap_libcoap_build.h"

#if ! defined(WITH_LWIP) && ! defined(WITH_CONTIKI) && ! defined (RIOT_VERSION)

#ifdef HAVE_STDIO_H
#  include <stdio.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifndef __ZEPHYR__
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_SYS_UIO_H
# include <sys/uio.h>
#endif
#ifdef _WIN32
#include <stdio.h>
#endif /* _WIN32 */
#if COAP_EPOLL_SUPPORT
#include <sys/epoll.h>
#include <sys/timerfd.h>
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#endif /* COAP_EPOLL_SUPPORT */
#else /* __ZEPHYR__ */
#include <sys/ioctl.h>
#include <sys/select.h>
#endif /* __ZEPHYR__ */

#if COAP_EPOLL_SUPPORT
void
coap_epoll_ctl_add(coap_socket_t *sock,
                   uint32_t events,
                   const char *func) {
  int ret;
  struct epoll_event event;
  coap_context_t *context;

#if COAP_MAX_LOGGING_LEVEL < _COAP_LOG_ERR
  (void)func;
#endif

  if (sock == NULL)
    return;

#if COAP_SERVER_SUPPORT
  context = sock->session ? sock->session->context :
            sock->endpoint ? sock->endpoint->context : NULL;
#else /* ! COAP_SERVER_SUPPORT */
  context = sock->session ? sock->session->context : NULL;
#endif /* ! COAP_SERVER_SUPPORT */
  if (context == NULL)
    return;

  /* Needed if running 32bit as ptr is only 32bit */
  memset(&event, 0, sizeof(event));
  event.events = events;
  event.data.ptr = sock;

  ret = epoll_ctl(context->epfd, EPOLL_CTL_ADD, sock->fd, &event);
  if (ret == -1) {
    coap_log_err("%s: epoll_ctl ADD failed: %s (%d)\n",
                 func,
                 coap_socket_strerror(), errno);
  }
}

void
coap_epoll_ctl_mod(coap_socket_t *sock,
                   uint32_t events,
                   const char *func) {
  int ret;
  struct epoll_event event;
  coap_context_t *context;

#if COAP_MAX_LOGGING_LEVEL < _COAP_LOG_ERR
  (void)func;
#endif

  if (sock == NULL)
    return;

#if COAP_SERVER_SUPPORT
  context = sock->session ? sock->session->context :
            sock->endpoint ? sock->endpoint->context : NULL;
#else /* COAP_SERVER_SUPPORT */
  context = sock->session ? sock->session->context : NULL;
#endif /* COAP_SERVER_SUPPORT */
  if (context == NULL)
    return;

  event.events = events;
  event.data.ptr = sock;

  ret = epoll_ctl(context->epfd, EPOLL_CTL_MOD, sock->fd, &event);
  if (ret == -1) {
#if (COAP_MAX_LOGGING_LEVEL < COAP_LOG_ERR)
    (void)func;
#endif
    coap_log_err("%s: epoll_ctl MOD failed: %s (%d)\n",
                 func,
                 coap_socket_strerror(), errno);
  }
}
#endif /* COAP_EPOLL_SUPPORT */

COAP_API int
coap_io_process(coap_context_t *ctx, uint32_t timeout_ms) {
  int ret;

  coap_lock_lock(return 0);
  ret = coap_io_process_lkd(ctx, timeout_ms);
  coap_lock_unlock();
  return ret;
}

int
coap_io_process_lkd(coap_context_t *ctx, uint32_t timeout_ms) {
  return coap_io_process_with_fds_lkd(ctx, timeout_ms, 0, NULL, NULL, NULL);
}

COAP_API int
coap_io_process_with_fds(coap_context_t *ctx, uint32_t timeout_ms,
                         int enfds, fd_set *ereadfds, fd_set *ewritefds,
                         fd_set *eexceptfds) {
  int ret;

  coap_lock_lock(return 0);
  ret = coap_io_process_with_fds_lkd(ctx, timeout_ms, enfds, ereadfds, ewritefds,
                                     eexceptfds);
  coap_lock_unlock();
  return ret;
}

#if ! COAP_EPOLL_SUPPORT && COAP_THREAD_SAFE
static unsigned int
coap_io_prepare_fds(coap_context_t *ctx,
                    int enfds, fd_set *ereadfds, fd_set *ewritefds,
                    fd_set *eexceptfds) {
  coap_session_t *s, *stmp;
  unsigned int max_sockets = sizeof(ctx->sockets) / sizeof(ctx->sockets[0]);
  coap_fd_t nfds = 0;
  unsigned int i;

  ctx->num_sockets = 0;
#if COAP_SERVER_SUPPORT
  coap_endpoint_t *ep;

  LL_FOREACH(ctx->endpoint, ep) {
    if (ep->sock.flags & (COAP_SOCKET_WANT_READ | COAP_SOCKET_WANT_WRITE | COAP_SOCKET_WANT_ACCEPT)) {
      if (ctx->num_sockets < max_sockets)
        ctx->sockets[ctx->num_sockets++] = &ep->sock;
    }
    SESSIONS_ITER(ep->sessions, s, stmp) {
      if (s->sock.flags & (COAP_SOCKET_WANT_READ|COAP_SOCKET_WANT_WRITE)) {
        if (ctx->num_sockets < max_sockets)
          ctx->sockets[ctx->num_sockets++] = &s->sock;
      }
    }
  }
#endif /* COAP_SERVER_SUPPORT */
#if COAP_CLIENT_SUPPORT
  SESSIONS_ITER(ctx->sessions, s, stmp) {
    if (s->sock.flags & (COAP_SOCKET_WANT_READ |
                         COAP_SOCKET_WANT_WRITE |
                         COAP_SOCKET_WANT_CONNECT)) {
      if (ctx->num_sockets < max_sockets)
        ctx->sockets[ctx->num_sockets++] = &s->sock;
    }
  }
#endif /* COAP_CLIENT_SUPPORT */
  if (ereadfds) {
    ctx->readfds = *ereadfds;
    nfds = enfds;
  } else {
    FD_ZERO(&ctx->readfds);
  }
  if (ewritefds) {
    ctx->writefds = *ewritefds;
    nfds = enfds;
  } else {
    FD_ZERO(&ctx->writefds);
  }
  if (eexceptfds) {
    ctx->exceptfds = *eexceptfds;
    nfds = enfds;
  } else {
    FD_ZERO(&ctx->exceptfds);
  }
  for (i = 0; i < ctx->num_sockets; i++) {
    if (ctx->sockets[i]->fd + 1 > nfds)
      nfds = ctx->sockets[i]->fd + 1;
    if (ctx->sockets[i]->flags & COAP_SOCKET_WANT_READ)
      FD_SET(ctx->sockets[i]->fd, &ctx->readfds);
    if (ctx->sockets[i]->flags & COAP_SOCKET_WANT_WRITE)
      FD_SET(ctx->sockets[i]->fd, &ctx->writefds);
#if !COAP_DISABLE_TCP
    if (ctx->sockets[i]->flags & COAP_SOCKET_WANT_ACCEPT)
      FD_SET(ctx->sockets[i]->fd, &ctx->readfds);
    if (ctx->sockets[i]->flags & COAP_SOCKET_WANT_CONNECT) {
      FD_SET(ctx->sockets[i]->fd, &ctx->writefds);
      FD_SET(ctx->sockets[i]->fd, &ctx->exceptfds);
    }
#endif /* !COAP_DISABLE_TCP */
  }
  return nfds;
}
#endif /* ! COAP_EPOLL_SUPPORT && COAP_THREAD_SAFE */

int
coap_io_process_with_fds_lkd(coap_context_t *ctx, uint32_t timeout_ms,
                             int enfds, fd_set *ereadfds, fd_set *ewritefds,
                             fd_set *eexceptfds) {
  coap_fd_t nfds = 0;
  coap_tick_t before, now;
  unsigned int timeout;
#if ! COAP_EPOLL_SUPPORT
  struct timeval tv;
  int result;
  unsigned int i;
#endif /* ! COAP_EPOLL_SUPPORT */

  coap_lock_check_locked();
  coap_ticks(&before);

#if ! COAP_EPOLL_SUPPORT

  timeout = coap_io_prepare_io_lkd(ctx, ctx->sockets,
                                   (sizeof(ctx->sockets) / sizeof(ctx->sockets[0])),
                                   &ctx->num_sockets, before);
  ctx->next_timeout = timeout ? timeout + before : 0;

  if (ereadfds) {
    ctx->readfds = *ereadfds;
    nfds = enfds;
  } else {
    FD_ZERO(&ctx->readfds);
  }
  if (ewritefds) {
    ctx->writefds = *ewritefds;
    nfds = enfds;
  } else {
    FD_ZERO(&ctx->writefds);
  }
  if (eexceptfds) {
    ctx->exceptfds = *eexceptfds;
    nfds = enfds;
  } else {
    FD_ZERO(&ctx->exceptfds);
  }
  for (i = 0; i < ctx->num_sockets; i++) {
    if (ctx->sockets[i]->fd + 1 > nfds)
      nfds = ctx->sockets[i]->fd + 1;
    if (ctx->sockets[i]->flags & COAP_SOCKET_WANT_READ)
      FD_SET(ctx->sockets[i]->fd, &ctx->readfds);
    if (ctx->sockets[i]->flags & COAP_SOCKET_WANT_WRITE)
      FD_SET(ctx->sockets[i]->fd, &ctx->writefds);
#if !COAP_DISABLE_TCP
    if (ctx->sockets[i]->flags & COAP_SOCKET_WANT_ACCEPT)
      FD_SET(ctx->sockets[i]->fd, &ctx->readfds);
    if (ctx->sockets[i]->flags & COAP_SOCKET_WANT_CONNECT) {
      FD_SET(ctx->sockets[i]->fd, &ctx->writefds);
      FD_SET(ctx->sockets[i]->fd, &ctx->exceptfds);
    }
#endif /* !COAP_DISABLE_TCP */
  }

  if (timeout_ms == COAP_IO_NO_WAIT) {
    tv.tv_usec = 0;
    tv.tv_sec = 0;
    timeout = 1;
  } else if (timeout == 0 && timeout_ms == COAP_IO_WAIT) {
    ;
  } else {
    if (timeout == 0 || (timeout_ms != COAP_IO_WAIT && timeout_ms < timeout))
      timeout = timeout_ms;
    tv.tv_usec = (timeout % 1000) * 1000;
    tv.tv_sec = (long)(timeout / 1000);
  }

  /* on Windows select will return an error if called without FDs */
  if (nfds > 0) {
    /* Unlock so that other threads can lock/update ctx */
    coap_lock_unlock();

    result = select((int)nfds, &ctx->readfds, &ctx->writefds, &ctx->exceptfds,
                    timeout > 0 ? &tv : NULL);

    coap_lock_lock(return -1);
  } else {
    goto all_over;
  }

  if (result < 0) {   /* error */
#ifdef _WIN32
    coap_win_error_to_errno();
#endif
    if (errno != EINTR) {
#if COAP_THREAD_SAFE
      if (errno == EBADF) {
        coap_log_debug("select: %s\n", coap_socket_strerror());
        goto all_over;
      }
#endif /* COAP_THREAD_SAFE */
      coap_log_err("select: %s\n", coap_socket_strerror());
      return -1;
    }
    goto all_over;
  }
#if COAP_THREAD_SAFE
  /* Need to refresh what is available to read / write etc. */
  nfds = coap_io_prepare_fds(ctx, enfds, ereadfds, ewritefds, eexceptfds);
  tv.tv_usec = 0;
  tv.tv_sec = 0;
  result = select((int)nfds, &ctx->readfds, &ctx->writefds, &ctx->exceptfds, &tv);
  if (result < 0) {   /* error */
#ifdef _WIN32
    coap_win_error_to_errno();
#endif
    if (errno != EINTR) {
      if (errno == EBADF) {
        coap_log_debug("select: %s\n", coap_socket_strerror());
        goto all_over;
      }
      coap_log_err("select: %s\n", coap_socket_strerror());
      return -1;
    }
    goto all_over;
  }
#endif /* COAP_THREAD_SAFE */
  if (ereadfds) {
    *ereadfds = ctx->readfds;
  }
  if (ewritefds) {
    *ewritefds = ctx->writefds;
  }
  if (eexceptfds) {
    *eexceptfds = ctx->exceptfds;
  }

  if (result > 0) {
    for (i = 0; i < ctx->num_sockets; i++) {
      if ((ctx->sockets[i]->flags & COAP_SOCKET_WANT_READ) &&
          FD_ISSET(ctx->sockets[i]->fd, &ctx->readfds))
        ctx->sockets[i]->flags |= COAP_SOCKET_CAN_READ;
#if !COAP_DISABLE_TCP
      if ((ctx->sockets[i]->flags & COAP_SOCKET_WANT_ACCEPT) &&
          FD_ISSET(ctx->sockets[i]->fd, &ctx->readfds))
        ctx->sockets[i]->flags |= COAP_SOCKET_CAN_ACCEPT;
      if ((ctx->sockets[i]->flags & COAP_SOCKET_WANT_WRITE) &&
          FD_ISSET(ctx->sockets[i]->fd, &ctx->writefds))
        ctx->sockets[i]->flags |= COAP_SOCKET_CAN_WRITE;
      if ((ctx->sockets[i]->flags & COAP_SOCKET_WANT_CONNECT) &&
          (FD_ISSET(ctx->sockets[i]->fd, &ctx->writefds) ||
           FD_ISSET(ctx->sockets[i]->fd, &ctx->exceptfds)))
        ctx->sockets[i]->flags |= COAP_SOCKET_CAN_CONNECT;
#endif /* !COAP_DISABLE_TCP */
    }
  }

  coap_ticks(&now);
  coap_io_do_io_lkd(ctx, now);
  coap_ticks(&now);
  timeout = coap_io_prepare_io_lkd(ctx, ctx->sockets,
                                   (sizeof(ctx->sockets) / sizeof(ctx->sockets[0])),
                                   &ctx->num_sockets, now);
  ctx->next_timeout = timeout ? timeout + now : 0;

#else /* COAP_EPOLL_SUPPORT */
  (void)ereadfds;
  (void)ewritefds;
  (void)eexceptfds;
  (void)enfds;

  timeout = coap_io_prepare_epoll_lkd(ctx, before);

  do {
    struct epoll_event events[COAP_MAX_EPOLL_EVENTS];
    int etimeout;

    /* Potentially adjust based on what the caller wants */
    if (timeout_ms == COAP_IO_NO_WAIT) {
      /* Need to return immediately from epoll_wait() */
      etimeout = 0;
    } else if (timeout == 0 && timeout_ms == COAP_IO_WAIT) {
      /*
       * Nothing found in coap_io_prepare_epoll_lkd() and COAP_IO_WAIT set,
       * so wait forever in epoll_wait().
       */
      etimeout = -1;
    } else {
      etimeout = timeout;
      if (timeout == 0 || (timeout_ms != COAP_IO_WAIT && timeout_ms < timeout))
        etimeout = timeout_ms;
      if (etimeout < 0) {
        /*
         * If timeout > INT_MAX, epoll_wait() cannot wait longer than this as
         * it has int timeout parameter
         */
        etimeout = INT_MAX;
      }
    }

    /* Unlock so that other threads can lock/update ctx */
    coap_lock_unlock();

    nfds = epoll_wait(ctx->epfd, events, COAP_MAX_EPOLL_EVENTS, etimeout);
    if (nfds < 0) {
      if (errno != EINTR) {
        coap_log_err("epoll_wait: unexpected error: %s (%d)\n",
                     coap_socket_strerror(), nfds);
      }
      coap_lock_lock(return -1);
      break;
    }

    coap_lock_lock(return -1);
#if COAP_THREAD_SAFE
    /* Need to refresh what is available to read / write etc. */
    nfds = epoll_wait(ctx->epfd, events, COAP_MAX_EPOLL_EVENTS, 0);
    if (nfds < 0) {
      if (errno != EINTR) {
        coap_log_err("epoll_wait: unexpected error: %s (%d)\n",
                     coap_socket_strerror(), nfds);
      }
      break;
    }
#endif /* COAP_THREAD_SAFE */

    coap_io_do_epoll_lkd(ctx, events, nfds);

    /*
     * reset to COAP_IO_NO_WAIT (which causes etimeout to become 0)
     * incase we have to do another iteration
     * (COAP_MAX_EPOLL_EVENTS insufficient)
     */
    timeout_ms = COAP_IO_NO_WAIT;

    /* Keep retrying until less than COAP_MAX_EPOLL_EVENTS are returned */
  } while (nfds == COAP_MAX_EPOLL_EVENTS);

#endif /* COAP_EPOLL_SUPPORT */
#if COAP_SERVER_SUPPORT
  coap_expire_cache_entries(ctx);
#endif /* COAP_SERVER_SUPPORT */
#if COAP_ASYNC_SUPPORT
  /* Check to see if we need to send off any Async requests as delay might
     have been updated */
  coap_ticks(&now);
  coap_check_async(ctx, now, NULL);
#endif /* COAP_ASYNC_SUPPORT */

#if ! COAP_EPOLL_SUPPORT
all_over:
#endif /* COAP_EPOLL_SUPPORT */
  coap_ticks(&now);
  return (int)(((now - before) * 1000) / COAP_TICKS_PER_SECOND);
}

volatile int coap_thread_quit = 0;

void
coap_io_process_terminate_loop(void) {
  coap_send_recv_terminate();
  coap_thread_quit = 1;
}

COAP_API int
coap_io_process_loop(coap_context_t *context,
                     coap_io_process_thread_t main_loop_code,
                     void *main_loop_code_arg, uint32_t timeout_ms,
                     uint32_t thread_count) {
  int ret;

  if (!context)
    return 0;
  coap_lock_lock(return 0);
  ret = coap_io_process_loop_lkd(context, main_loop_code,
                                 main_loop_code_arg, timeout_ms,
                                 thread_count);
  coap_lock_unlock();
  return ret;
}

int
coap_io_process_loop_lkd(coap_context_t *context,
                         coap_io_process_thread_t main_loop_code,
                         void *main_loop_code_arg, uint32_t timeout_ms,
                         uint32_t thread_count) {
  int ret = 0;;

#if COAP_THREAD_SAFE
  if (thread_count > 1) {
    if (!coap_io_process_configure_threads(context, thread_count - 1))
      return 0;
  }
#else /* COAP_THREAD_SAFE */
  thread_count = 1;
#endif /* COAP_THREAD_SAFE */
  while (!coap_thread_quit) {
    if (main_loop_code) {
      coap_tick_t begin, end;
      uint32_t used_ms;

      coap_ticks(&begin);
      /*
       * main_loop_codecode should not be blocking for any time, and not calling
       * coap_io_process().
       */
      coap_lock_callback_release(main_loop_code(main_loop_code_arg),
                                 /* On re-lock failure */
                                 ret = 0; break);
      /*
       * Need to delay for the remainder of timeout_ms. In case main_loop_code()
       * is time sensitive (e.g Observe subscription to /time), delay to the
       * start of the a second boundary
       */
      coap_ticks(&end);
      used_ms = (uint32_t)(end - begin) * 1000 / COAP_TICKS_PER_SECOND;
      if (timeout_ms == COAP_IO_NO_WAIT || timeout_ms == COAP_IO_WAIT) {
        ret = coap_io_process_lkd(context, timeout_ms);
      } else if (timeout_ms > used_ms) {
        /* Wait for remaining time rounded up to next second start */
        coap_tick_t next_time = end + (timeout_ms - used_ms) * COAP_TICKS_PER_SECOND / 1000;
        unsigned int next_sec_us;
        unsigned int next_sec_ms;

        next_sec_us = (timeout_ms - used_ms) * 1000000 / COAP_TICKS_PER_SECOND + 1000000 -
                      (coap_ticks_to_rt_us(next_time) % 1000000);
        next_sec_ms = (next_sec_us + 999) / 1000;
        if (next_sec_ms > timeout_ms && next_sec_ms > 1000)
          next_sec_ms -= 1000;
        ret = coap_io_process_lkd(context, next_sec_ms ? next_sec_ms : 1);
      } else {
        /* timeout_ms has expired */
        ret = coap_io_process_lkd(context, COAP_IO_NO_WAIT);
      }

      if (thread_count == 1) {
        /*
         * Need to delay if only one thread until the remainder of
         * timeout_ms is used up.  Otherwise, another thread will be
         * waiting on coap_io_process() to do any input / timeout work.
         */
        coap_ticks(&end);
        used_ms = (uint32_t)(end - begin) * 1000 / COAP_TICKS_PER_SECOND;
        if (timeout_ms > 0 && timeout_ms < used_ms) {
          ret = coap_io_process_lkd(context, used_ms - timeout_ms);
        } else {
          ret = coap_io_process_lkd(context, COAP_IO_NO_WAIT);
        }
      }
    } else {
      ret = coap_io_process_lkd(context, timeout_ms);
    }
    /* coap_io_process_lkd() can return 0 */
    if (ret >= 0)
      ret = 1;

    if (ret < 0) {
      ret = 0;
      break;
    }
  }
#if COAP_THREAD_SAFE
  coap_io_process_remove_threads(context);
#endif /* COAP_THREAD_SAFE */
  coap_thread_quit = 0;
  return ret;
}

#else /* WITH_LWIP || WITH_CONTIKI || RIOT_VERSION */

#ifdef __clang__
/* Make compilers happy that do not like empty modules. As this function is
 * never used, we ignore -Wunused-function at the end of compiling this file
 */
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
static inline void
dummy(void) {
}

#endif /* WITH_LWIP || WITH_CONTIKI || RIOT_VERSION */
