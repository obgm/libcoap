/* coap_io.c -- Default network I/O functions for libcoap
 *
 * Copyright (C) 2012,2014,2016-2025 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file coap_io.c
 * @brief Network I/O functions
 */

#include "coap3/coap_libcoap_build.h"

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
#ifdef COAP_EPOLL_SUPPORT
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

#if COAP_SERVER_SUPPORT
coap_endpoint_t *
coap_malloc_endpoint(void) {
  return (coap_endpoint_t *)coap_malloc_type(COAP_ENDPOINT, sizeof(coap_endpoint_t));
}

void
coap_mfree_endpoint(coap_endpoint_t *ep) {
  coap_free_type(COAP_ENDPOINT, ep);
}
#endif /* COAP_SERVER_SUPPORT */

#ifndef WITH_CONTIKI
void
coap_update_io_timer(coap_context_t *context, coap_tick_t delay) {
#if COAP_EPOLL_SUPPORT
  if (context->eptimerfd != -1) {
    coap_tick_t now;

    coap_ticks(&now);
    if (context->next_timeout == 0 || context->next_timeout > now + delay) {
      struct itimerspec new_value;
      int ret;

      context->next_timeout = now + delay;
      memset(&new_value, 0, sizeof(new_value));
      if (delay == 0) {
        new_value.it_value.tv_nsec = 1; /* small but not zero */
      } else {
        new_value.it_value.tv_sec = delay / COAP_TICKS_PER_SECOND;
        new_value.it_value.tv_nsec = (delay % COAP_TICKS_PER_SECOND) *
                                     1000000;
      }
      ret = timerfd_settime(context->eptimerfd, 0, &new_value, NULL);
      if (ret == -1) {
        coap_log_err("%s: timerfd_settime failed: %s (%d)\n",
                     "coap_update_io_timer",
                     coap_socket_strerror(), errno);
      }
#ifdef COAP_DEBUG_WAKEUP_TIMES
      else {
        coap_log_debug("****** Next wakeup time %3ld.%09ld\n",
                       new_value.it_value.tv_sec, new_value.it_value.tv_nsec);
      }
#endif /* COAP_DEBUG_WAKEUP_TIMES */
    }
  }
#else /* ! COAP_EPOLL_SUPPORT */
  coap_tick_t now;

  coap_ticks(&now);
  if (context->next_timeout == 0 || context->next_timeout > now + delay) {
    context->next_timeout = now + delay;
  }
#endif /* ! COAP_EPOLL_SUPPORT */
}
#endif /* ! WITH_CONTIKI */

#ifdef _WIN32
void
coap_win_error_to_errno(void) {
  int w_error = WSAGetLastError();
  switch (w_error) {
  case WSA_NOT_ENOUGH_MEMORY:
    errno = ENOMEM;
    break;
  case WSA_INVALID_PARAMETER:
    errno = EINVAL;
    break;
  case WSAEINTR:
    errno = EINTR;
    break;
  case WSAEBADF:
    errno = EBADF;
    break;
  case WSAEACCES:
    errno = EACCES;
    break;
  case WSAEFAULT:
    errno = EFAULT;
    break;
  case WSAEINVAL:
    errno = EINVAL;
    break;
  case WSAEMFILE:
    errno = EMFILE;
    break;
  case WSAEWOULDBLOCK:
    errno = EWOULDBLOCK;
    break;
  case WSAENETDOWN:
    errno = ENETDOWN;
    break;
  case WSAENETUNREACH:
    errno = ENETUNREACH;
    break;
  case WSAENETRESET:
    errno = ENETRESET;
    break;
  case WSAECONNABORTED:
    errno = ECONNABORTED;
    break;
  case WSAECONNRESET:
    errno = ECONNRESET;
    break;
  case WSAENOBUFS:
    errno = ENOBUFS;
    break;
  case WSAETIMEDOUT:
    errno = ETIMEDOUT;
    break;
  case WSAECONNREFUSED:
    errno = ECONNREFUSED;
    break;
  case WSAEADDRNOTAVAIL:
    errno = EADDRNOTAVAIL;
    break;
  default:
    coap_log_err("WSAGetLastError: %d mapping to errno failed - please fix\n",
                 w_error);
    errno = EPERM;
    break;
  }
}
#endif /* _WIN32 */

#if !defined(WITH_LWIP) && !defined(__ZEPHYR__)
#if (!defined(WITH_CONTIKI)) != ( defined(HAVE_NETINET_IN_H) || defined(HAVE_WS2TCPIP_H) )
/* define struct in6_pktinfo and struct in_pktinfo if not available
   FIXME: check with configure
*/
#if !defined(__MINGW32__) && !defined(RIOT_VERSION)
struct in6_pktinfo {
  struct in6_addr ipi6_addr;        /* src/dst IPv6 address */
  unsigned int ipi6_ifindex;        /* send/recv interface index */
};

struct in_pktinfo {
  int ipi_ifindex;
  struct in_addr ipi_spec_dst;
  struct in_addr ipi_addr;
};
#endif /* ! __MINGW32__ && ! RIOT_VERSION */
#endif
#endif /* ! WITH_LWIP && ! __ZEPHYR__ */

void
coap_packet_get_memmapped(coap_packet_t *packet, unsigned char **address, size_t *length) {
  *address = packet->payload;
  *length = packet->length;
}

COAP_API unsigned int
coap_io_prepare_epoll(coap_context_t *ctx, coap_tick_t now) {
  unsigned int ret;

  coap_lock_lock(return 0);
  ret = coap_io_prepare_epoll_lkd(ctx, now);
  coap_lock_unlock();
  return ret;
}

unsigned int
coap_io_prepare_epoll_lkd(coap_context_t *ctx, coap_tick_t now) {
#ifndef COAP_EPOLL_SUPPORT
  (void)ctx;
  (void)now;
  coap_log_emerg("coap_io_prepare_epoll() requires libcoap compiled for using epoll\n");
  return 0;
#else /* COAP_EPOLL_SUPPORT */
  coap_socket_t *sockets[1];
  unsigned int max_sockets = sizeof(sockets)/sizeof(sockets[0]);
  unsigned int num_sockets;
  unsigned int timeout;

  coap_lock_check_locked();
  /* Use the common logic */
  timeout = coap_io_prepare_io_lkd(ctx, sockets, max_sockets, &num_sockets, now);
  /* Save when the next expected I/O is to take place */
  ctx->next_timeout = timeout ? now + timeout : 0;
  if (ctx->eptimerfd != -1) {
    struct itimerspec new_value;
    int ret;

    memset(&new_value, 0, sizeof(new_value));
    coap_ticks(&now);
    if (ctx->next_timeout != 0 && ctx->next_timeout > now) {
      coap_tick_t rem_timeout = ctx->next_timeout - now;
      /* Need to trigger an event on ctx->eptimerfd in the future */
      new_value.it_value.tv_sec = rem_timeout / COAP_TICKS_PER_SECOND;
      new_value.it_value.tv_nsec = (rem_timeout % COAP_TICKS_PER_SECOND) *
                                   1000000;
    }
#ifdef COAP_DEBUG_WAKEUP_TIMES
    coap_log_debug("****** Next wakeup time %3ld.%09ld\n",
                   new_value.it_value.tv_sec, new_value.it_value.tv_nsec);
#endif /* COAP_DEBUG_WAKEUP_TIMES */
    /* reset, or specify a future time for eptimerfd to trigger */
    ret = timerfd_settime(ctx->eptimerfd, 0, &new_value, NULL);
    if (ret == -1) {
      coap_log_err("%s: timerfd_settime failed: %s (%d)\n",
                   "coap_io_prepare_epoll",
                   coap_socket_strerror(), errno);
    }
  }
  return timeout;
#endif /* COAP_EPOLL_SUPPORT */
}

/*
 * return  0 No i/o pending
 *       +ve millisecs to next i/o activity
 */
COAP_API unsigned int
coap_io_prepare_io(coap_context_t *ctx,
                   coap_socket_t *sockets[],
                   unsigned int max_sockets,
                   unsigned int *num_sockets,
                   coap_tick_t now) {
  unsigned int ret;

  coap_lock_lock(return 0);
  ret = coap_io_prepare_io_lkd(ctx, sockets, max_sockets, num_sockets, now);
  coap_lock_unlock();
  return ret;
}

/*
 * return  0 No i/o pending
 *       +ve millisecs to next i/o activity
 */
unsigned int
coap_io_prepare_io_lkd(coap_context_t *ctx,
                       coap_socket_t *sockets[],
                       unsigned int max_sockets,
                       unsigned int *num_sockets,
                       coap_tick_t now) {
  coap_queue_t *nextpdu;
  coap_session_t *s, *stmp;
  coap_tick_t timeout = COAP_MAX_DELAY_TICKS;
  coap_tick_t s_timeout;
#if COAP_SERVER_SUPPORT
  int check_dtls_timeouts = 0;
#endif /* COAP_SERVER_SUPPORT */
#if defined(COAP_EPOLL_SUPPORT) || defined(WITH_LWIP) || defined(RIOT_VERSION)
  (void)sockets;
  (void)max_sockets;
#endif /* COAP_EPOLL_SUPPORT || WITH_LWIP || RIOT_VERSION*/

  coap_lock_check_locked();
  *num_sockets = 0;

#if COAP_SERVER_SUPPORT
  /* Check to see if we need to send off any Observe requests */
  coap_check_notify_lkd(ctx);

#if COAP_ASYNC_SUPPORT
  /* Check to see if we need to send off any Async requests */
  if (coap_check_async(ctx, now, &s_timeout)) {
    if (s_timeout < timeout)
      timeout = s_timeout;
  }
#endif /* COAP_ASYNC_SUPPORT */
#endif /* COAP_SERVER_SUPPORT */

  /* Check to see if we need to send off any retransmit request */
  nextpdu = coap_peek_next(ctx);
  while (nextpdu && now >= ctx->sendqueue_basetime &&
         nextpdu->t <= now - ctx->sendqueue_basetime) {
    coap_retransmit(ctx, coap_pop_next(ctx));
    nextpdu = coap_peek_next(ctx);
  }
  if (nextpdu && now >= ctx->sendqueue_basetime &&
      (nextpdu->t - (now - ctx->sendqueue_basetime) < timeout))
    timeout = nextpdu->t - (now - ctx->sendqueue_basetime);

  /* Check for DTLS timeouts */
  if (ctx->dtls_context) {
    if (coap_dtls_is_context_timeout()) {
      coap_tick_t tls_timeout = coap_dtls_get_context_timeout(ctx->dtls_context);
      if (tls_timeout > 0) {
        if (tls_timeout < now + COAP_TICKS_PER_SECOND / 10)
          tls_timeout = now + COAP_TICKS_PER_SECOND / 10;
        coap_log_debug("** DTLS global timeout set to %dms\n",
                       (int)((tls_timeout - now) * 1000 / COAP_TICKS_PER_SECOND));
        if (tls_timeout - now < timeout)
          timeout = tls_timeout - now;
      }
#if COAP_SERVER_SUPPORT
    } else {
      check_dtls_timeouts = 1;
#endif /* COAP_SERVER_SUPPORT */
    }
  }
#if COAP_PROXY_SUPPORT
  if (coap_proxy_check_timeouts(ctx, now, &s_timeout)) {
    if (s_timeout < timeout)
      timeout = s_timeout;
  }
#endif /* COAP_PROXY_SUPPORT */
#if COAP_SERVER_SUPPORT
  coap_endpoint_t *ep;
  coap_tick_t session_timeout;

  if (ctx->session_timeout > 0)
    session_timeout = ctx->session_timeout * COAP_TICKS_PER_SECOND;
  else
    session_timeout = COAP_DEFAULT_SESSION_TIMEOUT * COAP_TICKS_PER_SECOND;

  LL_FOREACH(ctx->endpoint, ep) {
#if !defined(COAP_EPOLL_SUPPORT) && !defined(WITH_LWIP) && !defined(RIOT_VERSION)
    if (ep->sock.flags & (COAP_SOCKET_WANT_READ | COAP_SOCKET_WANT_WRITE | COAP_SOCKET_WANT_ACCEPT)) {
      if (*num_sockets < max_sockets)
        sockets[(*num_sockets)++] = &ep->sock;
    }
#endif /* ! COAP_EPOLL_SUPPORT && ! WITH_LWIP && ! RIOT_VERSION */
    SESSIONS_ITER_SAFE(ep->sessions, s, stmp) {
      /* Check whether any idle server sessions should be released */
      if (s->type == COAP_SESSION_TYPE_SERVER && s->ref == 0 &&
          s->delayqueue == NULL &&
          (s->last_rx_tx + session_timeout <= now ||
           s->state == COAP_SESSION_STATE_NONE)) {
        coap_handle_event_lkd(ctx, COAP_EVENT_SERVER_SESSION_DEL, s);
        coap_session_free(s);
        continue;
      } else {
        if (s->type == COAP_SESSION_TYPE_SERVER && s->ref == 0 &&
            s->delayqueue == NULL) {
          /* Has to be positive based on if() above */
          s_timeout = (s->last_rx_tx + session_timeout) - now;
          if (s_timeout < timeout)
            timeout = s_timeout;
        }
        /* Make sure the session object is not deleted in any callbacks */
        coap_session_reference_lkd(s);
        /* Check any DTLS timeouts and expire if appropriate */
        if (check_dtls_timeouts && s->state == COAP_SESSION_STATE_HANDSHAKE &&
            s->proto == COAP_PROTO_DTLS && s->tls) {
          coap_tick_t tls_timeout = coap_dtls_get_timeout(s, now);
          while (tls_timeout > 0 && tls_timeout <= now) {
            coap_log_debug("** %s: DTLS retransmit timeout\n",
                           coap_session_str(s));
            if (coap_dtls_handle_timeout(s))
              goto release_1;

            if (s->tls)
              tls_timeout = coap_dtls_get_timeout(s, now);
            else {
              tls_timeout = 0;
              timeout = 1;
            }
          }
          if (tls_timeout > 0 && tls_timeout - now < timeout)
            timeout = tls_timeout - now;
        }
        /* Check if any server large receives are missing blocks */
        if (s->lg_srcv) {
          if (coap_block_check_lg_srcv_timeouts(s, now, &s_timeout)) {
            if (s_timeout < timeout)
              timeout = s_timeout;
          }
        }
        /* Check if any server large sending have timed out */
        if (s->lg_xmit) {
          if (coap_block_check_lg_xmit_timeouts(s, now, &s_timeout)) {
            if (s_timeout < timeout)
              timeout = s_timeout;
          }
        }
#if !defined(COAP_EPOLL_SUPPORT) && !defined(WITH_LWIP) && !defined(RIOT_VERSION)
        if (s->sock.flags & (COAP_SOCKET_WANT_READ|COAP_SOCKET_WANT_WRITE)) {
          if (*num_sockets < max_sockets && !(s->sock.flags & COAP_SOCKET_SLAVE))
            sockets[(*num_sockets)++] = &s->sock;
        }
#endif /* ! COAP_EPOLL_SUPPORT && ! WITH_LWIP && ! RIOT_VERSION */
#if COAP_Q_BLOCK_SUPPORT
        /*
         * Check if any server large transmits have hit MAX_PAYLOAD and need
         * restarting
         */
        if (s->lg_xmit) {
          if (coap_block_check_q_block2_xmit(s, now, &s_timeout)) {
            if (s_timeout < timeout)
              timeout = s_timeout;
          }
        }
#endif /* COAP_Q_BLOCK_SUPPORT */
release_1:
        coap_session_release_lkd(s);
      }
      if (s->type == COAP_SESSION_TYPE_SERVER &&
          s->state == COAP_SESSION_STATE_ESTABLISHED &&
          (s->ref_subscriptions || s->ref_proxy_subs) && !s->con_active &&
          ctx->ping_timeout > 0) {
        /* Only do this if this session is observing */
        if (s->last_rx_tx + ctx->ping_timeout * COAP_TICKS_PER_SECOND <= now) {
          /* Time to send a ping */
          coap_mid_t mid;

          if ((mid = coap_session_send_ping_lkd(s)) == COAP_INVALID_MID) {
            /* Some issue - not safe to continue processing */
            s->last_rx_tx = now;
            continue;
          }
          s->last_ping_mid = mid;
          if (s->last_ping > 0 && s->last_pong < s->last_ping) {
            coap_session_server_keepalive_failed(s);
            /* check the next session */
            continue;
          }
          s->last_rx_tx = now;
          s->last_ping = now;
        } else {
          /* Always positive due to if() above */
          s_timeout = (s->last_rx_tx + ctx->ping_timeout * COAP_TICKS_PER_SECOND) - now;
          if (s_timeout < timeout)
            timeout = s_timeout;
        }
      }
    }
  }
#endif /* COAP_SERVER_SUPPORT */
#if COAP_CLIENT_SUPPORT
  SESSIONS_ITER_SAFE(ctx->sessions, s, stmp) {
    if (s->type == COAP_SESSION_TYPE_CLIENT &&
        s->state == COAP_SESSION_STATE_ESTABLISHED && !s->con_active &&
        ctx->ping_timeout > 0) {
      if (s->last_rx_tx + ctx->ping_timeout * COAP_TICKS_PER_SECOND <= now) {
        /* Time to send a ping */
        coap_mid_t mid;

        if ((mid = coap_session_send_ping_lkd(s)) == COAP_INVALID_MID) {
          /* Some issue - not safe to continue processing */
          s->last_rx_tx = now;
          coap_session_failed(s);
          continue;
        }
        s->last_ping_mid = mid;
        if (s->last_ping > 0 && s->last_pong < s->last_ping) {
          coap_handle_event_lkd(s->context, COAP_EVENT_KEEPALIVE_FAILURE, s);
        }
        s->last_rx_tx = now;
        s->last_ping = now;
      } else {
        /* Always positive due to if() above */
        s_timeout = (s->last_rx_tx + ctx->ping_timeout * COAP_TICKS_PER_SECOND) - now;
        if (s_timeout < timeout)
          timeout = s_timeout;
      }
    }
    if (s->type == COAP_SESSION_TYPE_CLIENT &&
        s->session_failed && ctx->reconnect_time) {
      if (s->last_rx_tx + ctx->reconnect_time * COAP_TICKS_PER_SECOND <= now) {
        if (!coap_session_reconnect(s)) {
          /* server is not back up yet - delay retry a while */
          s->last_rx_tx = now;
          s_timeout = ctx->reconnect_time * COAP_TICKS_PER_SECOND;
          if (timeout == 0 || s_timeout < timeout)
            timeout = s_timeout;
        }
      } else {
        /* Always positive due to if() above */
        s_timeout = (s->last_rx_tx + ctx->reconnect_time * COAP_TICKS_PER_SECOND) - now;
        if (s_timeout < timeout)
          timeout = s_timeout;
      }
    }

#if !COAP_DISABLE_TCP
    if (s->type == COAP_SESSION_TYPE_CLIENT && COAP_PROTO_RELIABLE(s->proto) &&
        s->state == COAP_SESSION_STATE_CSM && ctx->csm_timeout_ms > 0) {
      if (s->csm_tx == 0) {
        s->csm_tx = now;
        s_timeout = (ctx->csm_timeout_ms * COAP_TICKS_PER_SECOND) / 1000;
      } else if (s->csm_tx + (ctx->csm_timeout_ms * COAP_TICKS_PER_SECOND) / 1000 <= now) {
        /* timed out - cannot handle 0, so has to be just +ve */
        s_timeout = 1;
      } else {
        s_timeout = (s->csm_tx + (ctx->csm_timeout_ms * COAP_TICKS_PER_SECOND) / 1000) - now;
      }
      if (s_timeout < timeout)
        timeout = s_timeout;
    }
#endif /* !COAP_DISABLE_TCP */

    /* Make sure the session object is not deleted in any callbacks */
    coap_session_reference_lkd(s);
    /* Check any DTLS timeouts and expire if appropriate */
    if (s->state == COAP_SESSION_STATE_HANDSHAKE &&
        s->proto == COAP_PROTO_DTLS && s->tls) {
      coap_tick_t tls_timeout = coap_dtls_get_timeout(s, now);
      while (tls_timeout > 0 && tls_timeout <= now) {
        coap_log_debug("** %s: DTLS retransmit timeout\n", coap_session_str(s));
        if (coap_dtls_handle_timeout(s))
          goto release_2;

        if (s->tls)
          tls_timeout = coap_dtls_get_timeout(s, now);
        else {
          tls_timeout = 0;
          timeout = 1;
        }
      }
      if (tls_timeout > 0 && tls_timeout - now < timeout)
        timeout = tls_timeout - now;
    }

    /* Check if any client large receives are missing blocks */
    if (s->lg_crcv) {
      if (coap_block_check_lg_crcv_timeouts(s, now, &s_timeout)) {
        if (s_timeout < timeout)
          timeout = s_timeout;
      }
    }
    /* Check if any client large sending have timed out */
    if (s->lg_xmit) {
      if (coap_block_check_lg_xmit_timeouts(s, now, &s_timeout)) {
        if (s_timeout < timeout)
          timeout = s_timeout;
      }
    }
#if COAP_Q_BLOCK_SUPPORT
    /*
     * Check if any client large transmits have hit MAX_PAYLOAD and need
     * restarting
     */
    if (s->lg_xmit) {
      if (coap_block_check_q_block1_xmit(s, now, &s_timeout)) {
        if (s_timeout < timeout)
          timeout = s_timeout;
      }
    }
#endif /* COAP_Q_BLOCK_SUPPORT */

#if !defined(COAP_EPOLL_SUPPORT) && !defined(WITH_LWIP) && !defined(RIOT_VERSION)
    assert(s->ref > 1);
    if (s->sock.flags & (COAP_SOCKET_WANT_READ |
                         COAP_SOCKET_WANT_WRITE |
                         COAP_SOCKET_WANT_CONNECT)) {
      if (*num_sockets < max_sockets && !(s->sock.flags & COAP_SOCKET_SLAVE))
        sockets[(*num_sockets)++] = &s->sock;
    }
#endif /* ! COAP_EPOLL_SUPPORT && ! WITH_LWIP && ! RIOT_VERSION */
release_2:
    coap_session_release_lkd(s);
  }
#endif /* COAP_CLIENT_SUPPORT */

  return (unsigned int)((timeout * 1000 + COAP_TICKS_PER_SECOND - 1) / COAP_TICKS_PER_SECOND);
}

/*
 * return  0 Insufficient space to hold fds, or fds not supported
 *         1 All fds found
 */
COAP_API unsigned int
coap_io_get_fds(coap_context_t *ctx,
                coap_fd_t read_fds[],
                unsigned int *have_read_fds,
                unsigned int max_read_fds,
                coap_fd_t write_fds[],
                unsigned int *have_write_fds,
                unsigned int max_write_fds,
                unsigned int *rem_timeout_ms) {
  unsigned int ret;

  coap_lock_lock(return 0);
  ret = coap_io_get_fds_lkd(ctx, read_fds, have_read_fds, max_read_fds, write_fds,
                            have_write_fds, max_write_fds, rem_timeout_ms);
  coap_lock_unlock();
  return ret;
}

#if !defined(WITH_LWIP) && !defined(WITH_CONTIKI)
static int
coap_add_fd(coap_fd_t fd, coap_fd_t this_fds[], unsigned int *have_this_fds,
            unsigned int max_this_fds) {
  if (*have_this_fds < max_this_fds) {
    this_fds[(*have_this_fds)++] = fd;
    return 1;
  }
  coap_log_warn("coap_io_get_fds: Insufficient space for new fd (%u >= %u)\n", *have_this_fds,
                max_this_fds);
  return 0;
}

/*
 * return  0 Insufficient space to hold fds, or fds not supported
 *         1 All fds found
 */
unsigned int
coap_io_get_fds_lkd(coap_context_t *ctx,
                    coap_fd_t read_fds[],
                    unsigned int *have_read_fds,
                    unsigned int max_read_fds,
                    coap_fd_t write_fds[],
                    unsigned int *have_write_fds,
                    unsigned int max_write_fds,
                    unsigned int *rem_timeout_ms) {
  *have_read_fds = 0;
  *have_write_fds = 0;

#ifdef COAP_EPOLL_SUPPORT
  (void)write_fds;
  (void)max_write_fds;;

  if (!coap_add_fd(ctx->epfd, read_fds, have_read_fds, max_read_fds))
    return 0;
  /* epoll is making use of timerfd, so no need to return any timeout */
  *rem_timeout_ms = 0;
  return 1;
#else /* ! COAP_EPOLL_SUPPORT */
  coap_session_t *s, *rtmp;
  coap_tick_t now;
  unsigned int timeout_ms;
#if COAP_SERVER_SUPPORT
  coap_endpoint_t *ep;

  LL_FOREACH(ctx->endpoint, ep) {
    if (ep->sock.flags & (COAP_SOCKET_WANT_READ | COAP_SOCKET_WANT_ACCEPT)) {
      if (!coap_add_fd(ep->sock.fd, read_fds, have_read_fds, max_read_fds))
        return 0;
    }
    if (ep->sock.flags & (COAP_SOCKET_WANT_WRITE | COAP_SOCKET_WANT_CONNECT)) {
      if (!coap_add_fd(ep->sock.fd, write_fds, have_write_fds, max_write_fds))
        return 0;
    }
    SESSIONS_ITER_SAFE(ep->sessions, s, rtmp) {
      if (s->sock.flags & (COAP_SOCKET_WANT_READ | COAP_SOCKET_WANT_ACCEPT)) {
        if (!coap_add_fd(s->sock.fd, read_fds, have_read_fds, max_read_fds))
          return 0;
      }
      if (s->sock.flags & (COAP_SOCKET_WANT_WRITE | COAP_SOCKET_WANT_CONNECT)) {
        if (!coap_add_fd(s->sock.fd, write_fds, have_write_fds, max_write_fds))
          return 0;
      }
    }
  }
#endif /* COAP_SERVER_SUPPORT */

#if COAP_CLIENT_SUPPORT
  SESSIONS_ITER_SAFE(ctx->sessions, s, rtmp) {
    if (s->sock.flags & (COAP_SOCKET_WANT_READ | COAP_SOCKET_WANT_ACCEPT)) {
      if (!coap_add_fd(s->sock.fd, read_fds, have_read_fds, max_read_fds))
        return 0;
    }
    if (s->sock.flags & (COAP_SOCKET_WANT_WRITE | COAP_SOCKET_WANT_CONNECT)) {
      if (!coap_add_fd(s->sock.fd, write_fds, have_write_fds, max_write_fds))
        return 0;
    }
  }
#endif /* COAP_CLIENT_SUPPORT */

  coap_ticks(&now);
  timeout_ms = (unsigned int)(ctx->next_timeout ? ctx->next_timeout > now ?
                              ctx->next_timeout - now : 0 : 0) *
               1000 / COAP_TICKS_PER_SECOND;
  *rem_timeout_ms = timeout_ms;
  return 1;
#endif /* ! COAP_EPOLL_SUPPORT */
}

#else /* WITH_LWIP || WITH_CONTIKI */

/*
 * return  0 Insufficient space to hold fds, or fds not supported
 *         1 All fds found
 */
unsigned int
coap_io_get_fds_lkd(coap_context_t *ctx,
                    coap_fd_t read_fds[],
                    unsigned int *have_read_fds,
                    unsigned int max_read_fds,
                    coap_fd_t write_fds[],
                    unsigned int *have_write_fds,
                    unsigned int max_write_fds,
                    unsigned int *rem_timeout_ms) {
  (void)ctx;
  (void)read_fds;
  (void)max_read_fds;
  (void)write_fds;
  (void)max_write_fds;

  *have_read_fds = 0;
  *have_write_fds = 0;
  *rem_timeout_ms = 0;

  coap_log_warn("coap_io_get_fds: Not supported\n");
  return 0;
}
#endif /* WITH_LWIP || WITH_CONTIKI */

COAP_API int
coap_io_pending(coap_context_t *context) {
  int ret;

  coap_lock_lock(return 0);
  ret = coap_io_pending_lkd(context);
  coap_lock_unlock();
  return ret;
}

/*
 * return 1  I/O pending
 *        0  No I/O pending
 */
int
coap_io_pending_lkd(coap_context_t *context) {
  coap_session_t *s, *rtmp;
#if COAP_SERVER_SUPPORT
  coap_endpoint_t *ep;
#endif /* COAP_SERVER_SUPPORT */

  if (!context)
    return 0;
  coap_lock_check_locked();
  if (coap_io_process_lkd(context, COAP_IO_NO_WAIT) < 0)
    return 0;

  if (context->sendqueue)
    return 1;
#if COAP_SERVER_SUPPORT
  LL_FOREACH(context->endpoint, ep) {
    SESSIONS_ITER(ep->sessions, s, rtmp) {
      if (s->delayqueue)
        return 1;
      if (s->lg_xmit)
        return 1;
      if (s->lg_srcv)
        return 1;
    }
  }
#endif /* COAP_SERVER_SUPPORT */
#if COAP_CLIENT_SUPPORT
  SESSIONS_ITER(context->sessions, s, rtmp) {
    if (s->delayqueue)
      return 1;
    if (s->lg_xmit)
      return 1;
    if (s->lg_crcv)
      return 1;
  }
#endif /* COAP_CLIENT_SUPPORT */
  return 0;
}

const char *
coap_socket_format_errno(int error) {
  return strerror(error);
}
#ifdef _WIN32
const char *
coap_socket_strerror(void) {
  coap_win_error_to_errno();
  return coap_socket_format_errno(errno);
}
#else /* _WIN32 */
const char *
coap_socket_strerror(void) {
  return coap_socket_format_errno(errno);
}
#endif /* _WIN32 */

COAP_API coap_fd_t
coap_socket_get_fd(coap_socket_t *sock) {
#if !defined(WITH_LWIP) && !defined(WITH_CONTIKI)
  return sock->fd;
#else
  (void)(sock);
  return COAP_INVALID_SOCKET;
#endif
}

COAP_API coap_socket_flags_t
coap_socket_get_flags(coap_socket_t *sock) {
  return sock->flags;
}

COAP_API void
coap_socket_set_flags(coap_socket_t *sock, coap_socket_flags_t flags) {
  sock->flags = flags;
}
