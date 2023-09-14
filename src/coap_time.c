/* coap_time.c -- Clock Handling
 *
 * Copyright (C) 2015,2023 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file coap_time.c
 * @brief Clock handling functions
 */

#include "coap3/coap_internal.h"

#ifdef HAVE_TIME_H
#include <time.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>  /* _POSIX_TIMERS */
#endif
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#include <stdint.h>
#endif

static coap_tick_t coap_clock_offset = 0;

#if _POSIX_TIMERS && !defined(__APPLE__)
/* _POSIX_TIMERS is > 0 when clock_gettime() is available */

/* Use real-time clock for correct timestamps in coap_log(). */
#define COAP_CLOCK CLOCK_REALTIME
#endif

#if defined(HAVE_WINSOCK2_H) && !defined(__MINGW32__)
static int
gettimeofday(struct timeval *tp, TIME_ZONE_INFORMATION *tzp) {
  (void)tzp;
  static const uint64_t s_tUnixEpoch = 116444736000000000Ui64;

  FILETIME file_time;
  ULARGE_INTEGER time;
  uint64_t tUsSinceUnicEpoch;

  GetSystemTimeAsFileTime(&file_time);
  time.LowPart = file_time.dwLowDateTime;
  time.HighPart = file_time.dwHighDateTime;
  tUsSinceUnicEpoch = (time.QuadPart - s_tUnixEpoch) / 10;

  tp->tv_sec = (long)(tUsSinceUnicEpoch / 1000000);
  tp->tv_usec = (long)(tUsSinceUnicEpoch % 1000000);
  return 0;
}
#endif /* HAVE_WINSOCK2_H && !__MINGW32__ */

void
coap_clock_init(void) {
#ifdef COAP_CLOCK
  struct timespec tv;
  clock_gettime(COAP_CLOCK, &tv);
#else /* _POSIX_TIMERS */
  struct timeval tv;
  gettimeofday(&tv, NULL);
#endif /* not _POSIX_TIMERS */

  coap_clock_offset = tv.tv_sec;
}

/* creates a Qx.frac from fval */
#define Q(frac,fval) ((1 << (frac)) * (fval))

/* number of frac bits for sub-seconds */
#define FRAC 10

/* rounds val up and right shifts by frac positions */
#define SHR_FP(val,frac) (((coap_tick_t)((val) + (1 << ((frac) - 1)))) >> (frac))

void
coap_ticks(coap_tick_t *t) {
  coap_tick_t tmp;

#ifdef COAP_CLOCK
  struct timespec tv;
  clock_gettime(COAP_CLOCK, &tv);
  /* Possible errors are (see clock_gettime(2)):
   *  EFAULT tp points outside the accessible address space.
   *  EINVAL The clk_id specified is not supported on this system.
   * Both cases should not be possible here.
   */

  tmp = SHR_FP(tv.tv_nsec * Q(FRAC, (COAP_TICKS_PER_SECOND/1000000000.0)), FRAC);
#else /* _POSIX_TIMERS */
  /* Fall back to gettimeofday() */

  struct timeval tv;
  gettimeofday(&tv, NULL);
  /* Possible errors are (see gettimeofday(2)):
   *  EFAULT One of tv or tz pointed outside the accessible address space.
   *  EINVAL Timezone (or something else) is invalid.
   * Both cases should not be possible here.
   */

  tmp = SHR_FP(tv.tv_usec * Q(FRAC, (COAP_TICKS_PER_SECOND/1000000.0)), FRAC);
#endif /* not _POSIX_TIMERS */

  /* Finally, convert temporary FP representation to multiple of
   * COAP_TICKS_PER_SECOND */
  *t = tmp + (tv.tv_sec - coap_clock_offset) * COAP_TICKS_PER_SECOND;
}

coap_time_t
coap_ticks_to_rt(coap_tick_t t) {
  return coap_clock_offset + (t / COAP_TICKS_PER_SECOND);
}

uint64_t
coap_ticks_to_rt_us(coap_tick_t t) {
  return (uint64_t)coap_clock_offset * 1000000 + (uint64_t)t * 1000000 / COAP_TICKS_PER_SECOND;
}

coap_tick_t
coap_ticks_from_rt_us(uint64_t t) {
  return (coap_tick_t)((t - (uint64_t)coap_clock_offset * 1000000) * COAP_TICKS_PER_SECOND / 1000000);
}

#undef Q
#undef FRAC
#undef SHR_FP

#else /* HAVE_TIME_H */

#ifdef __clang__
/* Make compilers happy that do not like empty modules. As this function is
 * never used, we ignore -Wunused-function at the end of compiling this file
 */
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
COAP_STATIC_INLINE void
dummy(void) {
}

#endif /* not HAVE_TIME_H */
