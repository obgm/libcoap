/* coap_time.c -- Clock Handling
 *
 * Copyright (C) 2015 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#include "coap_config.h"

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

#include "coap_time.h"

static coap_time_t coap_clock_offset = 0;

#if _POSIX_TIMERS && !defined(__APPLE__)
  /* _POSIX_TIMERS is > 0 when clock_gettime() is available */

  /* Use real-time clock for correct timestamps in coap_log(). */  
#define COAP_CLOCK CLOCK_REALTIME
#endif

#ifdef HAVE_WINSOCK2_H
static int
gettimeofday(struct timeval *tp, TIME_ZONE_INFORMATION *tzp) {
  static const uint64_t EPOCH = ((uint64_t) 116444736000000000ULL);

  SYSTEMTIME system_time;
  FILETIME file_time;
  uint64_t time;

  GetSystemTime(&system_time);
  SystemTimeToFileTime(&system_time, &file_time);
  time = ((uint64_t)file_time.dwLowDateTime);
  time += ((uint64_t)file_time.dwHighDateTime) << 32;

  tp->tv_sec = (long)((time - EPOCH) / 10000000L);
  tp->tv_usec = (long)(system_time.wMilliseconds * 1000);
  return 0;
}
#endif

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
#define Q(frac,fval) ((coap_tick_t)(((1 << (frac)) * (fval))))

/* number of frac bits for sub-seconds */
#define FRAC 10

/* rounds val up and right shifts by frac positions */
#define SHR_FP(val,frac) (((val) + (1 << ((frac) - 1))) >> (frac))

void
coap_ticks(coap_tick_t *t) {
  unsigned long tmp;

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

#undef Q
#undef FRAC
#undef SHR_FP

#else /* WITH_POSIX */

/* make compilers happy that do not like empty modules */
COAP_STATIC_INLINE void dummy()
{
}

#endif /* not WITH_POSIX */

