#include "coap_timer.h"

#include "debug.h"
#include "mem.h"

#include <string.h>
#include <sys/time.h> // TODO needs something like HAVE_TIME_H
#include <signal.h> // TODO needs something like HAVE_SIGNAL_H

#ifdef __GNUC__
#define UNUSED __attribute__((unused))
#else
#define UNUSED
#endif

struct coap_timer_t;

struct coap_timer_t {
  coap_timer_t *next_timer;
  CoapTimerCallback cb;
  coap_tick_t base_time;
  coap_tick_t duration;
  void *data;
};

static struct sigaction timer_sigaction;

static struct coap_timer_t *running_timers = NULL;

static void update_itimer(void) {
  coap_tick_t now;
  coap_ticks(&now);

  coap_tick_t num_ticks = running_timers->duration - (now - running_timers->base_time);

  coap_log(LOG_INFO, ">>>> SETITIMER to %lu - (%lu - %lu) = %lu\n",
           running_timers->duration, now, running_timers->base_time, num_ticks);

  struct itimerval it = {
    .it_value.tv_sec = num_ticks / COAP_TICKS_PER_SECOND,
    .it_value.tv_usec = num_ticks % COAP_TICKS_PER_SECOND * 1000, // MS -> US
  };

  setitimer(ITIMER_REAL, &it, NULL);
}

static void sigaction_handler(int sig UNUSED, siginfo_t *si UNUSED, void *uc UNUSED) {
  if (!running_timers) {
    return;
  }

  coap_tick_t now;
  coap_ticks(&now);

  do {
    coap_timer_t *timer = running_timers;
    running_timers = running_timers->next_timer;
    if (timer->cb) {
      timer->cb(timer->data);
    }
  } while (running_timers->duration + running_timers->base_time <= now);

  if (running_timers) {
    // set the itimer again
    update_itimer();
  }
}

void coap_timer_init(void) {
  memset(&timer_sigaction, 0, sizeof(struct sigaction));
  timer_sigaction.sa_sigaction = sigaction_handler;
  sigaction(SIGALRM, &timer_sigaction, NULL);
}

coap_timer_t *coap_new_timer(CoapTimerCallback cb, void *data) {
  coap_timer_t *timer = coap_malloc_type(COAP_TIMER, sizeof(coap_timer_t));
  memset(timer, 0, sizeof(coap_timer_t));
  timer->cb = cb;
  timer->data = data;
  return timer;
}

void coap_free_timer(coap_timer_t *timer) {
  // TODO remove from list
  memset(timer, 0, sizeof(coap_timer_t));
  coap_free_type(COAP_TIMER, timer);
}

void coap_timer_set(coap_timer_t *timer, coap_tick_t num_ticks) {
  // TODO handle the case where the timer is set
  coap_log(LOG_INFO, "> SET TIMER FOR %lu\n", num_ticks);
  coap_tick_t now;
  coap_ticks(&now);
  coap_timer_t **cur = &running_timers;
  while (*cur &&
         (*cur)->duration + (*cur)->base_time < now + num_ticks) {
    cur = &(*cur)->next_timer;
  }
  timer->next_timer = *cur;
  *cur = timer;

  timer->base_time = now;
  timer->duration = num_ticks;

  if (timer == running_timers) {
    update_itimer();
  }
}

char coap_timer_is_set(coap_timer_t *timer) {
  coap_timer_t *cur = running_timers;
  while (cur) {
    if (cur == timer) {
      return 1;
    }
    cur = cur->next_timer;
  }

  return 0;
}

void coap_timer_unset(coap_timer_t *timer) {
  char update_timer = (timer == running_timers);

  coap_timer_t **cur = &running_timers;
  while (*cur) {
    if (*cur == timer) {
      break;
    }
    cur = &(*cur)->next_timer;
  }
  *cur = (*cur)->next_timer;

  if (update_timer) {
    update_itimer();
  }

  return;
}

