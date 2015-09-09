#include "coap_timer.h"

#include "debug.h"
#include "mem.h"

#include <string.h>
#include <sys/time.h> // TODO needs something like HAVE_TIME_H
#include <signal.h> // TODO needs something like HAVE_SIGNAL_H
#include <pthread.h> // TODO needs something like HAVE_PTHREAD_H

#include "libev/ev.h"

#ifdef __GNUC__
#define UNUSED __attribute__((unused))
#else
#define UNUSED
#endif

struct coap_timer_t {
  ev_timer timer;
  CoapTimerCallback cb;
  void *data;
};

static pthread_t timer_thread;
static struct ev_loop *timer_loop;
static ev_async thread_wakeup;

static void timeout_cb(EV_P_ ev_timer *w, int revents) {
  coap_timer_t *coap_timer = (coap_timer_t *)w;
  if (coap_timer->cb) {
    coap_timer->cb(coap_timer->data);
  }
}

static void *timer_thread_func(void* args) {
  ev_run(timer_loop, 0);
  return NULL;
}

static void thread_wakeup_cb(EV_P_ ev_async *w, int revents) {
  // this only exists to wake up the thread
  // so it may pick up new timer watchers
}


// TODO coap_timer_deinit to cleanly kill the loop
void coap_timer_init(void) {
  timer_loop = EV_DEFAULT;

  // set up an async event for thread wakeup
  ev_async_init(&thread_wakeup, thread_wakeup_cb);
  ev_async_start(timer_loop, &thread_wakeup);

  pthread_create(&timer_thread, NULL, timer_thread_func, NULL);
}

coap_timer_t *coap_new_timer(CoapTimerCallback cb, void *data) {
  coap_timer_t *coap_timer = coap_malloc_type(COAP_TIMER, sizeof(coap_timer_t));

  if (coap_timer) {
    coap_timer->cb = cb;
    coap_timer->data = data;
    ev_timer_init(&coap_timer->timer, timeout_cb, 0., 0.);
  }

  return coap_timer;
}

void coap_free_timer(coap_timer_t *coap_timer) {
  ev_timer_stop(timer_loop, &coap_timer->timer);
  coap_free_type(COAP_TIMER, coap_timer);
}

void coap_timer_set(coap_timer_t *coap_timer, coap_tick_t num_ticks) {
  // stop the timer if it is running
  ev_timer_stop(timer_loop, &coap_timer->timer);

  // set the new timeout
  ev_tstamp time = (ev_tstamp)num_ticks / COAP_TICKS_PER_SECOND;
  ev_timer_set(&coap_timer->timer, time, 0.);
  ev_timer_start(timer_loop, &coap_timer->timer);

  // wake up the thread
  ev_async_send(timer_loop, &thread_wakeup);
}

char coap_timer_is_set(coap_timer_t *coap_timer) {
  return (ev_timer_remaining(timer_loop, &coap_timer->timer) != 0.);
}

void coap_timer_unset(coap_timer_t *coap_timer) {
  ev_timer_stop(timer_loop, &coap_timer->timer);
  ev_timer_set(&coap_timer->timer, 0., 0.);
}

