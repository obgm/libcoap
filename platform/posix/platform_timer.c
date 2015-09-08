#include "coap_timer.h"

#include "debug.h"
#include "mem.h"

#include <string.h>
#include <sys/time.h> // TODO needs something like HAVE_TIME_H
#include <signal.h> // TODO needs something like HAVE_SIGNAL_H

#include "libev/ev.h"

#ifdef __GNUC__
#define UNUSED __attribute__((unused))
#else
#define UNUSED
#endif

struct coap_timer_t;

struct coap_timer_t {
  CoapTimerCallback cb;
  void *data;
};

void coap_timer_init(void) {
   struct ev_loop *loop = EV_DEFAULT;
   ev_run (loop, 0);
}

coap_timer_t *coap_new_timer(CoapTimerCallback cb, void *data) {
  return NULL;
}

void coap_free_timer(coap_timer_t *timer) {
  return;
}

void coap_timer_set(coap_timer_t *timer, coap_tick_t num_ticks) {
  return;
}

char coap_timer_is_set(coap_timer_t *timer) {
  return 0;
}

void coap_timer_unset(coap_timer_t *timer) {
  return;
}

