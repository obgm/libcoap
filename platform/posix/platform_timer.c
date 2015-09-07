#include "coap_timer.h"

#ifdef __GNUC__
#define UNUSED __attribute__((unused))
#else
#define UNUSED
#endif

struct coap_timer_t {
  int time;
};

void coap_timer_init(void) {

}

coap_timer_t *coap_new_timer(CoapTimerCallback cb UNUSED, void *data UNUSED) {
  return NULL;
}

void coap_free_timer(coap_timer_t *timer UNUSED) {
  return;
}

void coap_timer_set(coap_timer_t *timer UNUSED, coap_tick_t num_ticks UNUSED) {
  return;
}

void coap_timer_is_set(coap_timer_t *timer UNUSED) {
  return;
}

void coap_timer_unset(coap_timer_t *timer UNUSED) {
  return;
}


