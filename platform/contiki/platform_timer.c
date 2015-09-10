#include "coap_timer.h"

struct coap_timer_t {

};

void coap_timer_init(void) {

}

coap_timer_t *coap_new_timer(CoapTimerCallback cb, void *data) {
  return 0;
}

void coap_free_timer(coap_timer_t *timer) {

}

void coap_timer_set(coap_timer_t *timer, coap_tick_t num_ticks) {

}

char coap_timer_is_set(coap_timer_t *timer) {
  return 0;
}

void coap_timer_unset(coap_timer_t *timer) {

}


