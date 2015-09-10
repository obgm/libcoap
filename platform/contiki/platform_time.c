#include "coap_time.h"

void
coap_clock_init(void) {
  //clock_init();
}

void
coap_ticks(coap_tick_t *t) {
  //*t = clock_time();
}

coap_time_t
coap_ticks_to_rt(coap_tick_t t) {
  return t / COAP_TICKS_PER_SECOND;
}

