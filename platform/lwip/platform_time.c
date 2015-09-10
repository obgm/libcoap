#include "coap_time.h"

#include <stdint.h>
#include <lwip/sys.h>

void
coap_ticks(coap_tick_t *t) {
  *t = sys_now();
}

void
coap_clock_init(void) {
}

coap_time_t
coap_ticks_to_rt(coap_tick_t t) {
  return t / COAP_TICKS_PER_SECOND;
}

