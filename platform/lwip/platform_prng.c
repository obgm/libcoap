#include "prng.h"

void prng_init(unsigned long value) {
}

int prng(unsigned char *buf, size_t len) {
  while (len--)
    *buf++ = LWIP_RAND() & 0xFF;
  return 1;
}
