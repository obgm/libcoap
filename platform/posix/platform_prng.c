#include "prng.h"

#include <stdlib.h>

void
prng_init(unsigned long value) {
  srand(value);
}

int
prng(unsigned char *buf, size_t len) {
  while (len--)
    *buf++ = rand() & 0xFF;
  return 1;
}
