#include "prng.h"

#include "random.h"

void
prng_init(unsigned long value) {
  random_init((unsigned short)value);
}

int
prng(unsigned char *buf, size_t len) {
  unsigned short v = random_rand();
  while (len > sizeof(v)) {
    memcpy(buf, &v, sizeof(v));
    len -= sizeof(v);
    buf += sizeof(v);
    v = random_rand();
  }

  memcpy(buf, &v, len);
  return 1;
}


