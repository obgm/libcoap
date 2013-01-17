/* endianness helpers for lwip port */

/* FIXME: i'm sure there is something in lwip we can use */

#include <stdint.h>

/* we're on little endian, ntohs & co swap */
static inline uint16_t ntohs(uint16_t x)
{
	return (x << 8) | (x >> 8);
}

#define htons ntohs
