#ifndef _PLATFORM_UTILS_H_
#define _PLATFORM_UTILS_H_

#undef HTONS
#define HTONS(BYTES) uip_htons(BYTES)

#undef NTOHS
#define NTOHS(BYTES) uip_ntohs(BYTES)

#endif /* _PLATFORM_UTILS_H_ */
