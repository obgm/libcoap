#ifndef _PLATFORM_UTILS_H_
#define _PLATFORM_UTILS_H_

#undef NTOHS
#define NTOHS(BYTES) ntohs(BYTES)

#undef HTONS
#define HTONS(BYTES) htons(BYTES)


#endif /* _PLATFORM_UTILS_H_ */
