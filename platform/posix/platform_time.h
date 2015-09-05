#ifndef _PLATFORM_TIME_H_
#define _PLATFORM_TIME_H_

#include <time.h>

/**
 * This data type represents internal timer ticks with COAP_TICKS_PER_SECOND
 * resolution.
 */
typedef unsigned long coap_tick_t;

/**
 * CoAP time in seconds since epoch.
 */
typedef time_t coap_time_t;

/**
 * This data type is used to represent the difference between two clock_tick_t
 * values. This data type must have the same size in memory as coap_tick_t to
 * allow wrapping.
 */
typedef long coap_tick_diff_t;

/** Use ms resolution on POSIX systems */
#define COAP_TICKS_PER_SECOND 1000

#endif /* _PLATFORM_TIME_H_ */
