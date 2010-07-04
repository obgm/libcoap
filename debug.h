/* debug.h -- debug utilities
 *
 * (c) 2010 Olaf Bergmann <bergmann@tzi.org>
 */

#ifndef debug
#  ifndef NDEBUG
#    define debug(...)   fprintf(stdout, __VA_ARGS__)
#  else
#    define debug(...)
#  endif
#endif

#include "pdu.h"

#ifndef NDEBUG
extern void coap_show_pdu( coap_pdu_t *);
#endif


