/* debug.h -- debug utilities
 *
 * (c) 2010 Olaf Bergmann <bergmann@tzi.org>
 */

#ifndef VERSION
#  define VERSION "0.03"
#endif

#ifndef debug
#  ifndef NDEBUG
#    ifdef __STRICT_ANSI__
extern void debug(char *,...);
#    else
#      define debug(...)   fprintf(stdout, __VA_ARGS__)
#    endif
#  else
#    define debug(...)
#  endif
#endif

#include "pdu.h"

#ifndef NDEBUG
extern void coap_show_pdu( coap_pdu_t *);
#endif


