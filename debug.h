/* debug.h -- debug utilities
 *
 * (c) 2010 Olaf Bergmann <bergmann@tzi.org>
 */

#ifndef _COAP_DEBUG_H_
#define _COAP_DEBUG_H_

#ifndef VERSION
#  define VERSION "0.04"
#endif

#ifndef NDEBUG

void debug(char *,...);

#include "pdu.h"
extern void coap_show_pdu(coap_pdu_t *);

#endif

#endif /* _COAP_DEBUG_H_ */
