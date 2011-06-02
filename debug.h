/* debug.h -- debug utilities
 *
 * Copyright (C) 2010,2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

#ifndef _COAP_DEBUG_H_
#define _COAP_DEBUG_H_

#ifndef NDEBUG

void debug(char *,...);

#include "pdu.h"
extern void coap_show_pdu(coap_pdu_t *);

#endif

#endif /* _COAP_DEBUG_H_ */
