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

#ifndef COAP_DEBUG_FD
#define COAP_DEBUG_FD stdout
#endif

void debug(char *,...);

#include "pdu.h"
void coap_show_pdu(const coap_pdu_t *);

struct __coap_address_t;
size_t coap_print_addr(const struct __coap_address_t *, unsigned char *, size_t);

#else

#define debug(...)
#define coap_show_pdu(x)
#define coap_print_addr(...)

#endif

#endif /* _COAP_DEBUG_H_ */
