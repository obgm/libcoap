/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 * -*- */

/* coap_list.h -- CoAP list structures
 *
 * Copyright (C) 2010,2011,2015 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms of
 * use.
 */

#ifndef _COAP_APPEND_H_
#define _COAP_APPEND_H_

#include "utlist.h"
#include "coap_list.h"

/**
 * Adds node to given queue, ordered by specified order function. Returns 1
 * when insert was successful, 0 otherwise.
 */
int coap_append(coap_list_t **queue, coap_list_t *node);

#endif /* _COAP_APPEND_H_ */
