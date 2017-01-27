/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 * -*- */

/* coap_list.c -- CoAP list structures
 *
 * Copyright (C) 2010,2011,2015 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms of
 * use.
 */

/* #include "coap_config.h" */

#include <stdio.h>
#include <string.h>

#include "debug.h"
#include "mem.h"
#include "coap_append.h"

int
coap_append(coap_list_t **head, coap_list_t *node) {
  if (!node) {
    coap_log(LOG_WARNING, "cannot create option Proxy-Uri\n");
  } else {
    /* must append at the list end to avoid re-ordering of
     * options during sort */
    LL_APPEND((*head), node);
  }

  return node != NULL;
}
