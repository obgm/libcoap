/* subscribe.c -- subscription handling for CoAP
 *                see draft-ietf-coap-observe-16
 *
 * Copyright (C) 2010--2019 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#include "coap_internal.h"

void
coap_subscription_init(coap_subscription_t *s) {
  assert(s);
  memset(s, 0, sizeof(coap_subscription_t));
}
