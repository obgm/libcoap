/*
 * client-coap.h -- RIOT client example
 *
 * Copyright (C) 2023 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#include "coap_config.h"
#include <coap3/coap.h>

/* Start up the CoAP Client */
void client_coap_init(int argc, char **argv);
