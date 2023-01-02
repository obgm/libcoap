/*
 * server-coap.h -- LwIP example
 *
 * Copyright (C) 2013-2016 Christian Amsüss <chrysn@fsfe.org>
 * Copyright (C) 2022-2023 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#include "coap_config.h"
#include <coap3/coap.h>

/* Start up the CoAP Client */
void client_coap_init(coap_lwip_input_wait_handler_t input_wait, void *input_arg,
                      int argc, char **argv);

/* Close down CoAP activity */

void client_coap_finished(void);

/*
 * Call this when you think that work needs to be done
 *
 * Returns: 1 if there is no more work to be done, else 0
 */
int client_coap_poll(void);
