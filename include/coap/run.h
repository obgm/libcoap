/*
 * run.h -- CoAP main loop
 *
 * Copyright (C) 2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#ifndef _COAP_RUN_H_
#define _COAP_RUN_H_

#include "net.h"

/**
 * Execute a single send/receive step. This function sends out any due
 * message from the sendqueue and then waits up to @p timeout_ms
 * milliseconds for incoming messages on the endpoints that are
 * attached to @p ctx. The return value is less than zero on error or
 * the number of milliseconds that have passed while waiting.
 *
 * @param ctx        The context to operate on.
 * @param timeout_ms The timeout in milliseconds.
 * @return The number of milliseconds that have passed since the
 *         operation has started or a value less than zero on error.
 */
int coap_run_once(coap_context_t *ctx, unsigned int timeout_ms);

/**
 * Simple main loop. This function infinitely runs coap_run_once()
 * on the given context @p ctx.
 *
 * @param ctx The context to operate on.
 */
void coap_run(coap_context_t *ctx);

#endif /* COAP_RUN_H */
