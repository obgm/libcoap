/*
 * coap_debug_internal.h -- debug utilities
 *
 * Copyright (C) 2010-2011,2014-2024 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_debug_internal.h
 * @brief CoAP Logging support internal information
 */

#ifndef COAP_DEBUG_INTERNAL_H_
#define COAP_DEBUG_INTERNAL_H_

/**
 * Check to see whether a packet should be sent or not.
 *
 * Internal function
 *
 * @return @c 1 if packet is to be sent, @c 0 if packet is to be dropped.
 */
int coap_debug_send_packet(void);

/**
 * Reset all the defined logging parameters.
 *
 * Internal function
 */
void coap_debug_reset(void);

#endif /* COAP_DEBUG_INTERNAL_H_ */
