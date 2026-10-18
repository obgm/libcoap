/*
 * coap_debug_internal.h -- debug utilities
 *
 * Copyright (C) 2010-2011,2014-2026 Olaf Bergmann <bergmann@tzi.org>
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

#ifdef __cplusplus
extern "C" {
#endif

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
 * Check to see whether an incoming packet should be dropped or not.
 *
 * Internal function
 *
 * @return @c 1 if packet is to be let through, @c 0 if packet is to be dropped.
 */
int coap_debug_recv_packet(void);

/**
 * Reset all the defined logging parameters.
 *
 * Internal function
 */
void coap_debug_reset(void);

/**
 * Output ascii representation of option number, if known.
 *
 * @param code The PDU code.
 * @param number The option number.
 *
 * @return Ascii representation or numeric value in ascii.
 */
const char *coap_option_string(coap_pdu_code_t code, coap_option_num_t number);

/**
 * The equivalent to snprintf() functionality, but returning the actual
 * characters added and defining the buffer offset in a separate parameter.
 *
 * Internal function
 *
 * @param buffer   The start of the buffer to write into.
 * @param buf_size The size of the buffer to write into.
 * @param offset   The start offset into @p buffer, updated after buffer is updated
 *                 with the currently used length of buffer, not including the NUL
 *                 terminator.
 * @param format   The formatting string to use as per printf().
 *
 * @return         The number of characters written to the string.  If 0, an error
 *                 or no more data can be put in @p buffer.
 */
#if (defined(__GNUC__))
int coap_snprintf(char *buffer, size_t buf_size, size_t *offset,
                  const char *format, ...) __attribute__((format(printf, 4, 5)));
#else
int coap_snprintf(char *buffer, size_t buf_size, size_t *offset, const char *format, ...);
#endif

#ifdef __cplusplus
}
#endif

#endif /* COAP_DEBUG_INTERNAL_H_ */
