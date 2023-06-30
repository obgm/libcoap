/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/*
 * Copyright (c) 2018, SICS, RISE AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/**
 * @file oscore_cbor.h
 * @brief An implementation of the Concise Binary Object Representation (RFC).
 *
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 * extended for libcoap by:
 *     Peter van der Stok <consultancy@vanderstok.org>
 *     on request of Fairhair alliance
 * adapted for libcoap integration
 *      Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 */

#ifndef _OSCORE_CBOR_H
#define _OSCORE_CBOR_H
#include <stddef.h>
#include <stdint.h>

/**
 * @ingroup internal_api
 * @defgroup oscore_cbor_internal OSCORE CBOR Support
 * Internal API for interfacing with OSCORE CBOR
 * @{
 */

/* CBOR major types */
#define CBOR_UNSIGNED_INTEGER 0
#define CBOR_NEGATIVE_INTEGER 1
#define CBOR_BYTE_STRING      2
#define CBOR_TEXT_STRING      3
#define CBOR_ARRAY            4
#define CBOR_MAP              5
#define CBOR_TAG              6
#define CBOR_SIMPLE_VALUE     7
#define CBOR_FLOATING_POINT   7

#define CBOR_FALSE 20
#define CBOR_TRUE  21
#define CBOR_NULL  22

size_t oscore_cbor_put_nil(uint8_t **buffer, size_t *buf_size);

size_t oscore_cbor_put_true(uint8_t **buffer, size_t *buf_size);

size_t oscore_cbor_put_false(uint8_t **buffer, size_t *buf_size);

size_t oscore_cbor_put_text(uint8_t **buffer,
                            size_t *buf_size,
                            const char *text,
                            size_t text_len);

size_t oscore_cbor_put_array(uint8_t **buffer, size_t *buf_size, size_t elements);

size_t oscore_cbor_put_bytes(uint8_t **buffer,
                             size_t *buf_size,
                             const uint8_t *bytes,
                             size_t bytes_len);

size_t oscore_cbor_put_map(uint8_t **buffer, size_t *buf_size, size_t elements);

size_t oscore_cbor_put_number(uint8_t **buffer, size_t *buf_size, int64_t value);

size_t oscore_cbor_put_simple_value(uint8_t **buffer, size_t *buf_size, uint8_t value);

size_t oscore_cbor_put_unsigned(uint8_t **buffer, size_t *buf_size, uint64_t value);

size_t oscore_cbor_put_tag(uint8_t **buffer, size_t *buf_size, uint64_t value);

size_t oscore_cbor_put_negative(uint8_t **buffer, size_t *buf_size, int64_t value);

uint8_t oscore_cbor_get_next_element(const uint8_t **buffer, size_t *buf_size);

size_t oscore_cbor_get_element_size(const uint8_t **buffer, size_t *buf_size);

uint8_t oscore_cbor_elem_contained(const uint8_t *data, size_t *buf_size,
                                   uint8_t *end);

uint8_t oscore_cbor_get_number(const uint8_t **data, size_t *buf_size,
                               int64_t *value);

uint8_t oscore_cbor_get_simple_value(const uint8_t **data, size_t *buf_size,
                                     uint8_t *value);

int64_t oscore_cbor_get_negative_integer(const uint8_t **buffer,
                                         size_t *buf_size);

uint64_t oscore_cbor_get_unsigned_integer(const uint8_t **buffer,
                                          size_t *buf_size);

void oscore_cbor_get_string(const uint8_t **buffer, size_t *buf_size,
                            char *str, size_t size);

void oscore_cbor_get_array(const uint8_t **buffer, size_t *buf_size,
                           uint8_t *arr, size_t size);

/* oscore_cbor_get_string_array
 * fills the the size and the array from the cbor element
 */
uint8_t oscore_cbor_get_string_array(const uint8_t **data, size_t *buf_size,
                                     uint8_t **result, size_t *len);

/* oscore_cbor_strip value
 * strips the value of the cbor element into result
 *  and returns size
 */
uint8_t oscore_cbor_strip_value(const uint8_t **data, size_t *buf_size,
                                uint8_t **result, size_t *len);

/** @} */

#endif /* _OSCORE_CBOR_H */
