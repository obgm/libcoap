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
 * @file oscore_cbor.c
 * @brief An implementation of the Concise Binary Object Representation (RFC).
 *
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 * extended for libcoap by Peter van der Stok
 *                         <consultancy@vanderstok.org>
 * on request of Fairhair alliance.
 * adapted for libcoap integration
 *      Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 */

#include "coap3/coap_internal.h"
#include <string.h>

static void
util_write_byte(uint8_t **buffer, size_t *buf_size, uint8_t value) {
  assert(*buf_size >= 1);
  (*buf_size)--;
  **buffer = value;
  (*buffer)++;
}

size_t
oscore_cbor_put_nil(uint8_t **buffer, size_t *buf_size) {
  util_write_byte(buffer, buf_size, 0xF6);
  return 1;
}

size_t
oscore_cbor_put_true(uint8_t **buffer, size_t *buf_size) {
  util_write_byte(buffer, buf_size, 0xF5);
  return 1;
}

size_t
oscore_cbor_put_false(uint8_t **buffer, size_t *buf_size) {
  util_write_byte(buffer, buf_size, 0xF4);
  return 1;
}

size_t
oscore_cbor_put_text(uint8_t **buffer,
                     size_t *buf_size,
                     const char *text,
                     size_t text_len) {
  uint8_t *pt = *buffer;
  size_t nb = oscore_cbor_put_unsigned(buffer, buf_size, text_len);
  assert(*buf_size >= text_len);
  (*buf_size) -= text_len;
  *pt = (*pt | 0x60);
  memcpy(*buffer, text, text_len);
  (*buffer) += text_len;
  return nb + text_len;
}

size_t
oscore_cbor_put_array(uint8_t **buffer, size_t *buf_size, size_t elements) {
  uint8_t *pt = *buffer;
  size_t nb = oscore_cbor_put_unsigned(buffer, buf_size, elements);
  *pt = (*pt | 0x80);
  return nb;
}

size_t
oscore_cbor_put_bytes(uint8_t **buffer,
                      size_t *buf_size,
                      const uint8_t *bytes,
                      size_t bytes_len) {
  uint8_t *pt = *buffer;
  size_t nb = oscore_cbor_put_unsigned(buffer, buf_size, bytes_len);
  assert(*buf_size >= bytes_len);
  (*buf_size) -= bytes_len;
  *pt = (*pt | 0x40);
  memcpy(*buffer, bytes, bytes_len);
  (*buffer) += bytes_len;
  return nb + bytes_len;
}

size_t
oscore_cbor_put_map(uint8_t **buffer, size_t *buf_size, size_t elements) {
  uint8_t *pt = *buffer;
  size_t nb = oscore_cbor_put_unsigned(buffer, buf_size, elements);
  *pt = (*pt | 0xa0);
  return nb;
}

size_t
oscore_cbor_put_number(uint8_t **buffer, size_t *buf_size, int64_t value) {
  if (value < 0)
    return oscore_cbor_put_negative(buffer, buf_size, -value);
  else
    return oscore_cbor_put_unsigned(buffer, buf_size, value);
}

size_t
oscore_cbor_put_simple_value(uint8_t **buffer,
                             size_t *buf_size,
                             uint8_t value) {
  uint8_t *pt = *buffer;
  size_t nb = oscore_cbor_put_unsigned(buffer, buf_size, value);
  *pt = (*pt | 0xe0);
  return nb;
}

size_t
oscore_cbor_put_tag(uint8_t **buffer, size_t *buf_size, uint64_t value) {
  uint8_t *pt = *buffer;
  size_t nb = oscore_cbor_put_unsigned(buffer, buf_size, value);
  *pt = (*pt | 0xc0);
  return nb;
}

size_t
oscore_cbor_put_negative(uint8_t **buffer, size_t *buf_size, int64_t value) {
  value--;
  uint8_t *pt = *buffer;
  size_t nb = oscore_cbor_put_unsigned(buffer, buf_size, value);
  *pt = (*pt | 0x20);
  return nb;
}

static void
put_b_f(uint8_t **buffer, uint64_t value, uint8_t nr) {
  uint8_t *pt = *buffer - 1;
  uint64_t vv = value;
  for (int q = nr; q > -1; q--) {
    (*pt--) = (uint8_t)(vv & 0xff);
    vv = (vv >> 8);
  }
}

size_t
oscore_cbor_put_unsigned(uint8_t **buffer, size_t *buf_size, uint64_t value) {
  if (value < 0x18) { /* small value half a byte */
    assert(*buf_size >= 1);
    (*buf_size)--;
    (**buffer) = (uint8_t)value;
    (*buffer)++;
    return 1;
  } else if ((value > 0x17) && (value < 0x100)) {
    /* one byte uint8_t  */
    assert(*buf_size >= 2);
    (*buf_size) -= 2;
    (**buffer) = (0x18);
    *buffer = (*buffer) + 2;
    put_b_f(buffer, value, 0);
    return 2;
  } else if ((value > 0xff) && (value < 0x10000)) {
    /* 2 bytes uint16_t     */
    assert(*buf_size >= 3);
    (*buf_size) -= 3;
    (**buffer) = (0x19);
    *buffer = (*buffer) + 3;
    put_b_f(buffer, value, 1);
    return 3;
  } else if ((value > 0xffff) && (value < 0x100000000)) {
    /* 4 bytes uint32_t   */
    assert(*buf_size >= 5);
    (*buf_size) -= 5;
    (**buffer) = (0x1a);
    *buffer = (*buffer) + 5;
    put_b_f(buffer, value, 3);
    return 5;
  } else { /*if(value > 0xffffffff)*/
    /* 8 bytes uint64_t  */
    assert(*buf_size >= 9);
    (*buf_size) -= 9;
    (**buffer) = (0x1b);
    *buffer = (*buffer) + 9;
    put_b_f(buffer, value, 7);
    return 9;
  }
}

static uint8_t
get_byte(const uint8_t **buffer, size_t *buf_len) {
#if NDEBUG
  (void)buf_len;
#endif /* NDEBUG */
  assert((*buf_len) > 0);
  return (*buffer)[0];
}

static uint8_t
get_byte_inc(const uint8_t **buffer, size_t *buf_len) {
  assert((*buf_len) > 0);
  (*buf_len)--;
  return ((*buffer)++)[0];
}

uint8_t
oscore_cbor_get_next_element(const uint8_t **buffer, size_t *buf_len) {
  uint8_t element = get_byte(buffer, buf_len);
  return element >> 5;
}

/* oscore_cbor_get_element_size returns
 *   - size of byte strings of character strings
 *   - size of array
 *   - size of map
 *   - value of unsigned integer
 */

size_t
oscore_cbor_get_element_size(const uint8_t **buffer, size_t *buf_len) {
  uint8_t control = get_byte(buffer, buf_len) & 0x1f;
  size_t size = get_byte_inc(buffer, buf_len);

  if (control < 0x18) {
    size = (uint64_t)control;
  } else {
    control = control & 0x3;
    int num = 1 << control;
    size = 0;
    size_t getal;
    for (int i = 0; i < num; i++) {
      getal = get_byte_inc(buffer, buf_len);
      size = (size << 8) + getal;
    }
  }
  return size;
}

uint8_t
oscore_cbor_elem_contained(const uint8_t *data, size_t *buf_len, uint8_t *end) {
  const uint8_t *buf = data;
  const uint8_t *last = data + oscore_cbor_get_element_size(&buf, buf_len);
  if (last > end) {
    coap_log_err("oscore_cbor_elem_contained returns 1 \n");
    return 1;
  } else
    return 0;
}

int64_t
oscore_cbor_get_negative_integer(const uint8_t **buffer, size_t *buf_len) {
  return -(int64_t)(oscore_cbor_get_element_size(buffer, buf_len) + 1);
}

uint64_t
oscore_cbor_get_unsigned_integer(const uint8_t **buffer, size_t *buf_len) {
  return oscore_cbor_get_element_size(buffer, buf_len);
}

/*
 * oscore_cbor_get_number
 *
 * gets a negative or positive number from data
 * OK: return 0 ; NOK: return 1
 */
uint8_t
oscore_cbor_get_number(const uint8_t **data, size_t *buf_len, int64_t *value) {
  uint8_t elem = oscore_cbor_get_next_element(data, buf_len);
  if (elem == CBOR_UNSIGNED_INTEGER) {
    *value = oscore_cbor_get_unsigned_integer(data, buf_len);
    return 0;
  } else if (elem == CBOR_NEGATIVE_INTEGER) {
    *value = oscore_cbor_get_negative_integer(data, buf_len);
    return 0;
  } else
    return 1;
}

/*
 * oscore_cbor_get_simple_value
 *
 * gets a simple value from data
 * OK: return 0 ; NOK: return 1
 */
uint8_t
oscore_cbor_get_simple_value(const uint8_t **data, size_t *buf_len, uint8_t *value) {
  uint8_t elem = oscore_cbor_get_next_element(data, buf_len);
  if (elem == CBOR_SIMPLE_VALUE) {
    *value = get_byte_inc(data, buf_len) & 0x1f;
    return 0;
  } else
    return 1;
}

void
oscore_cbor_get_string(const uint8_t **buffer, size_t *buf_len, char *str, size_t size) {
  (void)buf_len;
  for (size_t i = 0; i < size; i++) {
    *str++ = (char)get_byte_inc(buffer, buf_len);
  }
}

void
oscore_cbor_get_array(const uint8_t **buffer, size_t *buf_len, uint8_t *arr, size_t size) {
  (void)buf_len;
  for (size_t i = 0; i < size; i++) {
    *arr++ = get_byte_inc(buffer, buf_len);
  }
}

/* oscore_cbor_get_string_array
 * fills the the size and the array from the cbor element
 */
uint8_t
oscore_cbor_get_string_array(const uint8_t **data, size_t *buf_len,
                             uint8_t **result,
                             size_t *len) {

  uint8_t elem = oscore_cbor_get_next_element(data, buf_len);
  *len = oscore_cbor_get_element_size(data, buf_len);
  *result = NULL;
  void *rs = coap_malloc_type(COAP_STRING, *len);
  *result = (uint8_t *)rs;
  if (elem == CBOR_TEXT_STRING) {
    oscore_cbor_get_string(data, buf_len, (char *)*result, *len);
    return 0;
  } else if (elem == CBOR_BYTE_STRING) {
    oscore_cbor_get_array(data, buf_len, *result, *len);
    return 0; /* all is well */
  } else {
    free(*result);
    *result = NULL;
    return 1; /* failure */
  }
}

/* oscore_cbor_skip value
 *  returns number of CBOR bytes
 */
static size_t
oscore_cbor_skip_value(const uint8_t **data, size_t *buf_len) {
  uint8_t elem = oscore_cbor_get_next_element(data, buf_len);
  uint8_t control = get_byte(data, buf_len) & 0x1f;
  size_t nb = 0;   /* number of elements in array or map */
  size_t num = 0;  /* number of bytes of length or number */
  size_t size = 0; /* size of value to be skipped */
  if (control < 0x18) {
    num = 1;
  } else {
    control = control & 0x3;
    num = 1 + (1 << control);
  }
  switch (elem) {
  case CBOR_UNSIGNED_INTEGER:
  case CBOR_NEGATIVE_INTEGER:
    assert((*buf_len) >= num);
    *buf_len -= num;
    *data = *data + num;
    size = num;
    break;
  case CBOR_BYTE_STRING:
  case CBOR_TEXT_STRING:
    size = num;
    size += oscore_cbor_get_element_size(data, buf_len);
    assert((*buf_len) >= (size - num));
    *buf_len -= (size - num);
    (*data) = (*data) + size - num;
    break;
  case CBOR_ARRAY:
    nb = oscore_cbor_get_element_size(data, buf_len);
    size = num;
    for (uint16_t qq = 0; qq < nb; qq++)
      size += oscore_cbor_skip_value(data, buf_len);
    break;
  case CBOR_MAP:
    nb = oscore_cbor_get_element_size(data, buf_len);
    size = num;
    for (uint16_t qq = 0; qq < nb; qq++) {
      size += oscore_cbor_skip_value(data, buf_len);
      size += oscore_cbor_skip_value(data, buf_len);
    }
    break;
  case CBOR_TAG:
    assert((*buf_len) >= 1);
    *buf_len -= 1;
    (*data)++;
    size = 1;
    break;
  default:
    return 0;
    break;
  } /* switch */
  return size;
}

/* oscore_cbor_strip value
 * strips the value of the cbor element into result
 *  and returns size
 */
uint8_t
oscore_cbor_strip_value(const uint8_t **data, size_t *buf_len, uint8_t **result, size_t *len) {
  const uint8_t *st_data = *data;
  size_t size = oscore_cbor_skip_value(data, buf_len);
  *result = coap_malloc_type(COAP_STRING, size);
  for (uint16_t qq = 0; qq < size; qq++)
    (*result)[qq] = st_data[qq];
  *len = size;
  return 0;
}
