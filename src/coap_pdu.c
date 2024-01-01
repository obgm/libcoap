/* coap_pdu.c -- CoAP PDU handling
 *
 * Copyright (C) 2010--2024 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file coap_pdu.c
 * @brief CoAP PDU handling
 */

#include "coap3/coap_internal.h"

#if defined(HAVE_LIMITS_H)
#include <limits.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#include <ctype.h>

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef max
#define max(a,b) ((a) > (b) ? (a) : (b))
#endif

void
coap_pdu_clear(coap_pdu_t *pdu, size_t size) {
  assert(pdu);
  assert(pdu->token);
  assert(pdu->max_hdr_size >= COAP_PDU_MAX_UDP_HEADER_SIZE);
  if (pdu->alloc_size > size)
    pdu->alloc_size = size;
  pdu->type = 0;
  pdu->code = 0;
  pdu->hdr_size = 0;
  pdu->actual_token.length = 0;
  pdu->e_token_length = 0;
  pdu->crit_opt = 0;
  pdu->mid = 0;
  pdu->max_opt = 0;
  pdu->max_size = size;
  pdu->used_size = 0;
  pdu->data = NULL;
  pdu->body_data = NULL;
  pdu->body_length = 0;
  pdu->body_offset = 0;
  pdu->body_total = 0;
  pdu->lg_xmit = NULL;
  pdu->session = NULL;
}

#ifdef WITH_LWIP
coap_pdu_t *
coap_pdu_from_pbuf(struct pbuf *pbuf) {
  coap_pdu_t *pdu;

  if (pbuf == NULL)
    return NULL;

  LWIP_ASSERT("Can only deal with contiguous PBUFs (increase PBUF_POOL_BUFSIZE)",
              pbuf->tot_len == pbuf->len);
  LWIP_ASSERT("coap_io_do_io needs to receive an exclusive copy of the incoming pbuf",
              pbuf->ref == 1);

  pdu = coap_malloc_type(COAP_PDU, sizeof(coap_pdu_t));
  if (!pdu) {
    pbuf_free(pbuf);
    return NULL;
  }

  pdu->max_hdr_size = COAP_PDU_MAX_UDP_HEADER_SIZE;
  pdu->pbuf = pbuf;
  pdu->token = (uint8_t *)pbuf->payload + pdu->max_hdr_size;
  pdu->alloc_size = pbuf->tot_len - pdu->max_hdr_size;
  coap_pdu_clear(pdu, pdu->alloc_size);

  return pdu;
}
#endif /* LWIP */

coap_pdu_t *
coap_pdu_init(coap_pdu_type_t type, coap_pdu_code_t code, coap_mid_t mid,
              size_t size) {
  coap_pdu_t *pdu;

#ifndef RIOT_VERSION
  assert(type <= 0x3);
  assert(code <= 0xff);
  assert(mid >= 0 && mid <= 0xffff);
#endif /* RIOT_VERSION */

#ifdef WITH_LWIP
#if MEMP_STATS
  /* Reserve 1 PDU for a response packet */
  if (memp_pools[MEMP_COAP_PDU]->stats->used + 1 >=
      memp_pools[MEMP_COAP_PDU]->stats->avail) {
    memp_pools[MEMP_COAP_PDU]->stats->err++;
    return NULL;
  }
#endif /* MEMP_STATS */
#endif /* LWIP */
  pdu = coap_malloc_type(COAP_PDU, sizeof(coap_pdu_t));
  if (!pdu)
    return NULL;

#if defined(WITH_CONTIKI) || defined(WITH_LWIP)
  assert(size <= COAP_DEFAULT_MAX_PDU_RX_SIZE);
  if (size > COAP_DEFAULT_MAX_PDU_RX_SIZE)
    return NULL;
  pdu->max_hdr_size = COAP_PDU_MAX_UDP_HEADER_SIZE;
#else
  pdu->max_hdr_size = COAP_PDU_MAX_TCP_HEADER_SIZE;
#endif

#ifdef WITH_LWIP
  pdu->pbuf = pbuf_alloc(PBUF_TRANSPORT, size + pdu->max_hdr_size, PBUF_RAM);
  if (pdu->pbuf == NULL) {
    coap_free_type(COAP_PDU, pdu);
    return NULL;
  }
  pdu->token = (uint8_t *)pdu->pbuf->payload + pdu->max_hdr_size;
#else /* WITH_LWIP */
  uint8_t *buf;
  pdu->alloc_size = min(size, 256);
  buf = coap_malloc_type(COAP_PDU_BUF, pdu->alloc_size + pdu->max_hdr_size);
  if (buf == NULL) {
    coap_free_type(COAP_PDU, pdu);
    return NULL;
  }
  pdu->token = buf + pdu->max_hdr_size;
#endif /* WITH_LWIP */
  coap_pdu_clear(pdu, size);
  pdu->mid = mid;
  pdu->type = type;
  pdu->code = code;
  return pdu;
}

coap_pdu_t *
coap_new_pdu(coap_pdu_type_t type, coap_pdu_code_t code,
             coap_session_t *session) {
  coap_pdu_t *pdu;

  coap_lock_check_locked(session->context);
  pdu = coap_pdu_init(type, code, coap_new_message_id(session),
                      coap_session_max_pdu_size(session));
  if (!pdu)
    coap_log_crit("coap_new_pdu: cannot allocate memory for new PDU\n");
  return pdu;
}

void
coap_delete_pdu(coap_pdu_t *pdu) {
  if (pdu != NULL) {
#ifdef WITH_LWIP
    pbuf_free(pdu->pbuf);
#else
    if (pdu->token != NULL)
      coap_free_type(COAP_PDU_BUF, pdu->token - pdu->max_hdr_size);
#endif
    coap_free_type(COAP_PDU, pdu);
  }
}

/*
 * Note: This does not include any data, just the token and options
 */
coap_pdu_t *
coap_pdu_duplicate(const coap_pdu_t *old_pdu,
                   coap_session_t *session,
                   size_t token_length,
                   const uint8_t *token,
                   coap_opt_filter_t *drop_options) {
  uint8_t doing_first = session->doing_first;
  coap_pdu_t *pdu;

  coap_lock_check_locked(session->context);
  /*
   * Need to make sure that coap_session_max_pdu_size() immediately
   * returns, rather than wait for the first CSM response from remote
   * that indicates BERT size (TCP/TLS only) as this may be called early
   * the OSCORE logic.
   */
  session->doing_first = 0;
  pdu = coap_pdu_init(old_pdu->type, old_pdu->code,
                      coap_new_message_id(session),
                      max(old_pdu->max_size,
                          coap_session_max_pdu_size(session)));
  /* Restore any pending waits */
  session->doing_first = doing_first;
  if (pdu == NULL)
    return NULL;

  coap_add_token(pdu, token_length, token);
  pdu->lg_xmit = old_pdu->lg_xmit;

  if (drop_options == NULL) {
    /* Drop COAP_PAYLOAD_START as well if data */
    size_t length = old_pdu->used_size - old_pdu->e_token_length -
                    (old_pdu->data ?
                     old_pdu->used_size - (old_pdu->data - old_pdu->token) +1 : 0);
    if (!coap_pdu_resize(pdu, length + pdu->e_token_length))
      goto fail;
    /* Copy the options but not any data across */
    memcpy(pdu->token + pdu->e_token_length,
           old_pdu->token + old_pdu->e_token_length, length);
    pdu->used_size += length;
    pdu->max_opt = old_pdu->max_opt;
  } else {
    /* Copy across all the options the slow way */
    coap_opt_iterator_t opt_iter;
    coap_opt_t *option;

    coap_option_iterator_init(old_pdu, &opt_iter, COAP_OPT_ALL);
    while ((option = coap_option_next(&opt_iter))) {
      if (drop_options && coap_option_filter_get(drop_options, opt_iter.number))
        continue;
      if (!coap_add_option_internal(pdu, opt_iter.number,
                                    coap_opt_length(option),
                                    coap_opt_value(option)))
        goto fail;
    }
  }
  return pdu;

fail:
  coap_delete_pdu(pdu);
  return NULL;
}


/*
 * The new size does not include the coap header (max_hdr_size)
 */
int
coap_pdu_resize(coap_pdu_t *pdu, size_t new_size) {
  if (new_size > pdu->alloc_size) {
#if !defined(WITH_LWIP)
    uint8_t *new_hdr;
    size_t offset;
#endif
    if (pdu->max_size && new_size > pdu->max_size) {
      coap_log_warn("coap_pdu_resize: pdu too big\n");
      return 0;
    }
#if !defined(WITH_LWIP)
    if (pdu->data != NULL) {
      assert(pdu->data > pdu->token);
      offset = pdu->data - pdu->token;
    } else {
      offset = 0;
    }
    new_hdr = (uint8_t *)coap_realloc_type(COAP_PDU_BUF,
                                           pdu->token - pdu->max_hdr_size,
                                           new_size + pdu->max_hdr_size);
    if (new_hdr == NULL) {
      coap_log_warn("coap_pdu_resize: realloc failed\n");
      return 0;
    }
    pdu->token = new_hdr + pdu->max_hdr_size;
    if (offset > 0)
      pdu->data = pdu->token + offset;
    else
      pdu->data = NULL;
    if (pdu->actual_token.length < COAP_TOKEN_EXT_1B_BIAS)
      pdu->actual_token.s = &pdu->token[0];
    else if (pdu->actual_token.length < COAP_TOKEN_EXT_2B_BIAS)
      pdu->actual_token.s = &pdu->token[1];
    else
      pdu->actual_token.s = &pdu->token[2];
#endif
  }
  pdu->alloc_size = new_size;
  return 1;
}

int
coap_pdu_check_resize(coap_pdu_t *pdu, size_t size) {
  if (size > pdu->alloc_size) {
    size_t new_size = max(256, pdu->alloc_size * 2);
    while (size > new_size)
      new_size *= 2;
    if (pdu->max_size && new_size > pdu->max_size) {
      new_size = pdu->max_size;
      if (new_size < size)
        return 0;
    }
    if (!coap_pdu_resize(pdu, new_size))
      return 0;
  }
  return 1;
}

int
coap_add_token(coap_pdu_t *pdu, size_t len, const uint8_t *data) {
  size_t bias = 0;

  /* must allow for pdu == NULL as callers may rely on this */
  if (!pdu)
    return 0;

  if (pdu->used_size) {
    coap_log_warn("coap_add_token: The token must defined first. Token ignored\n");
    return 0;
  }
  pdu->actual_token.length = len;
  if (len < COAP_TOKEN_EXT_1B_BIAS) {
    bias = 0;
  } else if (len < COAP_TOKEN_EXT_2B_BIAS) {
    bias = 1;
  } else if (len <= COAP_TOKEN_EXT_MAX) {
    bias = 2;
  } else {
    coap_log_warn("coap_add_token: Token size too large. Token ignored\n");
    return 0;
  }
  if (!coap_pdu_check_resize(pdu, len + bias)) {
    coap_log_warn("coap_add_token: Insufficient space for token. Token ignored\n");
    return 0;
  }

  pdu->actual_token.length = len;
  pdu->actual_token.s = &pdu->token[bias];
  pdu->e_token_length = (uint32_t)(len + bias);
  if (len) {
    switch (bias) {
    case 0:
      memcpy(pdu->token, data, len);
      break;
    case 1:
      pdu->token[0] = (uint8_t)(len - COAP_TOKEN_EXT_1B_BIAS);
      memcpy(&pdu->token[1], data, len);
      break;
    case 2:
      pdu->token[0] = (uint8_t)((len - COAP_TOKEN_EXT_2B_BIAS) >> 8);
      pdu->token[1] = (uint8_t)((len - COAP_TOKEN_EXT_2B_BIAS) & 0xff);
      memcpy(&pdu->token[2], data, len);
      break;
    default:
      break;
    }
  }
  pdu->max_opt = 0;
  pdu->used_size = len + bias;
  pdu->data = NULL;

  return 1;
}

/* It is assumed that coap_encode_var_safe8() has been called to reduce data */
int
coap_update_token(coap_pdu_t *pdu, size_t len, const uint8_t *data) {
  size_t bias = 0;

  /* must allow for pdu == NULL as callers may rely on this */
  if (!pdu)
    return 0;

  if (pdu->used_size == 0) {
    return coap_add_token(pdu, len, data);
  }
  if (len < COAP_TOKEN_EXT_1B_BIAS) {
    bias = 0;
  } else if (len < COAP_TOKEN_EXT_2B_BIAS) {
    bias = 1;
  } else if (len <= COAP_TOKEN_EXT_MAX) {
    bias = 2;
  } else {
    coap_log_warn("coap_add_token: Token size too large. Token ignored\n");
    return 0;
  }
  if ((len + bias) == pdu->e_token_length) {
    /* Easy case - just data has changed */
  } else if ((len + bias) > pdu->e_token_length) {
    if (!coap_pdu_check_resize(pdu,
                               pdu->used_size + (len + bias) - pdu->e_token_length)) {
      coap_log_warn("Failed to update token\n");
      return 0;
    }
    memmove(&pdu->token[(len + bias) - pdu->e_token_length],
            pdu->token, pdu->used_size);
    pdu->used_size += len + bias - pdu->e_token_length;
  } else {
    pdu->used_size -= pdu->e_token_length - (len + bias);
    memmove(pdu->token, &pdu->token[pdu->e_token_length - (len + bias)], pdu->used_size);
  }
  if (pdu->data) {
    pdu->data += (len + bias) - pdu->e_token_length;
  }

  pdu->actual_token.length = len;
  pdu->actual_token.s = &pdu->token[bias];
  pdu->e_token_length = (uint8_t)(len + bias);
  if (len) {
    switch (bias) {
    case 0:
      if (memcmp(pdu->token, data, len) != 0)
        memcpy(pdu->token, data, len);
      break;
    case 1:
      pdu->token[0] = (uint8_t)(len - COAP_TOKEN_EXT_1B_BIAS);
      memcpy(&pdu->token[1], data, len);
      break;
    case 2:
      pdu->token[0] = (uint8_t)((len - COAP_TOKEN_EXT_2B_BIAS) >> 8);
      pdu->token[1] = (uint8_t)((len - COAP_TOKEN_EXT_2B_BIAS) & 0xff);
      memcpy(&pdu->token[2], data, len);
      break;
    default:
      break;
    }
  }
  return 1;
}

int
coap_remove_option(coap_pdu_t *pdu, coap_option_num_t number) {
  coap_opt_iterator_t opt_iter;
  coap_opt_t *option;
  coap_opt_t *next_option = NULL;
  size_t opt_delta;
  coap_option_t decode_this;
  coap_option_t decode_next;

  /* Need to locate where in current options to remove this one */
  coap_option_iterator_init(pdu, &opt_iter, COAP_OPT_ALL);
  while ((option = coap_option_next(&opt_iter))) {
    if (opt_iter.number == number) {
      /* Found option to delete */
      break;
    }
  }
  if (!option)
    return 0;

  if (!coap_opt_parse(option, pdu->used_size - (option - pdu->token),
                      &decode_this))
    return 0;

  next_option = coap_option_next(&opt_iter);
  if (next_option) {
    if (!coap_opt_parse(next_option,
                        pdu->used_size - (next_option - pdu->token),
                        &decode_next))
      return 0;
    opt_delta = decode_this.delta + decode_next.delta;
    if (opt_delta < 13) {
      /* can simply update the delta of next option */
      next_option[0] = (next_option[0] & 0x0f) + (coap_opt_t)(opt_delta << 4);
    } else if (opt_delta < 269 && decode_next.delta < 13) {
      /* next option delta size increase */
      next_option -= 1;
      next_option[0] = (next_option[1] & 0x0f) + (13 << 4);
      next_option[1] = (coap_opt_t)(opt_delta - 13);
    } else if (opt_delta < 269) {
      /* can simply update the delta of next option */
      next_option[1] = (coap_opt_t)(opt_delta - 13);
    } else if (decode_next.delta < 13) { /* opt_delta >= 269 */
      /* next option delta size increase */
      if (next_option - option < 2) {
        /* Need to shuffle everything up by 1 before decrement */
        if (!coap_pdu_check_resize(pdu, pdu->used_size + 1))
          return 0;
        /* Possible a re-size took place with a realloc() */
        /* Need to rediscover this and next options */
        coap_option_iterator_init(pdu, &opt_iter, COAP_OPT_ALL);
        while ((option = coap_option_next(&opt_iter))) {
          if (opt_iter.number == number) {
            /* Found option to delete */
            break;
          }
        }
        next_option = coap_option_next(&opt_iter);
        assert(option != NULL);
        assert(next_option != NULL);
        memmove(&next_option[1], next_option,
                pdu->used_size - (next_option - pdu->token));
        pdu->used_size++;
        if (pdu->data)
          pdu->data++;
        next_option++;
      }
      next_option -= 2;
      next_option[0] = (next_option[2] & 0x0f) + (14 << 4);
      next_option[1] = (coap_opt_t)((opt_delta - 269) >> 8);
      next_option[2] = (opt_delta - 269) & 0xff;
    } else if (decode_next.delta < 269) { /* opt_delta >= 269 */
      /* next option delta size increase */
      next_option -= 1;
      next_option[0] = (next_option[1] & 0x0f) + (14 << 4);
      next_option[1] = (coap_opt_t)((opt_delta - 269) >> 8);
      next_option[2] = (opt_delta - 269) & 0xff;
    } else { /* decode_next.delta >= 269 && opt_delta >= 269 */
      next_option[1] = (coap_opt_t)((opt_delta - 269) >> 8);
      next_option[2] = (opt_delta - 269) & 0xff;
    }
  } else {
    next_option = option + coap_opt_encode_size(decode_this.delta,
                                                coap_opt_length(option));
    pdu->max_opt -= decode_this.delta;
  }
  if (pdu->used_size - (next_option - pdu->token))
    memmove(option, next_option, pdu->used_size - (next_option - pdu->token));
  pdu->used_size -= next_option - option;
  if (pdu->data)
    pdu->data -= next_option - option;
  return 1;
}

int
coap_option_check_repeatable(coap_option_num_t number) {
  /* Validate that the option is repeatable */
  switch (number) {
  /* Ignore list of genuine repeatable */
  case COAP_OPTION_IF_MATCH:
  case COAP_OPTION_ETAG:
  case COAP_OPTION_LOCATION_PATH:
  case COAP_OPTION_URI_PATH:
  case COAP_OPTION_URI_QUERY:
  case COAP_OPTION_LOCATION_QUERY:
  case COAP_OPTION_RTAG:
    break;
  /* Protest at the known non-repeatable options and ignore them */
  case COAP_OPTION_URI_HOST:
  case COAP_OPTION_IF_NONE_MATCH:
  case COAP_OPTION_OBSERVE:
  case COAP_OPTION_URI_PORT:
  case COAP_OPTION_OSCORE:
  case COAP_OPTION_CONTENT_FORMAT:
  case COAP_OPTION_MAXAGE:
  case COAP_OPTION_HOP_LIMIT:
  case COAP_OPTION_ACCEPT:
  case COAP_OPTION_BLOCK2:
  case COAP_OPTION_BLOCK1:
  case COAP_OPTION_SIZE2:
  case COAP_OPTION_PROXY_URI:
  case COAP_OPTION_PROXY_SCHEME:
  case COAP_OPTION_SIZE1:
  case COAP_OPTION_ECHO:
  case COAP_OPTION_NORESPONSE:
    coap_log_info("Option number %d is not defined as repeatable - dropped\n",
                  number);
    return 0;
  default:
    coap_log_info("Option number %d is not defined as repeatable\n",
                  number);
    /* Accepting it after warning as there may be user defineable options */
    break;
  }
  return 1;
}

size_t
coap_insert_option(coap_pdu_t *pdu, coap_option_num_t number, size_t len,
                   const uint8_t *data) {
  coap_opt_iterator_t opt_iter;
  coap_opt_t *option;
  uint16_t prev_number = 0;
  size_t shift;
  size_t opt_delta;
  coap_option_t decode;
  size_t shrink = 0;

  if (number >= pdu->max_opt)
    return coap_add_option_internal(pdu, number, len, data);

  /* Need to locate where in current options to insert this one */
  coap_option_iterator_init(pdu, &opt_iter, COAP_OPT_ALL);
  while ((option = coap_option_next(&opt_iter))) {
    if (opt_iter.number > number) {
      /* Found where to insert */
      break;
    }
    prev_number = opt_iter.number;
  }
  assert(option != NULL);
  /* size of option inc header to insert */
  shift = coap_opt_encode_size(number - prev_number, len);

  /* size of next option (header may shrink in size as delta changes */
  if (!coap_opt_parse(option, pdu->used_size - (option - pdu->token), &decode))
    return 0;
  opt_delta = opt_iter.number - number;
  if (opt_delta == 0) {
    if (!coap_option_check_repeatable(number))
      return 0;
  }

  if (!coap_pdu_check_resize(pdu,
                             pdu->used_size + shift - shrink))
    return 0;

  /* Possible a re-size took place with a realloc() */
  /* Need to locate where in current options to insert this one */
  coap_option_iterator_init(pdu, &opt_iter, COAP_OPT_ALL);
  while ((option = coap_option_next(&opt_iter))) {
    if (opt_iter.number > number) {
      /* Found where to insert */
      break;
    }
  }
  assert(option != NULL);

  if (decode.delta < 13) {
    /* can simply patch in the new delta of next option */
    option[0] = (option[0] & 0x0f) + (coap_opt_t)(opt_delta << 4);
  } else if (decode.delta < 269 && opt_delta < 13) {
    /* option header is going to shrink by one byte */
    option[1] = (option[0] & 0x0f) + (coap_opt_t)(opt_delta << 4);
    shrink = 1;
  } else if (decode.delta < 269 && opt_delta < 269) {
    /* can simply patch in the new delta of next option */
    option[1] = (coap_opt_t)(opt_delta - 13);
  } else if (opt_delta < 13) {
    /* option header is going to shrink by two bytes */
    option[2] = (option[0] & 0x0f) + (coap_opt_t)(opt_delta << 4);
    shrink = 2;
  } else if (opt_delta < 269) {
    /* option header is going to shrink by one bytes */
    option[1] = (option[0] & 0x0f) + 0xd0;
    option[2] = (coap_opt_t)(opt_delta - 13);
    shrink = 1;
  } else {
    /* can simply patch in the new delta of next option */
    option[1] = (coap_opt_t)((opt_delta - 269) >> 8);
    option[2] = (opt_delta - 269) & 0xff;
  }

  memmove(&option[shift], &option[shrink],
          pdu->used_size - (option - pdu->token) - shrink);
  if (!coap_opt_encode(option, pdu->alloc_size - pdu->used_size,
                       number - prev_number, data, len))
    return 0;

  pdu->used_size += shift - shrink;
  if (pdu->data)
    pdu->data += shift - shrink;
  return shift;
}

size_t
coap_update_option(coap_pdu_t *pdu, coap_option_num_t number, size_t len,
                   const uint8_t *data) {
  coap_opt_iterator_t opt_iter;
  coap_opt_t *option;
  coap_option_t decode;
  size_t new_length = 0;
  size_t old_length = 0;

  option = coap_check_option(pdu, number, &opt_iter);
  if (!option)
    return coap_insert_option(pdu, number, len, data);

  old_length = coap_opt_parse(option, (size_t)-1, &decode);
  if (old_length == 0)
    return 0;
  new_length = coap_opt_encode_size(decode.delta, len);

  if (new_length > old_length) {
    if (!coap_pdu_check_resize(pdu,
                               pdu->used_size + new_length - old_length))
      return 0;
    /* Possible a re-size took place with a realloc() */
    option = coap_check_option(pdu, number, &opt_iter);
  }

  if (new_length != old_length)
    memmove(&option[new_length], &option[old_length],
            pdu->used_size - (option - pdu->token) - old_length);

  if (!coap_opt_encode(option, new_length,
                       decode.delta, data, len))
    return 0;

  pdu->used_size += new_length - old_length;
  if (pdu->data)
    pdu->data += new_length - old_length;
  return 1;
}

size_t
coap_add_option(coap_pdu_t *pdu, coap_option_num_t number, size_t len,
                const uint8_t *data) {
  if (pdu->data) {
    coap_log_warn("coap_add_optlist_pdu: PDU already contains data\n");
    return 0;
  }
  return coap_add_option_internal(pdu, number, len, data);
}

size_t
coap_add_option_internal(coap_pdu_t *pdu, coap_option_num_t number, size_t len,
                         const uint8_t *data) {
  size_t optsize;
  coap_opt_t *opt;

  assert(pdu);

  if (number == pdu->max_opt) {
    if (!coap_option_check_repeatable(number))
      return 0;
  }

  if (COAP_PDU_IS_REQUEST(pdu) &&
      (number == COAP_OPTION_PROXY_URI ||
       number == COAP_OPTION_PROXY_SCHEME)) {
    /*
     * Need to check whether there is a hop-limit option.  If not, it needs
     * to be inserted by default (RFC 8768).
     */
    coap_opt_iterator_t opt_iter;

    if (coap_check_option(pdu, COAP_OPTION_HOP_LIMIT, &opt_iter) == NULL) {
      size_t hop_limit = COAP_OPTION_HOP_LIMIT;

      coap_insert_option(pdu, COAP_OPTION_HOP_LIMIT, 1, (uint8_t *)&hop_limit);
    }
  }

  if (number < pdu->max_opt) {
    coap_log_debug("coap_add_option: options are not in correct order\n");
    return coap_insert_option(pdu, number, len, data);
  }

  optsize = coap_opt_encode_size(number - pdu->max_opt, len);
  if (!coap_pdu_check_resize(pdu,
                             pdu->used_size + optsize))
    return 0;

  if (pdu->data) {
    /* include option delimiter */
    memmove(&pdu->data[optsize-1], &pdu->data[-1],
            pdu->used_size - (pdu->data - pdu->token) + 1);
    opt = pdu->data -1;
    pdu->data += optsize;
  } else {
    opt = pdu->token + pdu->used_size;
  }

  /* encode option and check length */
  optsize = coap_opt_encode(opt, pdu->alloc_size - pdu->used_size,
                            number - pdu->max_opt, data, len);

  if (!optsize) {
    coap_log_warn("coap_add_option: cannot add option\n");
    /* error */
    return 0;
  } else {
    pdu->max_opt = number;
    pdu->used_size += optsize;
  }

  return optsize;
}

int
coap_add_data(coap_pdu_t *pdu, size_t len, const uint8_t *data) {
  if (len == 0) {
    return 1;
  } else {
    uint8_t *payload = coap_add_data_after(pdu, len);
    if (payload != NULL)
      memcpy(payload, data, len);
    return payload != NULL;
  }
}

uint8_t *
coap_add_data_after(coap_pdu_t *pdu, size_t len) {
  assert(pdu);
  if (pdu->data) {
    coap_log_warn("coap_add_data: PDU already contains data\n");
    return 0;
  }

  if (len == 0)
    return NULL;

  if (!coap_pdu_resize(pdu, pdu->used_size + len + 1))
    return 0;
  pdu->token[pdu->used_size++] = COAP_PAYLOAD_START;
  pdu->data = pdu->token + pdu->used_size;
  pdu->used_size += len;
  return pdu->data;
}

int
coap_get_data(const coap_pdu_t *pdu, size_t *len, const uint8_t **data) {
  size_t offset;
  size_t total;

  return coap_get_data_large(pdu, len, data, &offset, &total);
}

int
coap_get_data_large(const coap_pdu_t *pdu, size_t *len, const uint8_t **data,
                    size_t *offset, size_t *total) {
  assert(pdu);
  assert(len);
  assert(data);

  *offset = pdu->body_offset;
  *total = pdu->body_total;
  if (pdu->body_data) {
    *data = pdu->body_data;
    *len = pdu->body_length;
    return 1;
  }
  *data = pdu->data;
  if (pdu->data == NULL) {
    *len = 0;
    *total = 0;
    return 0;
  }

  *len = pdu->used_size - (pdu->data - pdu->token);
  if (*total == 0)
    *total = *len;

  return 1;
}

#ifndef SHORT_ERROR_RESPONSE
typedef struct {
  unsigned char code;
  const char *phrase;
} error_desc_t;

/* if you change anything here, make sure, that the longest string does not
 * exceed COAP_ERROR_PHRASE_LENGTH. */
error_desc_t coap_error[] = {
  { COAP_RESPONSE_CODE(201), "Created" },
  { COAP_RESPONSE_CODE(202), "Deleted" },
  { COAP_RESPONSE_CODE(203), "Valid" },
  { COAP_RESPONSE_CODE(204), "Changed" },
  { COAP_RESPONSE_CODE(205), "Content" },
  { COAP_RESPONSE_CODE(231), "Continue" },
  { COAP_RESPONSE_CODE(400), "Bad Request" },
  { COAP_RESPONSE_CODE(401), "Unauthorized" },
  { COAP_RESPONSE_CODE(402), "Bad Option" },
  { COAP_RESPONSE_CODE(403), "Forbidden" },
  { COAP_RESPONSE_CODE(404), "Not Found" },
  { COAP_RESPONSE_CODE(405), "Method Not Allowed" },
  { COAP_RESPONSE_CODE(406), "Not Acceptable" },
  { COAP_RESPONSE_CODE(408), "Request Entity Incomplete" },
  { COAP_RESPONSE_CODE(409), "Conflict" },
  { COAP_RESPONSE_CODE(412), "Precondition Failed" },
  { COAP_RESPONSE_CODE(413), "Request Entity Too Large" },
  { COAP_RESPONSE_CODE(415), "Unsupported Content-Format" },
  { COAP_RESPONSE_CODE(422), "Unprocessable" },
  { COAP_RESPONSE_CODE(429), "Too Many Requests" },
  { COAP_RESPONSE_CODE(500), "Internal Server Error" },
  { COAP_RESPONSE_CODE(501), "Not Implemented" },
  { COAP_RESPONSE_CODE(502), "Bad Gateway" },
  { COAP_RESPONSE_CODE(503), "Service Unavailable" },
  { COAP_RESPONSE_CODE(504), "Gateway Timeout" },
  { COAP_RESPONSE_CODE(505), "Proxying Not Supported" },
  { COAP_RESPONSE_CODE(508), "Hop Limit Reached" },
  { 0, NULL }                        /* end marker */
};

const char *
coap_response_phrase(unsigned char code) {
  int i;
  for (i = 0; coap_error[i].code; ++i) {
    if (coap_error[i].code == code)
      return coap_error[i].phrase;
  }
  return NULL;
}
#endif

/**
 * Advances *optp to next option if still in PDU. This function
 * returns the number of bytes opt has been advanced or @c 0
 * on error.
 */
static size_t
next_option_safe(coap_opt_t **optp, size_t *length, uint16_t *max_opt) {
  coap_option_t option;
  size_t optsize;

  assert(optp);
  assert(*optp);
  assert(length);

  optsize = coap_opt_parse(*optp, *length, &option);
  if (optsize) {
    assert(optsize <= *length);

    /* signal an error if this option would exceed the
     * allowed number space */
    if (*max_opt + option.delta > COAP_MAX_OPT) {
      return 0;
    }
    *max_opt += option.delta;
    *optp += optsize;
    *length -= optsize;
  }

  return optsize;
}

size_t
coap_pdu_parse_header_size(coap_proto_t proto,
                           const uint8_t *data) {
  assert(data);
  size_t header_size = 0;

  if (proto == COAP_PROTO_TCP || proto==COAP_PROTO_TLS) {
    uint8_t len = *data >> 4;
    if (len < 13)
      header_size = 2;
    else if (len==13)
      header_size = 3;
    else if (len==14)
      header_size = 4;
    else
      header_size = 6;
  } else if (proto == COAP_PROTO_WS || proto==COAP_PROTO_WSS) {
    header_size = 2;
  } else if (proto == COAP_PROTO_UDP || proto==COAP_PROTO_DTLS) {
    header_size = 4;
  }

  return header_size;
}

#if !COAP_DISABLE_TCP
/*
 * strm
 * return +ve  PDU size including token
 *          0  PDU does not parse
 */
size_t
coap_pdu_parse_size(coap_proto_t proto,
                    const uint8_t *data,
                    size_t length) {
  assert(data);
  assert(proto == COAP_PROTO_TCP || proto == COAP_PROTO_TLS ||
         proto == COAP_PROTO_WS || proto == COAP_PROTO_WSS);
  assert(coap_pdu_parse_header_size(proto, data) <= length);

  size_t size = 0;
  const uint8_t *token_start = NULL;

  if ((proto == COAP_PROTO_TCP || proto == COAP_PROTO_TLS) && length >= 1) {
    uint8_t len = *data >> 4;
    uint8_t tkl = *data & 0x0f;

    if (len < 13) {
      size = len;
      token_start = &data[2];
    } else if (length >= 2) {
      if (len==13) {
        size = (size_t)data[1] + COAP_MESSAGE_SIZE_OFFSET_TCP8;
        token_start = &data[3];
      } else if (length >= 3) {
        if (len==14) {
          size = ((size_t)data[1] << 8) + data[2] + COAP_MESSAGE_SIZE_OFFSET_TCP16;
          token_start = &data[4];
        } else if (length >= 5) {
          size = ((size_t)data[1] << 24) + ((size_t)data[2] << 16)
                 + ((size_t)data[3] << 8) + data[4] + COAP_MESSAGE_SIZE_OFFSET_TCP32;
          token_start = &data[6];
        }
      }
    }
    if (token_start) {
      /* account for the token length */
      if (tkl < COAP_TOKEN_EXT_1B_TKL) {
        size += tkl;
      } else if (tkl == COAP_TOKEN_EXT_1B_TKL) {
        size += token_start[0] + COAP_TOKEN_EXT_1B_BIAS + 1;
      } else if (tkl == COAP_TOKEN_EXT_2B_TKL) {
        size += ((uint16_t)token_start[0] << 8) + token_start[1] +
                COAP_TOKEN_EXT_2B_BIAS + 2;
      } else {
        /* Invalid at this point - caught later as undersized */
      }
    }
  }

  return size;
}
#endif /* ! COAP_DISABLE_TCP */

int
coap_pdu_parse_header(coap_pdu_t *pdu, coap_proto_t proto) {
  uint8_t *hdr = pdu->token - pdu->hdr_size;
  uint8_t e_token_length;

  if (proto == COAP_PROTO_UDP || proto == COAP_PROTO_DTLS) {
    assert(pdu->hdr_size == 4);
    if ((hdr[0] >> 6) != COAP_DEFAULT_VERSION) {
      coap_log_debug("coap_pdu_parse: UDP version not supported\n");
      return 0;
    }
    pdu->type = (hdr[0] >> 4) & 0x03;
    pdu->code = hdr[1];
    pdu->mid = (uint16_t)hdr[2] << 8 | hdr[3];
  } else if (proto == COAP_PROTO_TCP || proto == COAP_PROTO_TLS) {
    assert(pdu->hdr_size >= 2 && pdu->hdr_size <= 6);
    pdu->type = COAP_MESSAGE_CON;
    pdu->code = hdr[pdu->hdr_size-1];
    pdu->mid = 0;
  } else if (proto == COAP_PROTO_WS || proto == COAP_PROTO_WSS) {
    assert(pdu->hdr_size == 2);
    pdu->type = COAP_MESSAGE_CON;
    pdu->code = hdr[pdu->hdr_size-1];
    pdu->mid = 0;
  } else {
    coap_log_debug("coap_pdu_parse: unsupported protocol\n");
    return 0;
  }

  e_token_length = hdr[0] & 0x0f;
  if (e_token_length < COAP_TOKEN_EXT_1B_TKL) {
    pdu->e_token_length = e_token_length;
    pdu->actual_token.length = pdu->e_token_length;
    pdu->actual_token.s = &pdu->token[0];
  } else if (e_token_length == COAP_TOKEN_EXT_1B_TKL) {
    pdu->e_token_length = pdu->token[0] + COAP_TOKEN_EXT_1B_BIAS + 1;
    pdu->actual_token.length = pdu->e_token_length - 1;
    pdu->actual_token.s = &pdu->token[1];
  } else if (e_token_length == COAP_TOKEN_EXT_2B_TKL) {
    pdu->e_token_length = ((uint16_t)pdu->token[0] << 8) + pdu->token[1] +
                          COAP_TOKEN_EXT_2B_BIAS + 2;
    pdu->actual_token.length = pdu->e_token_length - 2;
    pdu->actual_token.s = &pdu->token[2];
  }
  if (pdu->e_token_length > pdu->alloc_size || e_token_length == 15) {
    /* Invalid PDU provided - not wise to assert here though */
    coap_log_debug("coap_pdu_parse: PDU header token size broken\n");
    pdu->e_token_length = 0;
    pdu->actual_token.length = 0;
    return 0;
  }
  return 1;
}

static int
coap_pdu_parse_opt_csm(coap_pdu_t *pdu, uint16_t len) {
  switch ((coap_pdu_signaling_proto_t)pdu->code) {
  case COAP_SIGNALING_CSM:
    switch (pdu->max_opt) {
    case COAP_SIGNALING_OPTION_MAX_MESSAGE_SIZE:
      if (len > 4)
        goto bad;
      break;
    case COAP_SIGNALING_OPTION_BLOCK_WISE_TRANSFER:
      if (len > 0)
        goto bad;
      break;
    case COAP_SIGNALING_OPTION_EXTENDED_TOKEN_LENGTH:
      if (len > 3)
        goto bad;
      break;
    default:
      if (pdu->max_opt & 0x01)
        goto bad; /* Critical */
    }
    break;
  case COAP_SIGNALING_PING:
  case COAP_SIGNALING_PONG:
    switch (pdu->max_opt) {
    case COAP_SIGNALING_OPTION_CUSTODY:
      if (len > 0)
        goto bad;
      break;
    default:
      if (pdu->max_opt & 0x01)
        goto bad; /* Critical */
    }
    break;
  case COAP_SIGNALING_RELEASE:
    switch (pdu->max_opt) {
    case COAP_SIGNALING_OPTION_ALTERNATIVE_ADDRESS:
      if (len < 1 || len > 255)
        goto bad;
      break;
    case COAP_SIGNALING_OPTION_HOLD_OFF:
      if (len > 3)
        goto bad;
      break;
    default:
      if (pdu->max_opt & 0x01)
        goto bad; /* Critical */
    }
    break;
  case COAP_SIGNALING_ABORT:
    switch (pdu->max_opt) {
    case COAP_SIGNALING_OPTION_BAD_CSM_OPTION:
      if (len > 2)
        goto bad;
      break;
    default:
      if (pdu->max_opt & 0x01)
        goto bad; /* Critical */
    }
    break;
  default:
    ;
  }
  return 1;
bad:
  return 0;
}

static int
coap_pdu_parse_opt_base(coap_pdu_t *pdu, uint16_t len) {
  int res = 1;

  switch (pdu->max_opt) {
  case COAP_OPTION_IF_MATCH:
    if (len > 8)
      res = 0;
    break;
  case COAP_OPTION_URI_HOST:
    if (len < 1 || len > 255)
      res = 0;
    break;
  case COAP_OPTION_ETAG:
    if (len < 1 || len > 8)
      res = 0;
    break;
  case COAP_OPTION_IF_NONE_MATCH:
    if (len != 0)
      res = 0;
    break;
  case COAP_OPTION_OBSERVE:
    if (len > 3)
      res = 0;
    break;
  case COAP_OPTION_URI_PORT:
    if (len > 2)
      res = 0;
    break;
  case COAP_OPTION_LOCATION_PATH:
    if (len > 255)
      res = 0;
    break;
  case COAP_OPTION_OSCORE:
    if (len > 255)
      res = 0;
    break;
  case COAP_OPTION_URI_PATH:
    if (len > 255)
      res = 0;
    break;
  case COAP_OPTION_CONTENT_FORMAT:
    if (len > 2)
      res = 0;
    break;
  case COAP_OPTION_MAXAGE:
    if (len > 4)
      res = 0;
    break;
  case COAP_OPTION_URI_QUERY:
    if (len < 1 || len > 255)
      res = 0;
    break;
  case COAP_OPTION_HOP_LIMIT:
    if (len != 1)
      res = 0;
    break;
  case COAP_OPTION_ACCEPT:
    if (len > 2)
      res = 0;
    break;
  case COAP_OPTION_LOCATION_QUERY:
    if (len > 255)
      res = 0;
    break;
  case COAP_OPTION_BLOCK2:
    if (len > 3)
      res = 0;
    break;
  case COAP_OPTION_BLOCK1:
    if (len > 3)
      res = 0;
    break;
  case COAP_OPTION_SIZE2:
    if (len > 4)
      res = 0;
    break;
  case COAP_OPTION_PROXY_URI:
    if (len < 1 || len > 1034)
      res = 0;
    break;
  case COAP_OPTION_PROXY_SCHEME:
    if (len < 1 || len > 255)
      res = 0;
    break;
  case COAP_OPTION_SIZE1:
    if (len > 4)
      res = 0;
    break;
  case COAP_OPTION_ECHO:
    if (len > 40)
      res = 0;
    break;
  case COAP_OPTION_NORESPONSE:
    if (len > 1)
      res = 0;
    break;
  case COAP_OPTION_RTAG:
    if (len > 8)
      res = 0;
    break;
  default:
    ;
  }
  return res;
}

static int
write_prefix(char **obp, size_t *len, const char *prf, size_t prflen) {
  /* Make sure space for null terminating byte */
  if (*len < prflen +1) {
    return 0;
  }

  memcpy(*obp, prf, prflen);
  *obp += prflen;
  *len -= prflen;
  return 1;
}

static int
write_char(char **obp, size_t *len, int c, int printable) {
  /* Make sure space for null terminating byte */
  if (*len < 2 +1) {
    return 0;
  }

  if (!printable) {
    const uint8_t hex[] = "0123456789abcdef";
    (*obp)[0] = hex[(c & 0xf0) >> 4];
    (*obp)[1] = hex[c & 0x0f];
  } else {
    (*obp)[0] = isprint(c) ? c : '.';
    (*obp)[1] = ' ';
  }
  *obp += 2;
  *len -= 2;
  return 1;
}

int
coap_pdu_parse_opt(coap_pdu_t *pdu) {

  int good = 1;
  /* sanity checks */
  if (pdu->code == 0) {
    if (pdu->used_size != 0 || pdu->e_token_length) {
      coap_log_debug("coap_pdu_parse: empty message is not empty\n");
      return 0;
    }
  }

  if (pdu->e_token_length > pdu->used_size) {
    coap_log_debug("coap_pdu_parse: invalid Token\n");
    return 0;
  }

  pdu->max_opt = 0;
  if (pdu->code == 0) {
    /* empty packet */
    pdu->used_size = 0;
    pdu->data = NULL;
  } else {
    /* skip header + token */
    coap_opt_t *opt = pdu->token + pdu->e_token_length;
    size_t length = pdu->used_size - pdu->e_token_length;

    while (length > 0 && *opt != COAP_PAYLOAD_START) {
#if (COAP_MAX_LOGGING_LEVEL >= _COAP_LOG_WARN)
      coap_opt_t *opt_last = opt;
#endif
      size_t optsize = next_option_safe(&opt, &length, &pdu->max_opt);
      const uint32_t len =
          optsize ? coap_opt_length((const uint8_t *)opt - optsize) : 0;
      if (optsize == 0) {
        coap_log_debug("coap_pdu_parse: %d.%02d: offset %u malformed option\n",
                       pdu->code >> 5, pdu->code & 0x1F,
                       (int)(opt_last - pdu->token - pdu->e_token_length));
        good = 0;
        break;
      }
      if (COAP_PDU_IS_SIGNALING(pdu) ?
          !coap_pdu_parse_opt_csm(pdu, len) :
          !coap_pdu_parse_opt_base(pdu, len)) {
        coap_log_warn("coap_pdu_parse: %d.%02d: offset %u option %u has bad length %" PRIu32 "\n",
                      pdu->code >> 5, pdu->code & 0x1F,
                      (int)(opt_last - pdu->token - pdu->e_token_length), pdu->max_opt,
                      len);
        good = 0;
      }
    }

    if (!good) {
      /*
       * Dump the options in the PDU for analysis, space separated except
       * error options which are prefixed by *
       * Two rows - hex and ascii (if printable)
       */
      static char outbuf[COAP_DEBUG_BUF_SIZE];
      char *obp;
      size_t tlen;
      size_t outbuflen;
      int i;
      int ok;

      for (i = 0; i < 2; i++) {
        opt = pdu->token + pdu->e_token_length;
        length = pdu->used_size - pdu->e_token_length;
        pdu->max_opt = 0;

        outbuflen = sizeof(outbuf);
        obp = outbuf;
        ok = write_prefix(&obp, &outbuflen, "O: ", 3);
        while (length > 0 && *opt != COAP_PAYLOAD_START) {
          coap_opt_t *opt_last = opt;
          size_t optsize = next_option_safe(&opt, &length, &pdu->max_opt);
          const uint32_t len =
              optsize ? coap_opt_length((const uint8_t *)opt - optsize) : 0;
          if (!optsize || (COAP_PDU_IS_SIGNALING(pdu) ?
                           !coap_pdu_parse_opt_csm(pdu, len) :
                           !coap_pdu_parse_opt_base(pdu, len))) {
            ok = ok && write_prefix(&obp, &outbuflen, "*", 1);
            if (!optsize) {
              /* Skip to end of options to output all data */
              opt = pdu->token + pdu->used_size;
              length = 0;
            }
          } else {
            ok = ok && write_prefix(&obp, &outbuflen, " ", 1);
          }
          tlen = opt - opt_last;
          while (tlen--) {
            ok = ok && write_char(&obp, &outbuflen, *opt_last, i);
            opt_last++;
          }
        }
        if (length && *opt == COAP_PAYLOAD_START) {
          ok = ok && write_char(&obp, &outbuflen, *opt, i);
        }
        /* write_*() always leaves a spare byte to null terminate */
        *obp = '\000';
        coap_log_debug("%s\n", outbuf);
      }
    }

    if (length > 0) {
      assert(*opt == COAP_PAYLOAD_START);
      opt++;
      length--;

      if (length == 0) {
        coap_log_debug("coap_pdu_parse: message ending in payload start marker\n");
        return 0;
      }
    }
    if (length > 0)
      pdu->data = (uint8_t *)opt;
    else
      pdu->data = NULL;
  }

  return good;
}

int
coap_pdu_parse(coap_proto_t proto,
               const uint8_t *data,
               size_t length,
               coap_pdu_t *pdu) {
  size_t hdr_size;

  if (length == 0)
    return 0;
  hdr_size = coap_pdu_parse_header_size(proto, data);
  if (!hdr_size || hdr_size > length)
    return 0;
  if (hdr_size > pdu->max_hdr_size)
    return 0;
  if (!coap_pdu_resize(pdu, length - hdr_size))
    return 0;
  if (pdu->token - hdr_size != data)
    memcpy(pdu->token - hdr_size, data, length);
  pdu->hdr_size = (uint8_t)hdr_size;
  pdu->used_size = length - hdr_size;
  return coap_pdu_parse_header(pdu, proto) && coap_pdu_parse_opt(pdu);
}

size_t
coap_pdu_encode_header(coap_pdu_t *pdu, coap_proto_t proto) {
  uint8_t e_token_length;

  if (pdu->actual_token.length < COAP_TOKEN_EXT_1B_BIAS) {
    e_token_length = (uint8_t)pdu->actual_token.length;
  } else if (pdu->actual_token.length < COAP_TOKEN_EXT_2B_BIAS) {
    e_token_length = COAP_TOKEN_EXT_1B_TKL;
  } else if (pdu->actual_token.length <= COAP_TOKEN_EXT_MAX) {
    e_token_length = COAP_TOKEN_EXT_2B_TKL;
  } else {
    coap_log_warn("coap_add_token: Token size too large. PDU ignored\n");
    return 0;
  }
  if (COAP_PROTO_NOT_RELIABLE(proto)) {
    assert(pdu->max_hdr_size >= 4);
    if (pdu->max_hdr_size < 4) {
      coap_log_warn("coap_pdu_encode_header: not enough space for UDP-style header\n");
      return 0;
    }
    pdu->token[-4] = COAP_DEFAULT_VERSION << 6
                     | pdu->type << 4
                     | e_token_length;
    pdu->token[-3] = pdu->code;
    pdu->token[-2] = (uint8_t)(pdu->mid >> 8);
    pdu->token[-1] = (uint8_t)(pdu->mid);
    pdu->hdr_size = 4;
#if !COAP_DISABLE_TCP
  } else if (COAP_PROTO_RELIABLE(proto)) {
    size_t len;
    assert(pdu->used_size >= pdu->e_token_length);
    if (pdu->used_size < pdu->e_token_length) {
      coap_log_warn("coap_pdu_encode_header: corrupted PDU\n");
      return 0;
    }

    /* A lot of the reliable code assumes type is CON */
    if (pdu->type != COAP_MESSAGE_CON)
      pdu->type = COAP_MESSAGE_CON;

    if (proto == COAP_PROTO_WS || proto == COAP_PROTO_WSS)
      len = 0;
    else
      len = pdu->used_size - pdu->e_token_length;
    if (len <= COAP_MAX_MESSAGE_SIZE_TCP0) {
      assert(pdu->max_hdr_size >= 2);
      if (pdu->max_hdr_size < 2) {
        coap_log_warn("coap_pdu_encode_header: not enough space for TCP0 header\n");
        return 0;
      }
      pdu->token[-2] = (uint8_t)len << 4
                       | e_token_length;
      pdu->token[-1] = pdu->code;
      pdu->hdr_size = 2;
    } else if (len <= COAP_MAX_MESSAGE_SIZE_TCP8) {
      assert(pdu->max_hdr_size >= 3);
      if (pdu->max_hdr_size < 3) {
        coap_log_warn("coap_pdu_encode_header: not enough space for TCP8 header\n");
        return 0;
      }
      pdu->token[-3] = 13 << 4 | e_token_length;
      pdu->token[-2] = (uint8_t)(len - COAP_MESSAGE_SIZE_OFFSET_TCP8);
      pdu->token[-1] = pdu->code;
      pdu->hdr_size = 3;
    } else if (len <= COAP_MAX_MESSAGE_SIZE_TCP16) {
      assert(pdu->max_hdr_size >= 4);
      if (pdu->max_hdr_size < 4) {
        coap_log_warn("coap_pdu_encode_header: not enough space for TCP16 header\n");
        return 0;
      }
      pdu->token[-4] = 14 << 4 | e_token_length;
      pdu->token[-3] = (uint8_t)((len - COAP_MESSAGE_SIZE_OFFSET_TCP16) >> 8);
      pdu->token[-2] = (uint8_t)(len - COAP_MESSAGE_SIZE_OFFSET_TCP16);
      pdu->token[-1] = pdu->code;
      pdu->hdr_size = 4;
    } else {
      assert(pdu->max_hdr_size >= 6);
      if (pdu->max_hdr_size < 6) {
        coap_log_warn("coap_pdu_encode_header: not enough space for TCP32 header\n");
        return 0;
      }
      pdu->token[-6] = 15 << 4 | e_token_length;
      pdu->token[-5] = (uint8_t)((len - COAP_MESSAGE_SIZE_OFFSET_TCP32) >> 24);
      pdu->token[-4] = (uint8_t)((len - COAP_MESSAGE_SIZE_OFFSET_TCP32) >> 16);
      pdu->token[-3] = (uint8_t)((len - COAP_MESSAGE_SIZE_OFFSET_TCP32) >> 8);
      pdu->token[-2] = (uint8_t)(len - COAP_MESSAGE_SIZE_OFFSET_TCP32);
      pdu->token[-1] = pdu->code;
      pdu->hdr_size = 6;
    }
#endif /* ! COAP_DISABLE_TCP */
  } else {
    coap_log_warn("coap_pdu_encode_header: unsupported protocol\n");
  }
  return pdu->hdr_size;
}

coap_pdu_code_t
coap_pdu_get_code(const coap_pdu_t *pdu) {
  return pdu->code;
}

void
coap_pdu_set_code(coap_pdu_t *pdu, coap_pdu_code_t code) {
#ifndef RIOT_VERSION
  assert(code <= 0xff);
#endif /* RIOT_VERSION */
  pdu->code = code;
}

coap_pdu_type_t
coap_pdu_get_type(const coap_pdu_t *pdu) {
  return pdu->type;
}

void
coap_pdu_set_type(coap_pdu_t *pdu, coap_pdu_type_t type) {
  assert(type <= 0x3);
  pdu->type = type;
}

coap_bin_const_t
coap_pdu_get_token(const coap_pdu_t *pdu) {
  return pdu->actual_token;
}

coap_mid_t
coap_pdu_get_mid(const coap_pdu_t *pdu) {
  return pdu->mid;
}

void
coap_pdu_set_mid(coap_pdu_t *pdu, coap_mid_t mid) {
#if (UINT_MAX > 65535)
  assert(mid >= 0 && mid <= 0xffff);
#endif /* UINT_MAX > 65535 */
  pdu->mid = mid;
}
