/* pdu.c -- CoAP message structure
 *
 * Copyright (C) 2010--2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

#include "coap_config.h"

#if defined(HAVE_ASSERT_H) && !defined(assert)
# include <assert.h>
#endif

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

#include "libcoap.h"
#include "debug.h"
#include "pdu.h"
#include "option.h"
#include "encode.h"
#include "mem.h"
#include "coap_session.h"

void
coap_pdu_clear(coap_pdu_t *pdu, size_t size) {
  assert(pdu);
  assert(pdu->token);
  assert(pdu->max_hdr_size >= COAP_PDU_MAX_UDP_HEADER_SIZE);
  pdu->type = 0;
  pdu->code = 0;
  pdu->token_length = 0;
  pdu->tid = 0;
  pdu->max_delta = 0;
  pdu->max_size = size;
  pdu->used_size = 0;
  pdu->data = NULL;
}

#ifdef WITH_LWIP
coap_pdu_t *
coap_pdu_from_pbuf( struct pbuf *pbuf )
{
  coap_pdu_t *pdu;

  if (pbuf == NULL) return NULL;

  LWIP_ASSERT("Can only deal with contiguous PBUFs", pbuf->tot_len == pbuf->len);
  LWIP_ASSERT("coap_read needs to receive an exclusive copy of the incoming pbuf", pbuf->ref == 1);

  pdu = coap_malloc_type(COAP_PDU, sizeof(coap_pdu_t) );
  if (!pdu) {
    pbuf_free(pbuf);
    return NULL;
  }

  pdu->max_hdr_size = COAP_PDU_MAX_UDP_HEADER_SIZE;
  pdu->pbuf = pbuf;
  pdu->token = pbuf->payload + pdu->max_hdr_size;
  coap_pdu_clear(pdu, pbuf->tot_len - pdu->max_hdr_size);

  return pdu;
}
#endif

coap_pdu_t *
coap_pdu_init(uint8_t type, uint8_t code, uint16_t tid, size_t size) {
  coap_pdu_t *pdu;
  uint8_t *buf;

#ifdef WITH_CONTIKI
  if (size == 0)
    size = COAP_RXBUFFER_SIZE - COAP_PDU_MAX_UDP_HEADER_SIZE;
  assert(size <= COAP_RXBUFFER_SIZE - COAP_PDU_MAX_UDP_HEADER_SIZE);
  if (size > COAP_RXBUFFER_SIZE - COAP_PDU_MAX_UDP_HEADER_SIZE)
    return NULL;
#else
  if (size == 0)
    size = 256;
#endif

  pdu = coap_malloc_type(COAP_PDU, sizeof(coap_pdu_t));
  if (!pdu) return NULL;

#if defined(WITH_CONTIKI) || defined(WITH_LWIP)
  pdu->max_hdr_size = COAP_PDU_MAX_UDP_HEADER_SIZE;
#else
  pdu->max_hdr_size = COAP_PDU_MAX_TCP_HEADER_SIZE;
#endif

#ifdef WITH_LWIP
  pdu->pbuf = pbuf_alloc(PBUF_TRANSPORT, size + pdu->max_hdr_size, PBUF_RAM);
  if (pdu->pbuf == NULL) {
    coap_free_type(COAP_PDU, pdu);
    pdu = NULL;
  }
  pdu->token = pdu->pbuf->payload + pdu->max_hdr_size;
  size = pbuf->tot_len - pdu->max_hdr_size;
#else /* WITH_LWIP */
  buf = coap_malloc_type(COAP_PDU_BUF, size + pdu->max_hdr_size);
  if (buf == NULL) {
    coap_free_type(COAP_PDU, pdu);
    pdu = NULL;
  }
  pdu->token = buf + pdu->max_hdr_size;
#endif /* WITH_LWIP */
  coap_pdu_clear(pdu, size);
  pdu->tid = tid;
  pdu->type = type;
  pdu->code = code;
  return pdu;
}

coap_pdu_t *
coap_new_pdu() {
  coap_pdu_t *pdu = coap_pdu_init(0, 0, 0, 0);
#ifndef NDEBUG
  if (!pdu)
    coap_log(LOG_CRIT, "coap_new_pdu: cannot allocate memory for new PDU\n");
#endif
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

static int coap_pdu_resize(coap_pdu_t *pdu, size_t new_size) {
  if (new_size > pdu->max_size) {
#if defined(WITH_LWIP)
    if (new_size > pbuf->tot_len - pdu->max_hdr_size) {
      warn( "coap_pdu_resize: pdu too big\n" );
      return NULL;
    }
#elif defined(WITH_CONTIKI)
    if (new_size > COAP_RXBUFFER_SIZE - COAP_PDU_MAX_UDP_HEADER_SIZE) {
      warn( "coap_pdu_resize: pdu too big\n" );
      return NULL;
    }
#else
    uint8_t *new_hdr;
    size_t offset = 0;
    if (pdu->data != NULL) {
      assert(pdu->data > pdu->token);
      offset = pdu->data - pdu->token;
    }
    new_hdr = (uint8_t*)realloc(pdu->token - pdu->max_hdr_size, new_size + pdu->max_hdr_size);
    if (new_hdr == NULL) {
      warn("coap_pdu_resize: realloc failed\n");
      return 0;
    }
    pdu->token = new_hdr + pdu->max_hdr_size;
    if (offset > 0)
      pdu->data = pdu->token + offset;
    else
      pdu->data = NULL;
#endif
  }
  pdu->max_size = new_size;
  return 1;
}

static int
coap_pdu_check_resize(coap_pdu_t *pdu, size_t size) {
  if (size > pdu->max_size) {
#if defined(WITH_LWIP) || defined(WITH_CONTIKI)
    warn("coap_pdu_check_resize: cannot resize\n");
    return 0;
#endif
    size_t new_size = pdu->max_size * 2;
    while (size > new_size)
      new_size *= 2;
    if (!coap_pdu_resize(pdu, new_size))
      return 0;
  }
  return 1;
}

int
coap_add_token(coap_pdu_t *pdu, size_t len, const uint8_t *data) {
  /* must allow for pdu == NULL as callers may rely on this */
  if (!pdu || len > 8)
    return 0;

  if (!coap_pdu_check_resize(pdu, len))
    return 0;
  pdu->token_length = (uint8_t)len;
  if (len)
    memcpy(pdu->token, data, len);
  pdu->max_delta = 0;
  pdu->used_size = len;
  pdu->data = NULL;

  return 1;
}

/** @FIXME de-duplicate code with coap_add_option_later */
size_t
coap_add_option(coap_pdu_t *pdu, uint16_t type, size_t len, const uint8_t *data) {
  size_t optsize;
  coap_opt_t *opt;
  
  assert(pdu);
  pdu->data = NULL;

  if (type < pdu->max_delta) {
    warn("coap_add_option: options are not in correct order\n");
    return 0;
  }

  if (!coap_pdu_check_resize(pdu, pdu->used_size + len + 5))
    return 0;

  opt = pdu->token + pdu->used_size;

  /* encode option and check length */
  optsize = coap_opt_encode(opt, pdu->max_size - pdu->used_size, 
			    type - pdu->max_delta, data, len);

  if (!optsize) {
    warn("coap_add_option: cannot add option\n");
    /* error */
    return 0;
  } else {
    pdu->max_delta = type;
    pdu->used_size += optsize;
  }

  return optsize;
}

/** @FIXME de-duplicate code with coap_add_option */
uint8_t*
coap_add_option_later(coap_pdu_t *pdu, uint16_t type, size_t len) {
  size_t optsize;
  coap_opt_t *opt;

  assert(pdu);
  pdu->data = NULL;

  if (type < pdu->max_delta) {
    warn("coap_add_option: options are not in correct order\n");
    return NULL;
  }

  if (!coap_pdu_check_resize(pdu, pdu->used_size + len + 5))
    return 0;

  opt = pdu->token + pdu->used_size;

  /* encode option and check length */
  optsize = coap_opt_encode(opt, pdu->max_size - pdu->used_size,
			    type - pdu->max_delta, NULL, len);

  if (!optsize) {
    warn("coap_add_option: cannot add option\n");
    /* error */
    return NULL;
  } else {
    pdu->max_delta = type;
    pdu->used_size += (uint16_t)optsize;
  }

  return opt + optsize - len;
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
  assert(pdu->data == NULL);

  pdu->data = NULL;

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
coap_get_data(coap_pdu_t *pdu, size_t *len, uint8_t **data) {
  assert(pdu);
  assert(len);
  assert(data);

  *len = pdu->used_size - (pdu->data - pdu->token);
  *data = pdu->data;
  return *data != NULL;
}

#ifndef SHORT_ERROR_RESPONSE
typedef struct {
  unsigned char code;
  char *phrase;
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
  { COAP_RESPONSE_CODE(412), "Precondition Failed" },
  { COAP_RESPONSE_CODE(413), "Request Entity Too Large" },
  { COAP_RESPONSE_CODE(415), "Unsupported Content-Format" },
  { COAP_RESPONSE_CODE(500), "Internal Server Error" },
  { COAP_RESPONSE_CODE(501), "Not Implemented" },
  { COAP_RESPONSE_CODE(502), "Bad Gateway" },
  { COAP_RESPONSE_CODE(503), "Service Unavailable" },
  { COAP_RESPONSE_CODE(504), "Gateway Timeout" },
  { COAP_RESPONSE_CODE(505), "Proxying Not Supported" },
  { 0, NULL }			/* end marker */
};

char *
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
next_option_safe(const coap_opt_t **optp, size_t *length) {
  coap_option_t option;
  size_t optsize;

  assert(optp); assert(*optp); 
  assert(length);

  optsize = coap_opt_parse(*optp, *length, &option);
  if (optsize) {
    assert(optsize <= *length);

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
  } else if (proto == COAP_PROTO_UDP || proto==COAP_PROTO_DTLS) {
    header_size = 4;
  }

  return header_size;
}

size_t
coap_pdu_parse_size(coap_proto_t proto,
                    const uint8_t *data,
                    size_t length) {
  assert(data);
  assert(proto == COAP_PROTO_TCP || proto == COAP_PROTO_TLS);
  assert(coap_pdu_parse_header_size(proto, data) <= length );

  size_t size = 0;

  if ((proto == COAP_PROTO_TCP || proto==COAP_PROTO_TLS) && length >= 1) {
    uint8_t len = *data >> 4;
    if (len < 13) {
      size = len - 2;
    } else if (length >= 2) {
      if (len==13) {
	size = (size_t)data[1] + 13;
      } else if (length >= 3) {
	if (len==14) {
	  size = ((size_t)data[1] << 8) + data[2] + 269;
	} else if (length >= 5) {
	  size = ((size_t)data[1] << 24) + ((size_t)data[2] << 16) + ((size_t)data[3] << 8) + data[4] + 65805;
	}
      }
    }
  }
  
  return size;
}

int
coap_pdu_parse_opt(coap_proto_t proto,
                   const uint8_t *data,
                   size_t length,
                   coap_pdu_t *pdu,
                   size_t *offset)
{
  const coap_opt_t *opt;
  const uint8_t *token;

  assert(data);
  assert(pdu);

  *offset = 0;

#ifdef WITH_LWIP
  /* this verifies that with the classical copy-at-parse-time and lwip's
   * zerocopy-into-place approaches, both share the same idea of destination
   * addresses */
  LWIP_ASSERT("coap_pdu_parse with unexpected addresses", data == pdu->token - 4);
  LWIP_ASSERT("coap_pdu_parse with unexpected length", length == pdu->used_size + 4);
#endif

  if (proto == COAP_PROTO_UDP || proto == COAP_PROTO_DTLS) {
    if (length < 4) {
      debug( "coap_pdu_parse: UDP header too short\n" );
      return 0;
    }
    uint8_t version = data[0] >> 6;
    if (version != COAP_DEFAULT_VERSION) {
      debug( "coap_pdu_parse: UDP version not supported\n" );
      return 0;
    }
    pdu->type = (data[0] >> 4) & 0x03;
    pdu->token_length = data[0] & 0x0f;
    pdu->code = data[1];
    pdu->tid = (uint16_t)data[2] << 8 | data[3];
    token = data + 4;
  } else if (proto == COAP_PROTO_UDP || proto == COAP_PROTO_DTLS) {
    uint8_t len;
    if (length < 2) {
      debug( "coap_pdu_parse: TCP header too short\n" );
      return 0;
    }
    len = data[0] >> 4;
    if (len < 13) {
      pdu->code = data[1];
      token = data + 2;
    } else if (len == 13) {
      if (length < 3) {
	debug( "coap_pdu_parse: TCP8 header too short\n" );
	return 0;
      }
      pdu->code = data[2];
      token = data + 3;
    } else if (len == 14) {
      if (length < 4) {
	debug( "coap_pdu_parse: TCP16 header too short\n" );
	return 0;
      }
      pdu->code = data[3];
      token = data + 4;
    } else {
      if (length < 6) {
	debug( "coap_pdu_parse: TCP32 header too short\n" );
	return 0;
      }
      pdu->code = data[5];
      token = data + 6;
    }
    pdu->type = COAP_MESSAGE_CON;
    pdu->token_length = data[0] & 0x0f;
    pdu->tid = 0;
  } else {
    debug( "coap_pdu_parse: unsupported protocol\n" );
    return 0;
  }

  /* sanity checks */
  if (pdu->code == 0) {
    if (length != token - data || pdu->token_length) {
      debug("coap_pdu_parse: empty message is not empty\n");
      return 0;
    }
  }

  if (token + pdu->token_length > data + length
      || pdu->token_length > 8) {
    debug("coap_pdu_parse: invalid Token\n");
    return 0;
  }

  if (pdu->code == 0) {
    /* empty packet */
    pdu->used_size = 0;
  } else {
    /* skip header + token */
    opt = token + pdu->token_length;
    length = data + length - opt;

    while (length > 0 && *opt != COAP_PAYLOAD_START) {
      if ( !next_option_safe( &opt, (size_t *)&length ) ) {
	debug( "coap_pdu_parse: missing payload start code\n" );
	return 0;
      }
    }

    if (length > 0) {
      assert(*opt == COAP_PAYLOAD_START);
      opt++; length--;

      if (length == 0) {
        debug("coap_pdu_parse: message ending in payload start marker\n");
        return 0;
      }
    }

    if (opt > token) {
      if (!coap_pdu_check_resize(pdu, opt - token))
	return 0;

      /* Append options (including the token) to pdu structure, if any. */
      memcpy(pdu->token, token, opt - token);
      pdu->used_size = opt - token;

      *offset = opt - data;
    }
  }

  return 1;
}

int
coap_pdu_parse(coap_proto_t proto,
               const uint8_t *data,
               size_t length,
               coap_pdu_t *pdu)
{
  size_t offset;
  if (coap_pdu_parse_opt(proto, data, length, pdu, &offset) == 0)
    return 0;
  length -= offset;
  if (offset == 0 || length == 0)
    return 1;
  if (!coap_pdu_resize(pdu, pdu->used_size + length))
    return 0;
  pdu->data = pdu->token + pdu->used_size;
  memcpy(pdu->data, data + offset, length);
  pdu->used_size += length;
  return 1;
}

size_t
coap_pdu_encode_header(coap_pdu_t *pdu, coap_proto_t proto) {
  if (proto == COAP_PROTO_UDP || proto == COAP_PROTO_DTLS) {
    assert(pdu->max_hdr_size >= 4);
    if (pdu->max_hdr_size < 4) {
      warn("coap_pdu_encode_header: not enough space for UDP-style header");
      return 0;
    }
    pdu->token[-4] = COAP_DEFAULT_VERSION << 6
                   | pdu->type << 4
                   | pdu->token_length;
    pdu->token[-3] = pdu->code;
    pdu->token[-2] = (uint8_t)(pdu->tid >> 8);
    pdu->token[-1] = (uint8_t)(pdu->tid);
    return 4;
  } else if (proto == COAP_PROTO_TCP || proto == COAP_PROTO_TLS) {
    size_t len;
    assert(pdu->used_size >= pdu->token_length);
    if (pdu->used_size < pdu->token_length) {
      warn("coap_pdu_encode_header: corrupted PDU");
      return 0;
    }
    len = pdu->used_size - pdu->token_length;
    if (len < 13) {
      assert(pdu->max_hdr_size >= 2);
      if (pdu->max_hdr_size < 2) {
	warn("coap_pdu_encode_header: not enough space for TCP0 header");
	return 0;
      }
      pdu->token[-2] = (uint8_t)len << 4
                     | pdu->token_length;
      pdu->token[-1] = pdu->code;
      return 2;
    } else if (len < 269) {
      assert(pdu->max_hdr_size >= 3);
      if (pdu->max_hdr_size < 3) {
	warn("coap_pdu_encode_header: not enough space for TCP8 header");
	return 0;
      }
      pdu->token[-3] = 13 << 4 | pdu->token_length;
      pdu->token[-2] = (uint8_t)(len - 13);
      pdu->token[-1] = pdu->code;
      return 3;
    } else if (len < 65805) {
      assert(pdu->max_hdr_size >= 4);
      if (pdu->max_hdr_size < 4) {
	warn("coap_pdu_encode_header: not enough space for TCP16 header");
	return 0;
      }
      pdu->token[-4] = 14 << 4 | pdu->token_length;
      pdu->token[-3] = (uint8_t)((len - 269) >> 8);
      pdu->token[-2] = (uint8_t)(len - 269);
      pdu->token[-1] = pdu->code;
      return 4;
    } else {
      assert(pdu->max_hdr_size >= 6);
      if (pdu->max_hdr_size < 6) {
	warn("coap_pdu_encode_header: not enough space for TCP32 header");
	return 0;
      }
      pdu->token[-6] = 15 << 4 | pdu->token_length;
      pdu->token[-5] = (uint8_t)((len - 65805) >> 24);
      pdu->token[-4] = (uint8_t)((len - 65805) >> 16);
      pdu->token[-3] = (uint8_t)((len - 65805) >> 8);
      pdu->token[-2] = (uint8_t)(len - 65805);
      pdu->token[-1] = pdu->code;
      return 6;
    }
  }
  warn("coap_pdu_encode_header: unsupported protocol");
  return 0;
}
