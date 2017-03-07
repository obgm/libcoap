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

#include "debug.h"
#include "pdu.h"
#include "option.h"
#include "encode.h"
#include "mem.h"

void
coap_pdu_clear(coap_pdu_t *pdu, size_t size) {
    coap_pdu_clear2(pdu, size, COAP_UDP, 0);
}

void
coap_pdu_clear2(coap_pdu_t *pdu, size_t size, coap_transport_t transport, unsigned int length) {
  assert(length <= USHRT_MAX);
  assert(pdu);

#ifdef WITH_LWIP
  /* the pdu itself is not wiped as opposed to the other implementations,
   * because we have to rely on the pbuf to be set there. */
  pdu->hdr = pdu->pbuf->payload;
#else
  pdu->max_delta = 0;
  pdu->data = NULL;
#endif
  memset(pdu->hdr, 0, size);
  pdu->max_size = size;
  pdu->hdr->version = COAP_DEFAULT_VERSION;

  if (COAP_UDP == transport) {
    pdu->transport_hdr->udp.version = COAP_DEFAULT_VERSION;
    /* data is NULL unless explicitly set by coap_add_data() */
    pdu->length = sizeof(coap_hdr_t);
  }
#ifdef WITH_TCP
  else {
    /* data is NULL unless explicitly set by coap_add_data() */
    pdu->length = (unsigned short)length;
  }
#endif
}

#ifdef WITH_LWIP
coap_pdu_t *
coap_pdu_from_pbuf(struct pbuf *pbuf) {
  if (pbuf == NULL) return NULL;

  LWIP_ASSERT("Can only deal with contiguous PBUFs", pbuf->tot_len == pbuf->len);
  LWIP_ASSERT("coap_read needs to receive an exclusive copy of the incoming pbuf", pbuf->ref == 1);

  coap_pdu_t *result = coap_malloc_type(COAP_PDU, sizeof(coap_pdu_t));
  if (!result) {
	  pbuf_free(pbuf);
	  return NULL;
  }

  memset(result, 0, sizeof(coap_pdu_t));

  result->max_size = pbuf->tot_len;
  result->length = pbuf->tot_len;
  result->hdr = pbuf->payload;
  result->pbuf = pbuf;

  return result;
}
#endif

coap_pdu_t *
coap_pdu_init(unsigned char type, unsigned char code, 
	      unsigned short id, size_t size) {
  return coap_pdu_init2(type, code, id, size, COAP_UDP);
}

coap_pdu_t *
coap_pdu_init2(unsigned char type, unsigned char code, unsigned short id,
               size_t size, coap_transport_t transport) {
  coap_pdu_t *pdu;
#ifdef WITH_LWIP
  struct pbuf *p;
#endif

  size_t length = 0;
  switch (transport) {
    case COAP_UDP:
      length = sizeof(coap_hdr_t);
      break;
#ifdef WITH_TCP
    case COAP_TCP:
      length = COAP_TCP_HEADER_NO_FIELD;
      break;
    case COAP_TCP_8BIT:
      length = COAP_TCP_HEADER_8_BIT;
      break;
    case COAP_TCP_16BIT:
      length = COAP_TCP_HEADER_16_BIT;
      break;
    case COAP_TCP_32BIT:
      length = COAP_TCP_HEADER_32_BIT;
      break;
#endif
    default:
      debug("it has wrong type\n");
  }

  assert(length <= UINT_MAX);

#ifndef WITH_TCP
  assert(size <= COAP_MAX_PDU_SIZE);
  /* Size must be large enough to fit the header. */
  if (size < length || size > COAP_MAX_PDU_SIZE)
    return NULL;
#endif

  /* size must be large enough for hdr */
#if defined(WITH_POSIX) || defined(WITH_CONTIKI) || defined(WITH_ARDUINO) || defined(_WIN32)
  pdu = (coap_pdu_t *)coap_malloc_type(COAP_PDU, sizeof(coap_pdu_t));
  if (!pdu) return NULL;
  pdu->hdr = coap_malloc_type(COAP_PDU_BUF, size);
  if (pdu->hdr == NULL) {
    coap_free_type(COAP_PDU, pdu);
    pdu = NULL;
  }
#endif
#ifdef WITH_LWIP
  pdu = (coap_pdu_t*)coap_malloc_type(COAP_PDU, sizeof(coap_pdu_t));
  if (!pdu) return NULL;
  p = pbuf_alloc(PBUF_TRANSPORT, size, PBUF_RAM);
  if (p == NULL) {
    coap_free_type(COAP_PDU, pdu);
    pdu = NULL;
  }
#endif
  if (pdu) {
#ifdef WITH_LWIP
    pdu->pbuf = p;
#endif
    coap_pdu_clear2(pdu, size, transport, (unsigned int)length);
    switch (transport) {
      case COAP_UDP:
        pdu->transport_hdr->udp.id = id;
        pdu->transport_hdr->udp.type = type;
        pdu->transport_hdr->udp.code = code;
        break;
#ifdef WITH_TCP
      case COAP_TCP:
        pdu->transport_hdr->tcp.header_data[0] = 0;
        pdu->transport_hdr->tcp.header_data[1] = code;
        break;
      case COAP_TCP_8BIT:
        pdu->transport_hdr->tcp_8bit.header_data[0] = COAP_TCP_LENGTH_FIELD_NUM_8_BIT << 4;
        pdu->transport_hdr->tcp_8bit.header_data[2] = code;
        break;
      case COAP_TCP_16BIT:
        pdu->transport_hdr->tcp_16bit.header_data[0] = COAP_TCP_LENGTH_FIELD_NUM_16_BIT << 4;
        pdu->transport_hdr->tcp_16bit.header_data[3] = code;
        break;
      case COAP_TCP_32BIT:
        pdu->transport_hdr->tcp_32bit.header_data[0] = COAP_TCP_LENGTH_FIELD_NUM_32_BIT << 4;
        pdu->transport_hdr->tcp_32bit.header_data[5] = code;
        break;
#endif
      default:
        debug("it has wrong type\n");
    }
  } 
  return pdu;
}

coap_pdu_t *
coap_new_pdu(void) {
  return coap_new_pdu2(COAP_UDP, COAP_MAX_PDU_SIZE);
}

coap_pdu_t *
coap_new_pdu2(coap_transport_t transport, unsigned int size) {
  coap_pdu_t *pdu;

  pdu = coap_pdu_init2(0, 0,
#ifndef WITH_CONTIKI
                       ntohs((uint16_t)COAP_INVALID_TID),
#else /* WITH_CONTIKI */
                       uip_ntohs(COAP_INVALID_TID),
#endif /* WITH_CONTIKI */
                       size,
                       transport);

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
    if (pdu->hdr != NULL) {
      coap_free_type(COAP_PDU_BUF, pdu->hdr);
    }
#endif
    coap_free_type(COAP_PDU, pdu);
  }
}

#ifdef WITH_TCP
size_t
coap_get_total_message_length(const unsigned char *data, size_t size) {
    if (!data || !size) {
        debug("received data length is null\n");
        return 0;
    }

    coap_transport_t transport = coap_get_tcp_header_type_from_initbyte(
            ((unsigned char *)data)[0] >> 4);
    size_t optPaylaodLen = coap_get_length_from_header((unsigned char *)data,
                                                        transport);
    size_t headerLen = coap_get_tcp_header_length((unsigned char *)data);

    return headerLen + optPaylaodLen;
}

coap_transport_t
coap_get_tcp_header_type_from_size(unsigned int size) {
    if (size < COAP_TCP_LENGTH_FIELD_8_BIT) {
        return COAP_TCP;
    } else if (size < COAP_TCP_LENGTH_FIELD_16_BIT) {
        return COAP_TCP_8BIT;
    } else if (size < COAP_TCP_LENGTH_FIELD_32_BIT) {
        return COAP_TCP_16BIT;
    } else {
        return COAP_TCP_32BIT;
    }
}

coap_transport_t
coap_get_tcp_header_type_from_initbyte(unsigned int length) {
    coap_transport_t type;
    switch (length) {
        case COAP_TCP_LENGTH_FIELD_NUM_8_BIT:
            type = COAP_TCP_8BIT;
            break;
        case COAP_TCP_LENGTH_FIELD_NUM_16_BIT:
            type = COAP_TCP_16BIT;
            break;
        case COAP_TCP_LENGTH_FIELD_NUM_32_BIT:
            type = COAP_TCP_32BIT;
            break;
        default:
            type = COAP_TCP;
    }
    return type;
}

void
coap_add_length(const coap_pdu_t *pdu, coap_transport_t transport, unsigned int length) {
    assert(pdu);

    switch (transport) {
        case COAP_TCP:
            assert(length < COAP_TCP_LENGTH_FIELD_8_BIT);
            pdu->transport_hdr->tcp.header_data[0] = (length << 4) & 0x0000ff;
            break;
        case COAP_TCP_8BIT:
            if (length > COAP_TCP_LENGTH_FIELD_8_BIT) {
                unsigned int total_length = length - COAP_TCP_LENGTH_FIELD_8_BIT;
                assert(total_length <= UCHAR_MAX);
                pdu->transport_hdr->tcp_8bit.header_data[1] =
                    total_length & 0x0000ff;
            }
            break;
        case COAP_TCP_16BIT:
            if (length > COAP_TCP_LENGTH_FIELD_16_BIT) {
                unsigned int total_length = length - COAP_TCP_LENGTH_FIELD_16_BIT;
                assert(total_length <= USHRT_MAX);
                pdu->transport_hdr->tcp_16bit.header_data[1] = (total_length >> 8) & 0x0000ff;
                pdu->transport_hdr->tcp_16bit.header_data[2] = total_length & 0x000000ff;
            }
            break;
        case COAP_TCP_32BIT:
            if (length > COAP_TCP_LENGTH_FIELD_32_BIT) {
                unsigned int total_length = length - COAP_TCP_LENGTH_FIELD_32_BIT;
                pdu->transport_hdr->tcp_32bit.header_data[1] = total_length >> 24;
                pdu->transport_hdr->tcp_32bit.header_data[2] = (total_length >> 16) & 0x00ff;
                pdu->transport_hdr->tcp_32bit.header_data[3] = (total_length >> 8) & 0x0000ff;
                pdu->transport_hdr->tcp_32bit.header_data[4] = total_length & 0x000000ff;
            }
            break;
        default:
            debug("it has wrong type\n");
    }
}

unsigned int
coap_get_length_from_header(const unsigned char *header, coap_transport_t transport) {
    assert(header);

    unsigned int length = 0;
    unsigned int length_field_data = 0;
    switch (transport) {
        case COAP_TCP:
            length = header[0] >> 4;
            break;
        case COAP_TCP_8BIT:
            length = header[1] + COAP_TCP_LENGTH_FIELD_8_BIT;
            break;
        case COAP_TCP_16BIT:
            length_field_data = (header[1] << 8 | header[2]);
            length = length_field_data + COAP_TCP_LENGTH_FIELD_16_BIT;
            break;
        case COAP_TCP_32BIT:
            length_field_data = header[1] << 24 | header[2] << 16 | header[3] << 8 | header[4];
            length = length_field_data + COAP_TCP_LENGTH_FIELD_32_BIT;
            break;
        default:
            debug("it has wrong type\n");
    }

    return length;
}

unsigned int
coap_get_length(const coap_pdu_t *pdu, coap_transport_t transport) {
    assert(pdu);

    unsigned int length = 0;
    unsigned int length_field_data = 0;
    switch (transport) {
        case COAP_TCP:
            length = pdu->transport_hdr->tcp.header_data[0] >> 4;
            break;
        case COAP_TCP_8BIT:
            length = pdu->transport_hdr->tcp_8bit.header_data[1] + COAP_TCP_LENGTH_FIELD_8_BIT;
            break;
        case COAP_TCP_16BIT:
            length_field_data =
                    pdu->transport_hdr->tcp_16bit.header_data[1] << 8 |
                    pdu->transport_hdr->tcp_16bit.header_data[2];
            length = length_field_data + COAP_TCP_LENGTH_FIELD_16_BIT;
            break;
        case COAP_TCP_32BIT:
            length_field_data =
                    pdu->transport_hdr->tcp_32bit.header_data[1] << 24 |
                    pdu->transport_hdr->tcp_32bit.header_data[2] << 16 |
                    pdu->transport_hdr->tcp_32bit.header_data[3] << 8 |
                    pdu->transport_hdr->tcp_32bit.header_data[4];
            length = length_field_data + COAP_TCP_LENGTH_FIELD_32_BIT;
            break;
        default:
            debug("it has wrong type\n");
    }

    return length;
}

unsigned int
coap_get_tcp_header_length(unsigned char *data) {
    assert(data);

    unsigned int tokenLength =  data[0] & 0x0f;
    coap_transport_t transport =
            coap_get_tcp_header_type_from_initbyte(data[0] >> 4);
    unsigned int length = 0;

    length = coap_get_tcp_header_length_for_transport(transport) + tokenLength;
    return length;
}

unsigned int
coap_get_tcp_header_length_for_transport(coap_transport_t transport) {
    unsigned int length = 0;
    switch (transport) {
        case COAP_TCP:
            length = COAP_TCP_HEADER_NO_FIELD;
            break;
        case COAP_TCP_8BIT:   /* len(4bit) + TKL(4bit) + Len+bytes(1byte) + Code(1byte) */
            length = COAP_TCP_HEADER_8_BIT;
            break;
        case COAP_TCP_16BIT:  /* len(4bit) + TKL(4bit) + Len+bytes(2byte) + Code(1byte) */
            length = COAP_TCP_HEADER_16_BIT;
            break;
        case COAP_TCP_32BIT:  /* len(4bit) + TKL(4bit) + Len+bytes(4byte) + Code(1byte) */
            length = COAP_TCP_HEADER_32_BIT;
            break;
        default:
            debug("it has wrong type\n");
    }

    return length;
}

size_t
coap_get_opt_header_length(unsigned short key, size_t length) {
    size_t headerLength = 0;

    unsigned short optDeltaLength = 0;
    if (COAP_OPTION_FIELD_8_BIT >= key) {
        optDeltaLength = 0;
    } else if (COAP_OPTION_FIELD_8_BIT < key && COAP_OPTION_FIELD_16_BIT >= key) {
        optDeltaLength = 1;
    } else {
        optDeltaLength = 2;
    }

    size_t optLength = 0;
    if (COAP_OPTION_FIELD_8_BIT >= length) {
        optLength = 0;
    } else if (COAP_OPTION_FIELD_8_BIT < length && COAP_OPTION_FIELD_16_BIT >= length) {
        optLength = 1;
    } else if (COAP_OPTION_FIELD_16_BIT < length && COAP_OPTION_FIELD_32_BIT >= length) {
        optLength = 2;
    } else {
        printf("Error : Reserved for the Payload marker for length");
        return 0;
    }

    headerLength = length + optDeltaLength + optLength + 1;

    return headerLength;
}
#endif

void
coap_add_code(const coap_pdu_t *pdu, coap_transport_t transport, unsigned int code) {
  unsigned int long_code = COAP_RESPONSE_CODE(code);
  assert(long_code <= UINT8_MAX);
  assert(pdu);

  unsigned char coap_code = (unsigned char)long_code;
  switch (transport) {
    case COAP_UDP:
      pdu->transport_hdr->udp.code = coap_code;
      break;
#ifdef WITH_TCP
    case COAP_TCP:
      pdu->transport_hdr->tcp.header_data[1] = coap_code;
      break;
    case COAP_TCP_8BIT:
      pdu->transport_hdr->tcp_8bit.header_data[2] = coap_code;
      break;
    case COAP_TCP_16BIT:
      pdu->transport_hdr->tcp_16bit.header_data[3] = coap_code;
      break;
    case COAP_TCP_32BIT:
      pdu->transport_hdr->tcp_32bit.header_data[5] = coap_code;
      break;
#endif
    default:
      debug("it has wrong type\n");
  }
}

unsigned int
coap_get_code(const coap_pdu_t *pdu, coap_transport_t transport) {
  assert(pdu);

  unsigned int code = 0;
  switch (transport) {
    case COAP_UDP:
      code = pdu->transport_hdr->udp.code;
      break;
#ifdef WITH_TCP
    case COAP_TCP:
      code = pdu->transport_hdr->tcp.header_data[1];
      break;
    case COAP_TCP_8BIT:
      code = pdu->transport_hdr->tcp_8bit.header_data[2];
      break;
    case COAP_TCP_16BIT:
      code = pdu->transport_hdr->tcp_16bit.header_data[3];
      break;
    case COAP_TCP_32BIT:
      code = pdu->transport_hdr->tcp_32bit.header_data[5];
      break;
#endif
    default:
      debug("it has wrong type\n");
  }
  return code;
}

int
coap_add_token(coap_pdu_t *pdu, size_t len, const unsigned char *data) {
  return coap_add_token2(pdu, len, data, COAP_UDP);
}

int
coap_add_token2(coap_pdu_t *pdu, size_t len, const unsigned char *data,
                coap_transport_t transport) {
  const size_t HEADERLENGTH = len + 4;
  /* must allow for pdu == NULL as callers may rely on this */
  if (!pdu || len > 8 || pdu->max_size < HEADERLENGTH)
    return 0;

  unsigned char token_len = (unsigned char)len;
  unsigned char* token = NULL;
  switch (transport) {
    case COAP_UDP:
      pdu->transport_hdr->udp.token_length = token_len;
      token = pdu->transport_hdr->udp.token;
      pdu->length = (unsigned short)HEADERLENGTH;
      break;
#ifdef WITH_TCP
    case COAP_TCP:
      pdu->transport_hdr->tcp.header_data[0] =
              pdu->transport_hdr->tcp.header_data[0] | token_len;
      token = pdu->transport_hdr->tcp.token;
      pdu->length = token_len + COAP_TCP_HEADER_NO_FIELD;
      break;
    case COAP_TCP_8BIT:
      pdu->transport_hdr->tcp_8bit.header_data[0] =
              pdu->transport_hdr->tcp_8bit.header_data[0] | token_len;
      token = pdu->transport_hdr->tcp_8bit.token;
      pdu->length = token_len + COAP_TCP_HEADER_8_BIT;
      break;
    case COAP_TCP_16BIT:
      pdu->transport_hdr->tcp_16bit.header_data[0] =
              pdu->transport_hdr->tcp_16bit.header_data[0] | token_len;
      token = pdu->transport_hdr->tcp_16bit.token;
      pdu->length = token_len + COAP_TCP_HEADER_16_BIT;
      break;
    case COAP_TCP_32BIT:
      pdu->transport_hdr->tcp_32bit.header_data[0] =
              pdu->transport_hdr->tcp_32bit.header_data[0] | token_len;
      token = pdu->transport_hdr->tcp_32bit.token;
      pdu->length = token_len + COAP_TCP_HEADER_32_BIT;
      break;
#endif
    default:
      debug("it has wrong type\n");
  }

  if (token_len) {
    memcpy(token, data, token_len);
  }

  pdu->max_delta = 0;
  pdu->data = NULL;

  return 1;
}

void
coap_get_token(const coap_hdr_t *pdu_hdr,
               unsigned char **token, unsigned int *token_length) {
  coap_get_token2((const coap_hdr_transport_t *)pdu_hdr, COAP_UDP, token, token_length);
}

void
coap_get_token2(const coap_hdr_transport_t *pdu_hdr, coap_transport_t transport,
                unsigned char **token, unsigned int *token_length) {
  assert(pdu_hdr);
  assert(token);
  assert(token_length);

  switch (transport) {
    case COAP_UDP:
      *token_length = pdu_hdr->udp.token_length;
      *token = (unsigned char *)pdu_hdr->udp.token;
      break;
#ifdef WITH_TCP
    case COAP_TCP:
      *token_length = (pdu_hdr->tcp.header_data[0]) & 0x0f;
      *token = (unsigned char *)pdu_hdr->tcp.token;
      break;
    case COAP_TCP_8BIT:
      *token_length = (pdu_hdr->tcp_8bit.header_data[0]) & 0x0f;
      *token = (unsigned char *)pdu_hdr->tcp_8bit.token;
      break;
    case COAP_TCP_16BIT:
      *token_length = (pdu_hdr->tcp_16bit.header_data[0]) & 0x0f;
      *token = (unsigned char *)pdu_hdr->tcp_16bit.token;
      break;
    case COAP_TCP_32BIT:
      *token_length = (pdu_hdr->tcp_32bit.header_data[0]) & 0x0f;
      *token = (unsigned char *)pdu_hdr->tcp_32bit.token;
      break;
#endif
    default:
        debug("it has wrong type\n");
  }
}

size_t
coap_add_option(coap_pdu_t *pdu, unsigned short type, unsigned int len, const unsigned char *data) {
  return coap_add_option2(pdu, type, len, data, COAP_UDP);
}

/** @FIXME de-duplicate code with coap_add_option_later */
size_t
coap_add_option2(coap_pdu_t *pdu, unsigned short type, unsigned int len,
                 const unsigned char *data, coap_transport_t transport) {
  size_t optsize;
  coap_opt_t *opt;
  
  assert(pdu);
  pdu->data = NULL;

  if (type < pdu->max_delta) {
    warn("coap_add_option: options are not in correct order\n");
    return 0;
  }

  switch (transport) {
#ifdef WITH_TCP
    case COAP_TCP:
      opt = (unsigned char *) &(pdu->transport_hdr->tcp) + pdu->length;
      break;
    case COAP_TCP_8BIT:
      opt = (unsigned char *) &(pdu->transport_hdr->tcp_8bit) + pdu->length;
      break;
    case COAP_TCP_16BIT:
      opt = (unsigned char *) &(pdu->transport_hdr->tcp_16bit) + pdu->length;
      break;
    case COAP_TCP_32BIT:
      opt = (unsigned char *) &(pdu->transport_hdr->tcp_32bit) + pdu->length;
      break;
#endif
    default:
      opt = (unsigned char *) &(pdu->transport_hdr->udp) + pdu->length;
      break;
    }

  /* encode option and check length */
  optsize = coap_opt_encode(opt, pdu->max_size - pdu->length, 
			    type - pdu->max_delta, data, len);

  size_t new_pdu_length = pdu->length + optsize;
  if (!optsize || new_pdu_length > USHRT_MAX) {
    warn("coap_add_option: cannot add option\n");
    /* error */
    return 0;
  } else {
    pdu->max_delta = type;
    pdu->length = (unsigned short)new_pdu_length;
  }

  return optsize;
}

/** @FIXME de-duplicate code with coap_add_option */
unsigned char*
coap_add_option_later(coap_pdu_t *pdu, unsigned short type, unsigned int len) {
  size_t optsize;
  coap_opt_t *opt;

  assert(pdu);
  pdu->data = NULL;

  if (type < pdu->max_delta) {
    warn("coap_add_option: options are not in correct order\n");
    return NULL;
  }

  opt = (unsigned char *)pdu->hdr + pdu->length;

  /* encode option and check length */
  optsize = coap_opt_encode(opt, pdu->max_size - pdu->length,
			    type - pdu->max_delta, NULL, len);

  size_t new_pdu_length = pdu->length + optsize;
  if (!optsize || new_pdu_length > USHRT_MAX) {
    warn("coap_add_option: cannot add option\n");
    /* error */
    return NULL;
  } else {
    pdu->max_delta = type;
    pdu->length = (unsigned short)new_pdu_length;
  }

  return ((unsigned char*)opt) + optsize - len;
}

int
coap_add_data(coap_pdu_t *pdu, unsigned int len, const unsigned char *data) {
  assert(pdu);
  assert(pdu->data == NULL);

  if (len == 0)
    return 1;

  size_t new_length = pdu->length + len + 1;
  if (new_length > pdu->max_size || new_length > USHRT_MAX) {
    warn("coap_add_data: cannot add: data too large for PDU\n");
    assert(pdu->data == NULL);
    return 0;
  }

  pdu->data = (unsigned char *)pdu->hdr + pdu->length;
  *pdu->data = COAP_PAYLOAD_START;
  pdu->data++;

  memcpy(pdu->data, data, len);
  pdu->length = (unsigned short)new_length;
  return 1;
}

int
coap_get_data(const coap_pdu_t *pdu, size_t *len, unsigned char **data) {
  assert(pdu);
  assert(len);
  assert(data);

  if (pdu->data) {
    *len = (unsigned char *)pdu->hdr + pdu->length - pdu->data;
    *data = pdu->data;
  } else {			/* no data, clear everything */
    *len = 0;
    *data = NULL;
  }

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
next_option_safe(coap_opt_t **optp, size_t *length, coap_option_t* option) {
  size_t optsize;

  assert(optp);
  assert(*optp); 
  assert(length);

  optsize = coap_opt_parse(*optp, *length, option);
  if (optsize) {
    assert(optsize <= *length);

    *optp += optsize;
    *length -= optsize;
  }

  return optsize;
}

int
coap_pdu_parse(unsigned char *data, size_t length, coap_pdu_t *pdu) {
  return coap_pdu_parse2(data, length, pdu, COAP_UDP);
}

int
coap_pdu_parse2(unsigned char *data, size_t length, coap_pdu_t *pdu,
                coap_transport_t transport) {
  assert(data);
  assert(pdu);

  if (pdu->max_size < length || length > USHRT_MAX) {
    debug("insufficient space to store parsed PDU\n");
    return -1;
  }

  unsigned int headerSize = 0;

  if (COAP_UDP == transport) {
    headerSize = sizeof(coap_hdr_t);
  }
#ifdef WITH_TCP
  else {
    headerSize = coap_get_tcp_header_length_for_transport(transport);
  }
#endif

  if (length < headerSize) {
    debug("discarded invalid PDU\n");
  }

  coap_opt_t *opt = NULL;
  unsigned int tokenLength = 0;
#ifdef WITH_TCP
  switch (transport) {
    case COAP_UDP:
      break;
    case COAP_TCP:
      for (size_t i = 0 ; i < headerSize ; i++) {
        pdu->transport_hdr->tcp.header_data[i] = data[i];
      }

      tokenLength = data[0] & 0x0f;
      opt = (unsigned char *) (&(pdu->transport_hdr->tcp) + 1) + tokenLength;
      break;
    case COAP_TCP_8BIT:
      for (size_t i = 0 ; i < headerSize ; i++) {
        pdu->transport_hdr->tcp_8bit.header_data[i] = data[i];
      }

      tokenLength = data[0] & 0x0f;
      opt = (unsigned char *) (&(pdu->transport_hdr->tcp_8bit))
              + tokenLength + COAP_TCP_HEADER_8_BIT;
      break;
    case COAP_TCP_16BIT:
      for (size_t i = 0 ; i < headerSize ; i++) {
        pdu->transport_hdr->tcp_16bit.header_data[i] = data[i];
      }

      tokenLength = data[0] & 0x0f;
      opt = (unsigned char *) (&(pdu->transport_hdr->tcp_16bit) + 1) + tokenLength;
      break;
    case COAP_TCP_32BIT:
      for (size_t i = 0 ; i < headerSize ; i++) {
        pdu->transport_hdr->tcp_32bit.header_data[i] = data[i];
      }

      tokenLength = data[0] & 0x0f;
      opt = ((unsigned char *) &(pdu->transport_hdr->tcp_32bit)) +
              headerSize + tokenLength;
      break;
    default:
      printf("it has wrong type\n");
  }
#endif
  pdu->length = (unsigned short)length;

  if (COAP_UDP == transport) {
    pdu->transport_hdr->udp.version = data[0] >> 6;
    pdu->transport_hdr->udp.type = (data[0] >> 4) & 0x03;
    pdu->transport_hdr->udp.token_length = data[0] & 0x0f;
    pdu->transport_hdr->udp.code = data[1];
    pdu->data = NULL;

    tokenLength = pdu->transport_hdr->udp.token_length;

    /* sanity checks */
    if (pdu->transport_hdr->udp.code == 0) {
      if (length != headerSize || tokenLength) {
        debug("coap_pdu_parse2: empty message is not empty\n");
        goto discard;
      }
    }

    if (length < headerSize + tokenLength || tokenLength > 8) {
      debug("coap_pdu_parse2: invalid Token\n");
      goto discard;
    }

    memcpy(&pdu->transport_hdr->udp.id, data + 2, 2);

    /* Finally calculate beginning of data block and thereby check integrity
     * of the PDU structure. */

    /* append data (including the Token) to pdu structure */
    memcpy(&(pdu->transport_hdr->udp) + 1, data + headerSize, length - headerSize);

    /* skip header + token */
    length -= (tokenLength + headerSize);
    opt = (unsigned char *) (&(pdu->transport_hdr->udp) + 1) + tokenLength;
  }
#ifdef WITH_TCP
  else { // common for tcp header setting
    pdu->data = NULL;

    if (length < headerSize + tokenLength || tokenLength > 8) {
      debug("coap_pdu_parse2: invalid Token\n");
      goto discard;
    }
    /* Finally calculate beginning of data block and thereby check integrity
     * of the PDU structure. */

    /* append data (including the Token) to pdu structure */
    memcpy(((unsigned char *) pdu->hdr) + headerSize,
           data + headerSize, length - headerSize);

    /* skip header + token */
    length -= (tokenLength + headerSize);
  }
#endif

  /* Append data (including the Token) to pdu structure, if any. */
  if (length > sizeof(coap_hdr_t)) {
    memcpy(pdu->hdr + 1, data + sizeof(coap_hdr_t), length - sizeof(coap_hdr_t));
  }
 
  /* Finally calculate beginning of data block and thereby check integrity
   * of the PDU structure. */

  while (length && *opt != COAP_PAYLOAD_START) {
    coap_option_t option;
    memset(&option, 0, sizeof(coap_option_t));
    if (!next_option_safe(&opt, (size_t *) &length, &option)) {
      debug("coap_pdu_parse2: drop\n");
      goto discard;
    }
  }

  /* end of packet or start marker */
  if (length) {
    assert(*opt == COAP_PAYLOAD_START);
    opt++;
    length--;

    if (!length) {
      debug("coap_pdu_parse: message ending in payload start marker\n");
      goto discard;
    }

    debug("set data to %p (pdu ends at %p)\n", (unsigned char *)opt, 
	  (unsigned char *)pdu->hdr + pdu->length);
    pdu->data = (unsigned char *)opt;
  }

  return 1;

 discard:
  return 0;
}
