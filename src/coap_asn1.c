/* coap_asn1.c -- ASN.1 handling functions
 *
 * Copyright (C) 2020-2026 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file coap_asn1.c
 * @brief CoAP specific ASN.1 handling
 */

#include "coap3/coap_libcoap_build.h"

size_t
asn1_len(const uint8_t **ptr, size_t *plen) {
  size_t len = 0;

  if (*plen == 0)
    return 0;
  if ((**ptr) & 0x80) {
    size_t octets = (**ptr) & 0x7f;
    (*plen)--;
    (*ptr)++;
    while (octets) {
      if (*plen == 0)
        return 0;
      len = (len << 8) + (**ptr);
      (*plen)--;
      (*ptr)++;
      octets--;
    }
  } else {
    if (*plen == 0)
      return 0;
    len = (**ptr) & 0x7f;
    (*plen)--;
    (*ptr)++;
  }
  if (len > *plen)
    return *plen;
  return len;
}

coap_asn1_tag_t
asn1_tag_c(const uint8_t **ptr, size_t *plen, int *constructed, int *cls) {
  coap_asn1_tag_t tag = 0;
  uint8_t byte;

  if (*plen == 0) {
    *constructed = 0;
    *cls = 0;
    return COAP_ASN1_FAIL;
  }
  byte = (**ptr);
  *constructed = (byte & 0x20) ? 1 : 0;
  *cls = byte >> 6;
  tag = byte & 0x1F;
  (*plen)--;
  (*ptr)++;
  if (tag < 0x1F)
    return tag;

  /* Tag can be one byte or more based on B8 */
  if (*plen == 0)
    return COAP_ASN1_FAIL;
  byte = (**ptr);
  while (byte & 0x80) {
    tag = (tag << 7) + (byte & 0x7F);
    (*plen)--;
    (*ptr)++;
    if (*plen == 0)
      return COAP_ASN1_FAIL;
    byte = (**ptr);
  }
  /* Do the final one */
  tag = (tag << 7) + (byte & 0x7F);
  (*plen)--;
  (*ptr)++;
  return tag;
}

static coap_binary_t *
get_asn1_tag_internal(coap_asn1_tag_t ltag, const uint8_t *ptr, size_t tlen,
                      asn1_validate validate, uint32_t recursive_check) {
  int constructed;
  int class;
  coap_asn1_tag_t tag = asn1_tag_c(&ptr, &tlen, &constructed, &class);
  size_t len;
  coap_binary_t *tag_data;

  if (tag == COAP_ASN1_FAIL)
    return NULL;
  len = asn1_len(&ptr, &tlen);

  while (tlen > 0 && len <= tlen) {
    if (class == 2 && constructed == 1) {
      /* Skip over element description */
      tag = asn1_tag_c(&ptr, &tlen, &constructed, &class);
      if (tag == COAP_ASN1_FAIL)
        return NULL;
      len = asn1_len(&ptr, &tlen);
    }
    if (tag == ltag) {
      if (!validate || validate(ptr, len)) {
        tag_data = coap_new_binary(len);
        if (tag_data == NULL)
          return NULL;
        tag_data->length = len;
        memcpy(tag_data->s, ptr, len);
        return tag_data;
      }
    }
    if (tag == 0x10 && constructed == 1) {
      /* SEQUENCE or SEQUENCE OF */
      if (recursive_check > 100)
        return NULL;
      tag_data = get_asn1_tag_internal(ltag, ptr, len, validate, recursive_check + 1);
      if (tag_data)
        return tag_data;
    }
    /* Skip over non matching tag */
    ptr += len;
    tlen -= len;
    tag = asn1_tag_c(&ptr, &tlen, &constructed, &class);
    if (tag == COAP_ASN1_FAIL)
      return NULL;
    len = asn1_len(&ptr, &tlen);
  }
  return NULL;
}

/* caller must free off returned coap_binary_t* */
coap_binary_t *
get_asn1_tag(coap_asn1_tag_t ltag, const uint8_t *ptr, size_t tlen,
             asn1_validate validate) {
  return get_asn1_tag_internal(ltag, ptr, tlen, validate, 0);
}

/* first part of Raw public key, this is the start of the Subject Public Key */
static const unsigned char cert_asn1_header1[] = {
  0x30, 0x59, /* SEQUENCE, length 89 bytes */
  0x30, 0x13, /* SEQUENCE, length 19 bytes */
  0x06, 0x07, /* OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1) */
  0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
};
/* PrimeX will get inserted */
#if 0
0x06, 0x08, /* OBJECT IDENTIFIER prime256v1 (1 2 840 10045 3 1 7) */
      0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
#endif
static const unsigned char cert_asn1_header2[] = {
  0x03, 0x42, /* BIT STRING, length 66 bytes */
  /* Note: 0 bits (0x00) and no compression (0x04) are already in the certificate */
};

coap_binary_t *
get_asn1_spki(const uint8_t *data, size_t size) {
  coap_binary_t *pub_key = get_asn1_tag(COAP_ASN1_BITSTRING, data, size, NULL);
  coap_binary_t *prime = get_asn1_tag(COAP_ASN1_IDENTIFIER, data, size, NULL);
  coap_binary_t *spki = NULL;

  if (pub_key && prime) {
    size_t header_size = sizeof(cert_asn1_header1) +
                         2 +
                         prime->length +
                         sizeof(cert_asn1_header2);
    spki = coap_new_binary(header_size + pub_key->length);
    if (spki) {
      memcpy(&spki->s[header_size], pub_key->s, pub_key->length);
      memcpy(spki->s, cert_asn1_header1, sizeof(cert_asn1_header1));
      spki->s[sizeof(cert_asn1_header1)] = COAP_ASN1_IDENTIFIER;
      spki->s[sizeof(cert_asn1_header1)+1] = (uint8_t)prime->length;
      memcpy(&spki->s[sizeof(cert_asn1_header1)+2],
             prime->s, prime->length);
      memcpy(&spki->s[sizeof(cert_asn1_header1)+2+prime->length],
             cert_asn1_header2, sizeof(cert_asn1_header2));
      spki->length = header_size + pub_key->length;
    }
  }
  if (pub_key)
    coap_delete_binary(pub_key);
  if (prime)
    coap_delete_binary(prime);
  return spki;
}
