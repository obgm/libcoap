/*
 * ecdsa.h -- representation of ECDSA key material
 *
 * Copyright (C) 2010-2011,2015-2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */
 
 /**
 * @file ecdsa.h
 * @brief Representation of ECDSA key material
 */
 
#ifndef _COAP_ECDSA_H_
#define _COAP_ECDSA_H_
 
typedef enum {
  COAP_DTLS_ECDH_CURVE_SECP256R1
} coap_dtls_ecdh_curve;

typedef struct coap_dtls_ecdsa_key_t {
  coap_dtls_ecdh_curve curve;
  unsigned char *priv_key;	/** < private key as bytes > */
  unsigned char *pub_key_x;	/** < x part of the public key for the given private key > */
  unsigned char *pub_key_y;	/** < y part of the public key for the given private key > */
} coap_dtls_ecdsa_key_t;

#endif
