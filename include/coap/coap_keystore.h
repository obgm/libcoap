/*
 * coap_keystore.h -- libcoap keystore
 *
 * Copyright (C) 2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#ifndef _COAP_KEYSTORE_H_
#define _COAP_KEYSTORE_H_

#include "address.h"

/**
 * @defgroup keys Keystore
 * Generic container to store keys for secure communication.
 * @{
 */

struct coap_keystore_t;
typedef struct coap_keystore_t coap_keystore_t;
struct coap_keystore_item_t;
typedef struct coap_keystore_item_t coap_keystore_item_t;

coap_keystore_t *coap_new_keystore(void);

void coap_free_keystore(coap_keystore_t *keystore);

#define COAP_KEYSTORE_RELEASE_REALM 0x01
#define COAP_KEYSTORE_RELEASE_ID    0x02
#define COAP_KEYSTORE_RELEASE_KEY   0x04

coap_keystore_item_t *
coap_keystore_new_psk(void *realm, size_t realm_length,
                      void *id, size_t id_length,
                      void *key, size_t key_length,
                      int flags);


void coap_keystore_free_item(coap_keystore_item_t *item);

int coap_keystore_store_item(coap_keystore_t *keystore,
                             coap_keystore_item_t *item,
                             const coap_address_t *remote);

void coap_keystore_remove_item(coap_keystore_t *keystore,
                               coap_keystore_item_t *item);

coap_keystore_item_t *coap_keystore_find_psk(const coap_keystore_t *keystore,
                                             const void *realm,
                                             size_t realm_length,
                                             const void *id,
                                             size_t identity_length,
                                             const coap_address_t *remote);

ssize_t coap_psk_set_identity(const coap_keystore_item_t *psk,
                              uint8_t *buf, size_t max_len);

ssize_t coap_psk_set_key(const coap_keystore_item_t *psk,
                         uint8_t *buf, size_t max_len);

/** @} */

#endif /* COAP_KEYSTORE_H */
