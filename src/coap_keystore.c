/*
 * coap_keystore.c -- libcoap keystore
 *
 * Copyright (C) 2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#include "coap_config.h"
#include "coap.h"

#include "coap_keystore.h"

typedef enum coap_credentials_type_t {
  COAP_KEYSTORE_UNKNOWN=0,
  COAP_KEYSTORE_PSK
} coap_credentials_type_t ;

typedef struct coap_keystore_psk_t {
  void *realm;
  size_t realm_length;
  void *identity;
  size_t identity_length;
  void *key;
  size_t key_length;
  int flags;
} coap_keystore_psk_t;

struct coap_keystore_item_t {
  coap_credentials_type_t type;
  struct coap_keystore_item_t *next;
  union {
    coap_keystore_psk_t psk;
  } entry;
};

struct coap_keystore_t {
  struct coap_keystore_item_t *store;
};

coap_keystore_t *
coap_new_keystore(void) {
  coap_keystore_t *ks;

  ks = (coap_keystore_t *)coap_malloc(sizeof(coap_keystore_t));
  if (ks) {
    memset(ks, 0, sizeof(coap_keystore_t));
  }
  return ks;
}

void
coap_free_keystore(coap_keystore_t *keystore) {
  coap_keystore_item_t *item, *tmp;

  if (keystore) {
    LL_FOREACH_SAFE(keystore->store, item, tmp) {
      coap_keystore_free_item(item);
    }
    coap_free(keystore);
  }
}


coap_keystore_item_t *
coap_keystore_new_psk(void *realm, size_t realm_length,
                      void *id, size_t id_length,
                      void *key, size_t key_length, int flags) {
  coap_keystore_item_t *item;
  item = (coap_keystore_item_t *)coap_malloc(sizeof(coap_keystore_item_t));

  if (item) {
    memset(item, 0, sizeof(coap_keystore_item_t));
    item->type = COAP_KEYSTORE_PSK;
    item->entry.psk.realm = realm;
    item->entry.psk.realm_length = realm_length;
    item->entry.psk.identity = id;
    item->entry.psk.identity_length = id_length;
    item->entry.psk.key = key;
    item->entry.psk.key_length = key_length;
    item->entry.psk.flags = flags;
  }

  return item;
}

static void
free_psk(coap_keystore_psk_t *psk) {
  if (psk) {
    if ((psk->flags & COAP_KEYSTORE_RELEASE_REALM) != 0) {
      coap_free(psk->realm);
    }
    if ((psk->flags & COAP_KEYSTORE_RELEASE_ID) != 0) {
      coap_free(psk->identity);
    }
    if ((psk->flags & COAP_KEYSTORE_RELEASE_KEY) != 0) {
      coap_free(psk->key);
    }
  }
}

void
coap_keystore_free_item(coap_keystore_item_t *item) {
  if (item) {
    switch (item->type) {
    case COAP_KEYSTORE_PSK: free_psk(&item->entry.psk); break;
    case COAP_KEYSTORE_UNKNOWN:
    default:
      ;
    }
    coap_free(item);
  }
}

int
coap_keystore_store_item(coap_keystore_t *keystore,
                         coap_keystore_item_t *item,
                         const coap_address_t *remote __attribute__((unused))) {
  LL_PREPEND(keystore->store, item);
  return 1;
}

void
coap_keystore_remove_item(coap_keystore_t *keystore,
                          coap_keystore_item_t *item) {
  LL_DELETE(keystore->store, item);
  coap_keystore_free_item(item);
}

static inline int
match(const void *a, size_t alen, const void *b, size_t blen) {
  return !a || !b || ((alen == blen) && ((alen == 0) || (memcmp(a, b, alen) == 0)));
}

coap_keystore_item_t *
coap_keystore_find_psk(const coap_keystore_t *keystore,
                       const void *realm, size_t realm_length,
                       const void *identity, size_t identity_length,
                       const coap_address_t *remote __attribute__((unused))) {
  coap_keystore_item_t *item;
#define MATCH_PSK_FIELD(Field, Object)          \
  match((Field),                                \
        Field##_length,                         \
        (Object)->entry.psk.Field,              \
        (Object)->entry.psk.Field##_length)
        
  LL_FOREACH(keystore->store, item) {
    if (item->type == COAP_KEYSTORE_PSK) {
      if (MATCH_PSK_FIELD(realm, item) &&
          MATCH_PSK_FIELD(identity, item)) {
        return item;
      }
    }
  }
  return NULL;
}

ssize_t
coap_psk_set_identity(const coap_keystore_item_t *psk,
                      uint8_t *buf, size_t max_len) {
  if (psk->type != COAP_KEYSTORE_PSK ||
      max_len < psk->entry.psk.identity_length) {
    return -1;
  }

  memset(buf, 0, max_len);

  if (psk->entry.psk.identity_length > 0) {
    memcpy(buf, psk->entry.psk.identity, psk->entry.psk.identity_length);
  }
  return psk->entry.psk.identity_length;
}

ssize_t coap_psk_set_key(const coap_keystore_item_t *psk,
                         uint8_t *buf, size_t max_len) {
  if (psk->type != COAP_KEYSTORE_PSK ||
      max_len < psk->entry.psk.key_length) {
    return -1;
  }

  memset(buf, 0, max_len);

  if (psk->entry.psk.key_length > 0) {
    memcpy(buf, psk->entry.psk.key, psk->entry.psk.key_length);
  }
  return psk->entry.psk.key_length;
}
