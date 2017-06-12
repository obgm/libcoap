/*
 * coap_dtls.c -- Datagram Transport Layer Support for libcoap
 *
 * Copyright (C) 2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#include "coap_config.h"
#include "address.h"
#include "debug.h"
#include "mem.h"
#include "coap_dtls.h"
#include "coap_keystore.h"
#include "utlist.h"

#ifdef __GNUC__
#define UNUSED __attribute__((unused))
#else /* __GNUC__ */
#define UNUSED
#endif /* __GNUC__ */


#ifdef HAVE_LIBTINYDTLS
#include <tinydtls.h>
#include <dtls.h>

/* Prototypes from dtls_debug.h as including that header will conflict
 * with coap_config.h. */
void dtls_set_log_level(int);
int dtls_get_log_level(void);

/* Data item in the DTLS send queue. */
struct queue_t {
  struct queue_t *next;
  coap_tid_t id;
  size_t data_length;
  unsigned char data[];
};

/* This structure takes a tinydtls peer object to represent a session
 * with a remote peer. Note that session_t objects in tinydtls are
 * less useful to pass around because in the end, you will always need
 * to find the corresponding dtls_peer_t object. dtls_session must be
 * * the first component in this structure. */
typedef struct coap_dtls_session_t {
  session_t dtls_session;
  struct coap_dtls_session_t *next;
  struct queue_t *sendqueue;
} coap_dtls_session_t;

/* This structure encapsulates the dtls_context_t object from tinydtls
 * which must always be the first component. */
typedef struct coap_dtls_context_t {
  dtls_context_t *dtls_context;
  coap_dtls_session_t *sessions;
} coap_dtls_context_t;

int
coap_dtls_is_supported(void) {
  return 1;
}

void
coap_dtls_set_log_level(int level) {
  dtls_set_log_level(level);
}

int
coap_dtls_get_log_level(void) {
  return dtls_get_log_level();
}

static int
push_data_item(struct coap_dtls_session_t *session, coap_tid_t id,
               const unsigned char *data, size_t data_length) {
  struct queue_t *item;
#define ITEM_SIZE (sizeof(struct queue_t) + data_length)

  /* Only add if we do not already have that item. */
  LL_SEARCH_SCALAR(session->sendqueue, item, id, id);
  if (!item) {                  /* Not found, add new item */
    if ((item = (struct queue_t *)coap_malloc(ITEM_SIZE)) != NULL) {
      debug("*** add %p to sendqueue of session %p\n", item, session);
      item->id = id;
      item->data_length = data_length;
      memcpy(item->data, data, data_length);
      LL_APPEND(session->sendqueue, item);
    }
  }

  return item != NULL;
}

static int
flush_data(struct coap_dtls_context_t *context,
           struct coap_dtls_session_t *session) {
  struct queue_t *item, *tmp;
  int ok = 0;
  int res;

  LL_FOREACH_SAFE(session->sendqueue, item, tmp) {
    res = dtls_write(context->dtls_context, &session->dtls_session,
                     (uint8_t *)item->data, item->data_length);

    if (res <= 0) {
      debug("data not written\n");
      return ok;
    } else {
      if ((size_t)res < item->data_length) {
        debug("data truncated by dtls_write()\n");
      } else {
        ok = 1;
      }
      LL_DELETE(session->sendqueue, item);
      coap_free(item);
    }
  }

  return ok;
}

static int
dtls_send_to_peer(struct dtls_context_t *dtls_context,
	     session_t *session, uint8 *data, size_t len) {
  coap_context_t *coap_context = dtls_get_app_data(dtls_context);
  coap_endpoint_t *local_interface;

  assert(coap_context);

  LL_SEARCH_SCALAR(coap_context->endpoint, local_interface,
                   handle.fd, session->ifindex);

  if (!local_interface) {
    coap_log(LOG_WARNING, "dtls_send_to_peer: cannot find local interface\n");
    return -3;
  }

  return coap_network_send(coap_context, local_interface,
			   (coap_address_t *)session, data, len);
}

static int
dtls_application_data(struct dtls_context_t *dtls_context,
		      session_t *session, uint8 *data, size_t len) {
  coap_context_t *coap_context;
  coap_endpoint_t *local_interface;

  coap_context = (coap_context_t *)dtls_get_app_data(dtls_context);
  assert(coap_context && coap_context->dtls_context);

  LL_SEARCH_SCALAR(coap_context->endpoint, local_interface,
                   handle.fd, session->ifindex);

  if (!local_interface) {
    debug("dropped message that was received on invalid interface\n");
    return -1;
  }

  return coap_handle_message(coap_context, local_interface,
                             (coap_address_t *)session,
                             (unsigned char *)data, len);
}

static int
dtls_event(struct dtls_context_t *dtls_context,
           session_t *dtls_session,
	   dtls_alert_level_t level,
           unsigned short code) {
  coap_context_t *coap_context;
  coap_dtls_session_t *session;
  int event = (level == DTLS_ALERT_LEVEL_FATAL) ? COAP_EVENT_DTLS_ERROR : -1;

  coap_context = (coap_context_t *)dtls_get_app_data(dtls_context);
  assert(coap_context && coap_context->dtls_context);

  LL_FOREACH(coap_context->dtls_context->sessions, session) {
    if ((session->dtls_session.ifindex == dtls_session->ifindex) &&
        coap_address_equals((coap_address_t *)&session->dtls_session,
                            (coap_address_t *)dtls_session)) {
      break;
    }
  }

  if (!session) {
    coap_log(LOG_CRIT, "cannot handle event: session not found\n");
    return -1;
  }

  /* Stop all transactions that are affected from a fatal error
   * condition. */
  if (level == DTLS_ALERT_LEVEL_FATAL) {
    struct queue_t *item;
    LL_FOREACH(session->sendqueue, item) {
      coap_queue_t *node = NULL;
      coap_remove_from_queue(&coap_context->sendqueue, item->id, &node);
      coap_delete_node(node);
    }
  }

  /* handle DTLS events */
  switch (code) {
  case DTLS_ALERT_CLOSE_NOTIFY: {
    event = COAP_EVENT_DTLS_CLOSED;
    break;
  }
  case DTLS_EVENT_CONNECTED: {
    flush_data(coap_context->dtls_context, session);
    event = COAP_EVENT_DTLS_CONNECTED;
    break;
  }
  case DTLS_EVENT_RENEGOTIATE: {
    event = COAP_EVENT_DTLS_RENEGOTIATE;
    break;
  }
  default:
    ;
  }

  if (event != -1) {
    coap_handle_event(coap_context, event, session);
  }

  if (level == DTLS_ALERT_LEVEL_FATAL) {
    coap_dtls_free_session(coap_context->dtls_context, session);
  }

  return 0;
}

/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identity within this particular
 * session. */
static int
get_psk_info(struct dtls_context_t *dtls_context,
	     const session_t *session,
	     dtls_credentials_type_t type,
	     const unsigned char *id, size_t id_len,
	     unsigned char *result, size_t result_length) {
  coap_context_t *coap_context = dtls_get_app_data(dtls_context);
  coap_keystore_item_t *psk;
  ssize_t length;
  int fatal_error = DTLS_ALERT_INTERNAL_ERROR;

  if(!coap_context || !coap_context->keystore) {
    goto error;
  }

  switch (type) {
  case DTLS_PSK_IDENTITY:
    if (id_len) {
      coap_log(LOG_DEBUG, "got psk_identity_hint: '%.*s'\n", id_len, id);
    }

    psk = coap_keystore_find_psk(coap_context->keystore, id, id_len,
                                 NULL, 0, (coap_address_t *)session);
    if (!psk) {
      coap_log(LOG_WARNING, "no PSK identity for given realm\n");
      fatal_error = DTLS_ALERT_CLOSE_NOTIFY;
      goto error;
    }

    length = coap_psk_set_identity(psk, result, result_length);
    if (length < 0) {
      coap_log(LOG_WARNING, "cannot set psk_identity -- buffer too small\n");
      goto error;
    }

    return length;
  case DTLS_PSK_KEY:
    psk = coap_keystore_find_psk(coap_context->keystore, NULL, 0,
                                 id, id_len, (coap_address_t *)session);
    if (!psk) {
      coap_log(LOG_WARNING, "PSK for unknown id requested, exiting\n");
      fatal_error = DTLS_ALERT_HANDSHAKE_FAILURE;
      goto error;
    }

    length = coap_psk_set_key(psk, result, result_length);
    if (length < 0) {
      coap_log(LOG_WARNING, "cannot set psk -- buffer too small\n");
      goto error;
    }

    return length;
  case DTLS_PSK_HINT:
    /* There is no point in sending a psk_identity_hint hence it is
     * set to zero length. */
    return 0;
  default:
    coap_log(LOG_WARNING, "unsupported request type: %d\n", type);
  }

  error:
    return dtls_alert_fatal_create(fatal_error);
}

static dtls_handler_t cb = {
  .write = dtls_send_to_peer,
  .read  = dtls_application_data,
  .event = dtls_event,
  .get_psk_info = get_psk_info,
#ifdef WITH_ECC
  .get_ecdsa_key = NULL,
  .verify_ecdsa_key = NULL
#endif
};

struct coap_dtls_context_t *
coap_dtls_new_context(struct coap_context_t *coap_context) {
  struct coap_dtls_context_t *context;
#define CONTEXT_SIZE (sizeof(struct coap_dtls_context_t))

  context = (struct coap_dtls_context_t *)coap_malloc(CONTEXT_SIZE);
  if (context) {
    memset(context, 0, CONTEXT_SIZE);

    context->dtls_context = dtls_new_context(coap_context);
    if (!context->dtls_context) {
      goto error;
    }

    dtls_set_handler(context->dtls_context, &cb);
  }

  return context;
 error:

  coap_dtls_free_context(context);
  return NULL;
}

void
coap_dtls_free_context(struct coap_dtls_context_t *dtls_context) {
  while(dtls_context->sessions) {
    coap_dtls_free_session(dtls_context, dtls_context->sessions);
  }
  dtls_free_context(dtls_context->dtls_context);
  coap_free(dtls_context);
}

/* Convenience macro to copy IPv6 addresses without garbage. */
#define COAP_COPY_ADDRESS(DST,SRC) do {                                 \
    (DST)->size = (SRC)->size;                                          \
    if ((SRC)->addr.sa.sa_family == AF_INET6) {                         \
      (DST)->addr.sin6.sin6_family = (SRC)->addr.sin6.sin6_family;      \
      (DST)->addr.sin6.sin6_addr = (SRC)->addr.sin6.sin6_addr;          \
      (DST)->addr.sin6.sin6_port = (SRC)->addr.sin6.sin6_port;          \
    } else {                                                            \
      (DST)->addr.st = (SRC)->addr.st;                                  \
    }                                                                   \
  } while (0);

struct coap_dtls_session_t *
coap_dtls_new_session(coap_dtls_context_t *dtls_context,
                      const coap_endpoint_t *local_interface,
                      const coap_address_t *remote) {
  struct coap_dtls_session_t *session;
  const size_t need = sizeof(struct coap_dtls_session_t);

  session = coap_malloc_type(COAP_DTLS_SESSION, need);

  if (session) {
    /* create tinydtls session object from remote address and local
     * endpoint handle */
    memset(session, 0, need);
    dtls_session_init(&session->dtls_session);
    COAP_COPY_ADDRESS(&session->dtls_session, remote);
    session->dtls_session.ifindex = local_interface->handle.fd;

    LL_PREPEND(dtls_context->sessions, session);
    debug("*** new session %p\n", session);
  }

  return session;
}

void
coap_dtls_free_session(coap_dtls_context_t *dtls_context,
                       coap_dtls_session_t *session) {
  if (session) {
    struct queue_t *item, *tmp;

    LL_DELETE(dtls_context->sessions, session);
    LL_FOREACH_SAFE(session->sendqueue, item, tmp) {
      coap_free(item);
    }
    debug("*** removed session %p\n", session);
    coap_free_type(COAP_DTLS_SESSION, session);
  }
}

static coap_dtls_session_t *
coap_dtls_find_session(coap_dtls_context_t *dtls_context,
                       const coap_endpoint_t *local_interface,
                       const coap_address_t *dst) {
  struct coap_dtls_session_t *session;

  LL_FOREACH(dtls_context->sessions, session) {
    if ((session->dtls_session.ifindex == local_interface->handle.fd) &&
        coap_address_equals((coap_address_t *)&session->dtls_session, dst)) {
      return session;
    }
  }
  return session;
}

struct coap_dtls_session_t *
coap_dtls_get_session(struct coap_context_t *coap_context,
                      const coap_endpoint_t *local_interface,
                      const coap_address_t *dst) {
  dtls_peer_t *peer;
  coap_dtls_session_t *session;

  assert(coap_context && coap_context->dtls_context);

  /* reuse existing session if available, otherwise create new session */
  session = coap_dtls_find_session(coap_context->dtls_context,
                                   local_interface, dst);

  if (!session &&
      ((session = coap_dtls_new_session(coap_context->dtls_context,
                                        local_interface, dst)) == NULL)) {
    coap_log(LOG_WARNING, "cannot create session object\n");
    return NULL;
  }

  peer = dtls_get_peer(coap_context->dtls_context->dtls_context,
                       &session->dtls_session);

  if (!peer) {
    /* The peer connection does not yet exist. */
    /* dtls_connect() returns a value greater than zero if a new
     * connection attempt is made, 0 for session reuse. */
    if (dtls_connect(coap_context->dtls_context->dtls_context,
                     &session->dtls_session) >= 0) {

      peer = dtls_get_peer(coap_context->dtls_context->dtls_context,
                           &session->dtls_session);
    }
  }

  if (!peer) {
    /* delete existing session because the peer object has been invalidated */
    coap_dtls_free_session(coap_context->dtls_context, session);
    session = NULL;
  }

  return session;
}

int
coap_dtls_send(struct coap_context_t *coap_context,
               struct coap_dtls_session_t *session,
               const coap_pdu_t *pdu) {
  int res = -2;

  assert(coap_context && coap_context->dtls_context);
  coap_log(LOG_DEBUG, "call dtls_write\n");

  res = dtls_write(coap_context->dtls_context->dtls_context,
                   &session->dtls_session,
                   (uint8 *)pdu->hdr, pdu->length);

  if (res < 0) {
    coap_log(LOG_WARNING, "coap_dtls_send: cannot send PDU\n");
  } else if (res == 0) {
    coap_tid_t id;
    coap_transaction_id((coap_address_t *)&session->dtls_session, pdu, &id);

    if (!push_data_item(session, id, (uint8 *)pdu->hdr, pdu->length)) {
      coap_log(LOG_DEBUG, "cannot store %u bytes for deferred transmission\n",
               pdu->length);
      res = -2;
    }
  }

  return res;
}

int
coap_dtls_handle_message(struct coap_context_t *coap_context,
                         const coap_endpoint_t *local_interface,
                         const coap_address_t *dst,
                         const unsigned char *data, size_t data_len) {
  coap_dtls_session_t *session;
  int new_session = 0;

  session = coap_dtls_find_session(coap_context->dtls_context,
                                   local_interface, dst);

  if (!session) {
    if ((session = coap_dtls_new_session(coap_context->dtls_context,
                                         local_interface, dst)) != NULL) {
      new_session = 1;
    }
  }

  if (!session) {
    coap_log(LOG_WARNING, "cannot allocate session, drop packet\n");
    return -1;
  }

  int res =
    dtls_handle_message(coap_context->dtls_context->dtls_context,
                        &session->dtls_session, (uint8 *)data, data_len);

  if ((res < 0) && new_session) {
    coap_dtls_free_session(coap_context->dtls_context, session);
  }

  return -1;
}

#else /* HAVE_LIBTINYDTLS */

int
coap_dtls_is_supported(void) {
  return 0;
}

struct coap_dtls_context_t *
coap_dtls_new_context(struct coap_context_t *coap_context UNUSED) {
  return NULL;
}

void
coap_dtls_free_context(struct coap_dtls_context_t *dtls_context) {
}

struct coap_dtls_session_t *
coap_dtls_get_session(struct coap_context_t *coap_context UNUSED,
                      const coap_endpoint_t *local_interface UNUSED,
                      const coap_address_t *dst UNUSED) {
  return NULL;
}

int
coap_dtls_send(struct coap_context_t *coap_context,
               struct coap_dtls_session_t *session,
               const coap_pdu_t *pdu) {
  return -1;
}

struct coap_dtls_session_t *
coap_dtls_new_session(struct coap_dtls_context_t *dtls_context,
                      const coap_endpoint_t *local_interface,
                      const coap_address_t *remote) {
  return NULL;
}

struct coap_dtls_session_t;
void
coap_dtls_free_session(struct coap_dtls_context_t *dtls_context,
                       struct coap_dtls_session_t *session) {}

int
coap_dtls_handle_message(struct coap_context_t *coap_context UNUSED,
                         const coap_endpoint_t *local_interface UNUSED,
                         const coap_address_t *dst UNUSED,
                         const unsigned char *data UNUSED,
                         size_t data_len UNUSED) {
  return -1;
}

#endif /* HAVE_LIBTINYDTLS */

#undef UNUSED
