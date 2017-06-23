/*
 * coap_tinydtls.c -- Datagram Transport Layer Support for libcoap with tinydtls
 *
 * Copyright (C) 2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#include "coap_config.h"

#ifdef HAVE_LIBTINYDTLS

#include "address.h"
#include "debug.h"
#include "mem.h"
#include "coap_dtls.h"

#include <tinydtls.h>
#include <dtls.h>

 /* Prototypes from dtls_debug.h as including that header will conflict
  * with coap_config.h. */
void dtls_set_log_level(int);
int dtls_get_log_level(void);

int
coap_dtls_is_supported(void) {
  return 1;
}

void coap_dtls_startup(void) {
  dtls_init();
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
dtls_send_to_peer(struct dtls_context_t *dtls_context,
  session_t *dtls_session, uint8 *data, size_t len) {
  coap_context_t *coap_context = (coap_context_t *)dtls_get_app_data(dtls_context);
  coap_session_t *coap_session =
    coap_session_get_by_peer(coap_context, (const coap_address_t*)dtls_session, dtls_session->ifindex);
  if (!coap_session) {
    coap_log(LOG_WARNING, "dtls_send_to_peer: cannot find local interface\n");
    return -3;
  }
  return (int)coap_session_send(coap_session, data, len);
}

static int
dtls_application_data(struct dtls_context_t *dtls_context,
  session_t *dtls_session, uint8 *data, size_t len) {
  coap_context_t *coap_context = (coap_context_t *)dtls_get_app_data(dtls_context);
  coap_session_t *coap_session =
    coap_session_get_by_peer(coap_context, (const coap_address_t*)dtls_session, dtls_session->ifindex);
  if (!coap_session) {
    debug("dropped message that was received on invalid interface\n");
    return -1;
  }

  return coap_handle_message(coap_context, coap_session, data, len);
}

static int
dtls_event(struct dtls_context_t *dtls_context,
  session_t *dtls_session,
  dtls_alert_level_t level,
  unsigned short code) {
  coap_context_t *coap_context = (coap_context_t *)dtls_get_app_data(dtls_context);
  coap_session_t *coap_session =
    coap_session_get_by_peer(coap_context, (const coap_address_t*)dtls_session, dtls_session->ifindex);
  int event = (level == DTLS_ALERT_LEVEL_FATAL) ? COAP_EVENT_DTLS_ERROR : -1;

  if (!coap_session) {
    coap_log(LOG_CRIT, "cannot handle event: session not found\n");
    return -1;
  }

  /* handle DTLS events */
  switch (code) {
  case DTLS_ALERT_CLOSE_NOTIFY:
  {
    event = COAP_EVENT_DTLS_CLOSED;
    break;
  }
  case DTLS_EVENT_CONNECTED:
  {
    event = COAP_EVENT_DTLS_CONNECTED;
    break;
  }
  case DTLS_EVENT_RENEGOTIATE:
  {
    event = COAP_EVENT_DTLS_RENEGOTIATE;
    break;
  }
  default:
    ;
  }

  if (event != -1) {
    coap_handle_event(coap_context, event, coap_session);
  }

  if (event == COAP_EVENT_DTLS_CONNECTED)
    coap_session_connected(coap_session);
  else if (event == DTLS_ALERT_CLOSE_NOTIFY || COAP_EVENT_DTLS_ERROR)
    coap_session_disconnected(coap_session);

  return 0;
}

/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identity within this particular
 * session. */
static int
get_psk_info(struct dtls_context_t *dtls_context,
  const session_t *dtls_session,
  dtls_credentials_type_t type,
  const unsigned char *id, size_t id_len,
  unsigned char *result, size_t result_length) {
  coap_context_t *coap_context;
  coap_session_t *coap_session;
  int fatal_error = DTLS_ALERT_INTERNAL_ERROR;
  size_t identity_length;
  static int client = 0;
  static uint8_t psk[128];
  static size_t psk_len = 0;

  if (type == DTLS_PSK_KEY && client) {
    if (psk_len > result_length) {
      coap_log(LOG_WARNING, "cannot set psk -- buffer too small\n");
      goto error;
    }
    memcpy(result, psk, psk_len);
    client = 0;
    return (int)psk_len;
  }

  client = 0;
  coap_context = (coap_context_t *)dtls_get_app_data(dtls_context);
  coap_session =
    coap_session_get_by_peer(coap_context, (const coap_address_t*)dtls_session, dtls_session->ifindex);

  switch (type) {
  case DTLS_PSK_IDENTITY:

    if (id_len)
      coap_log(LOG_DEBUG, "got psk_identity_hint: '%.*s'\n", (int)id_len, id);

    if (!coap_context || !coap_context->get_client_psk)
      goto error;

    identity_length = 0;
    psk_len = coap_context->get_client_psk(coap_session, (const uint8_t*)id, id_len, (uint8_t*)result, &identity_length, result_length, psk, sizeof(psk));
    if (!psk_len) {
      coap_log(LOG_WARNING, "no PSK identity for given realm\n");
      fatal_error = DTLS_ALERT_CLOSE_NOTIFY;
      goto error;
    }
    client = 1;
    return (int)identity_length;

  case DTLS_PSK_KEY:
    if (coap_context->get_server_psk)
      return (int)coap_context->get_server_psk(coap_session, (const uint8_t*)id, id_len, (uint8_t*)result, result_length);
    return 0;
    break;

  case DTLS_PSK_HINT:
    client = 0;
    if (coap_context->get_server_hint)
      return (int)coap_context->get_server_hint(coap_session, (uint8_t *)result, result_length);
    return 0;

  default:
    coap_log(LOG_WARNING, "unsupported request type: %d\n", type);
  }

error:
  client = 0;
  return dtls_alert_fatal_create(fatal_error);
}

static dtls_handler_t cb = {
  .write = dtls_send_to_peer,
  .read = dtls_application_data,
  .event = dtls_event,
  .get_psk_info = get_psk_info,
#ifdef WITH_ECC
  .get_ecdsa_key = NULL,
  .verify_ecdsa_key = NULL
#endif
};

void *
coap_dtls_new_context(struct coap_context_t *coap_context) {
  struct dtls_context_t *dtls_context = dtls_new_context(coap_context);
  if (!dtls_context)
    goto error;
  dtls_set_handler(dtls_context, &cb);
  return dtls_context;
error:
  coap_dtls_free_context(dtls_context);
  return NULL;
}

void
coap_dtls_free_context(void *handle) {
  if (handle) {
    struct dtls_context_t *dtls_context = (struct dtls_context_t *)handle;
    dtls_free_context(dtls_context);
  }
}

static session_t *
coap_dtls_new_session(coap_session_t *session) {
  session_t *dtls_session = coap_malloc_type(COAP_DTLS_SESSION, sizeof(session_t));

  if (dtls_session) {
    /* create tinydtls session object from remote address and local
    * endpoint handle */
    dtls_session_init(dtls_session);
    coap_address_copy((coap_address_t*)dtls_session, &session->remote_addr);
    dtls_session->ifindex = session->ifindex;
    debug("*** new session %p\n", dtls_session);
  }

  return dtls_session;
}

void *coap_dtls_new_server_session(coap_session_t *session) {
  return coap_dtls_new_session(session);
}

void *coap_dtls_new_client_session(coap_session_t *session) {
  dtls_peer_t *peer;
  session_t *dtls_session = coap_dtls_new_session(session);
  if (!dtls_session)
    return NULL;
  peer =
    dtls_get_peer((struct dtls_context_t *)session->context->dtls_context,
      dtls_session);

  if (!peer) {
    /* The peer connection does not yet exist. */
    /* dtls_connect() returns a value greater than zero if a new
    * connection attempt is made, 0 for session reuse. */
    if (dtls_connect((struct dtls_context_t *)session->context->dtls_context,
      dtls_session) >= 0) {
      peer =
	dtls_get_peer((struct dtls_context_t *)session->context->dtls_context,
	  dtls_session);
    }
  }

  if (!peer) {
    /* delete existing session because the peer object has been invalidated */
    coap_free_type(COAP_DTLS_SESSION, dtls_session);
    dtls_session = NULL;
  }

  return dtls_session;
}

void
coap_dtls_free_session(coap_session_t *coap_session) {
  if (coap_session->tls) {
    dtls_close((struct dtls_context_t *)coap_session->context->dtls_context,
      (session_t *)coap_session->tls);
    debug("*** removed session %p\n", coap_session->tls);
    coap_free_type(COAP_DTLS_SESSION, coap_session->tls);
  }
}

int
coap_dtls_send(coap_session_t *session,
  const uint8_t *data,
  size_t data_len
) {
  int res;

  coap_log(LOG_DEBUG, "call dtls_write\n");

  res = dtls_write((struct dtls_context_t *)session->context->dtls_context,
    (session_t *)session->tls, (uint8 *)data, data_len);

  if (res < 0)
    coap_log(LOG_WARNING, "coap_dtls_send: cannot send PDU\n");

  return res;
}

int coap_dtls_get_context_timeout(void *dtls_context) {
  clock_time_t next = 0;
  dtls_check_retransmit((struct dtls_context_t *)dtls_context, &next);
  if (next > 0) {
    clock_time_t now;
    dtls_ticks(&now);
    if (next >= now)
      return (int)(((next - now) * 1000 + DTLS_TICKS_PER_SECOND - 1) / DTLS_TICKS_PER_SECOND);
  }
  return -1;
}

int coap_dtls_get_timeout(coap_session_t *session) {
  (void)session;
  return -1;
}

void coap_dtls_handle_timeout(coap_session_t *session) {
  (void)session;
  return;
}

int
coap_dtls_receive(coap_session_t *session,
  const uint8_t *data,
  size_t data_len
) {
  session_t *dtls_session = (session_t *)session->tls;
  int res = dtls_handle_message(
    (struct dtls_context_t *)session->context->dtls_context,
    dtls_session, (uint8 *)data, (int)data_len);
  return res;
}

int
coap_dtls_hello(coap_session_t *session,
  const uint8_t *data,
  size_t data_len
) {
  session_t dtls_session;
  struct dtls_context_t *dtls_context =
    (struct dtls_context_t *)session->context->dtls_context;

  dtls_session_init(&dtls_session);
  coap_address_copy((coap_address_t*)&dtls_session, &session->remote_addr);
  dtls_session.ifindex = session->ifindex;
  int res = dtls_handle_message(dtls_context, &dtls_session,
    (uint8 *)data, (int)data_len);
  if (res >= 0) {
    if (dtls_get_peer(dtls_context, &dtls_session))
      res = 1;
    else
      res = 0;
  }
  return res;
}

#else /* !HAVE_LIBTINYDTLS */

 /* make compilers happy that do not like empty modules */
static inline void dummy(void) {
}

#endif /* HAVE_LIBTINYDTLS */
