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
#include "utlist.h"

#ifdef __GNUC__
#define UNUSED __attribute__((unused))
#else /* __GNUC__ */
#define UNUSED
#endif /* __GNUC__ */


#ifdef HAVE_LIBTINYDTLS
#include <tinydtls.h>
#include <dtls.h>

/* This structure encapsulates the dtls_context_t object from tinydtls
 * which must always be the first component. */
typedef struct coap_dtls_context_t {
  dtls_context_t dtls_context;
} coap_dtls_context_t;

/* This structure takes a tinydtls peer object to represent a session
 * with a remote peer. Note that session_t objects in tinydtls are
 * less useful to pass around because in the end, you will always need
 * to find the corresponding dtls_peer_t object. dtls_session must be
 * * the first component in this structure. */
typedef struct coap_dtls_session_t {
  session_t dtls_session;
} coap_dtls_session_t;

int
coap_dtls_is_supported(void) {
  return 1;
}

static int
dtls_send_to_peer(struct dtls_context_t *dtls_context, 
	     session_t *session, uint8 *data, size_t len) {
  coap_context_t *coap_context = dtls_get_app_data(dtls_context);
  coap_endpoint_t *local_interface = NULL;

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
dtls_application_data(struct dtls_context_t *dtls_context UNUSED, 
		      session_t *session UNUSED, uint8 *data, size_t len UNUSED) {
  coap_log(LOG_DEBUG, "#### dtls_application_data\n");
  coap_log(LOG_DEBUG, "%s\n", (char *)data);
  coap_log(LOG_DEBUG, "##########################\n");
  return 0;
}

static int 
dtls_event(struct dtls_context_t *dtls_context_t,
           session_t *session, 
	   dtls_alert_level_t level,
           unsigned short code) {
  coap_log(LOG_DEBUG, "*** EVENT: %d %d\n", level, code);

  /* handle DTLS events */
  switch (code) {
  case DTLS_EVENT_CONNECTED: {
    debug("DTLS_EVENT_CONNECTED\n");
    break;
  }
  default:
    debug("unhandled event %x\n", code);
  }

  return 0;
}

int
coap_dtls_store_credentials(coap_dtls_context_t *dtls_context,
                            const coap_endpoint_t *local_interface,
                            const coap_address_t *remote,
                            dtls_credentials_type_t type) {

  return 0;
}
                            

/* The PSK information for DTLS */
static char psk_id[] = "Client_identity";
static size_t psk_id_length = 15;
static char psk_key[] = "secretPSK";
static size_t psk_key_length = 9;

/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identity within this particular
 * session. */
static int
get_psk_info(struct dtls_context_t *dtls_context UNUSED,
	     const session_t *session UNUSED,
	     dtls_credentials_type_t type,
	     const unsigned char *id, size_t id_len,
	     unsigned char *result, size_t result_length) {

  switch (type) {
  case DTLS_PSK_IDENTITY:
    if (id_len) {
      coap_log(LOG_DEBUG, "got psk_identity_hint: '%.*s'\n", id_len, id);
    }

    if (result_length < psk_id_length) {
      coap_log(LOG_WARNING, "cannot set psk_identity -- buffer too small\n");
      return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    }

    memcpy(result, psk_id, psk_id_length);
    return psk_id_length;
  case DTLS_PSK_KEY:
    if (id_len != psk_id_length || memcmp(psk_id, id, id_len) != 0) {
      coap_log(LOG_WARNING, "PSK for unknown id requested, exiting\n");
      return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);
    } else if (result_length < psk_key_length) {
      coap_log(LOG_WARNING, "cannot set psk -- buffer too small\n");
      return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    }

    memcpy(result, psk_key, psk_key_length);
    return psk_key_length;
  default:
    coap_log(LOG_WARNING, "unsupported request type: %d\n", type);
  }

  return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
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
  dtls_context_t *dtls;

  dtls = dtls_new_context(coap_context);
  if (dtls) {
    dtls_set_handler(dtls, &cb);
  }

  return (coap_dtls_context_t *)dtls;
}

void
coap_dtls_free_context(struct coap_dtls_context_t *dtls_context) {
  dtls_free_context((dtls_context_t *)dtls_context);
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
coap_dtls_new_session(const coap_endpoint_t *local_interface,
                      const coap_address_t *remote) {
  struct coap_dtls_session_t *session;

  session = coap_malloc_type(COAP_DTLS_SESSION,
                             sizeof(struct coap_dtls_session_t));

  if (session) {
    /* create tinydtls session object from remote address and local
     * endpoint handle */
    dtls_session_init(&session->dtls_session);
    COAP_COPY_ADDRESS(&session->dtls_session, remote);
    session->dtls_session.ifindex = local_interface->handle.fd;
  }

  return session;
}

void
coap_dtls_free_session(coap_dtls_session_t *session) {
  coap_free_type(COAP_DTLS_SESSION, session);
}

struct coap_dtls_session_t *
coap_dtls_get_session(struct coap_context_t *coap_context,
                      const coap_endpoint_t *local_interface,
                      const coap_address_t *dst) {
  dtls_peer_t *peer;
  coap_dtls_session_t *session;

  assert(coap_context && coap_context->dtls_context);

  session = coap_dtls_new_session(local_interface, dst);
  if (!session) {
    coap_log(LOG_WARNING, "cannot create session object\n");
    return NULL;
  }

  peer = dtls_get_peer((dtls_context_t *)coap_context->dtls_context,
                       &session->dtls_session);

  if (!peer) {
    /* The peer connection does not yet exist. */
    /* dtls_connect() returns a value greater than zero if a new
     * connection attempt is made, 0 for session reuse. */
    if (dtls_connect((dtls_context_t *)coap_context->dtls_context,
                     &session->dtls_session) >= 0) {

      peer = dtls_get_peer((dtls_context_t *)coap_context->dtls_context,
                           &session->dtls_session);
    }
  }

  if (!peer) {
    coap_dtls_free_session(session);
    session = NULL;
  }

  return session;
}

int
coap_dtls_send(struct coap_context_t *coap_context,
               struct coap_dtls_session_t *session,
               const unsigned char *data, size_t data_len) {
  int res = -2;

  assert(coap_context && coap_context->dtls_context);
  coap_log(LOG_DEBUG, "call dtls_write\n");

  res = dtls_write((dtls_context_t *)coap_context->dtls_context,
                   &session->dtls_session,
                   (uint8 *)data, data_len);

  if (res >= 0 && (size_t)res < data_len) {
    /* store remaining data in send queue */
    /* if (coap_application_push_data_item(app, local_interface->handle, */
    /*                                     (coap_address_t *)&session, */
    /*                                     data + res, len - res)) { */
    coap_log(LOG_DEBUG, "stored %u bytes for deferred transmission\n",
             data_len - res);
  } else {
    coap_log(LOG_WARNING, "could not send %u bytes\n", data_len - res);
  }

  return res;
}

int
coap_dtls_handle_message(struct coap_context_t *coap_context,
                         const coap_endpoint_t *local_interface,
                         const coap_address_t *dst,
                         const unsigned char *data, size_t data_len) {
  coap_dtls_session_t *session;

  session = coap_dtls_new_session(local_interface, dst);

  if (!session) {
    coap_log(LOG_WARNING, "cannot allocate session, drop packet\n");
    return -1;
  }

  dtls_handle_message((dtls_context_t *)coap_context->dtls_context,
                      &session->dtls_session, (uint8 *)data, data_len);

  coap_dtls_free_session(session);
  
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
coap_dtls_send(struct coap_context_t *coap_context UNUSED,
               struct coap_dtls_session_t *session UNUSED,
               const unsigned char *data UNUSED, size_t data_len UNUSED) {
  return -1;
}

struct coap_dtls_session_t *
coap_dtls_new_session(const coap_endpoint_t *local_interface UNUSED,
                      const coap_address_t *remote UNUSED) {
  return NULL;
}

void
coap_dtls_free_session(coap_dtls_session_t *session UNUSED) {}

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
