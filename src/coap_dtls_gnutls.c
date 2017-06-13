/*
 * coap_dtls_gnutls.c -- GunTLS Datagram Transport Layer Support for libcoap
 *
 * Copyright (C) 2017 Dag Bjorklund <dag.bjorklund@comsel.fi>
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
#include <inttypes.h>
#include <stdio.h>
#include <errno.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <unistd.h>

#ifdef __GNUC__
#define UNUSED __attribute__((unused))
#else /* __GNUC__ */
#define UNUSED
#endif /* __GNUC__ */

/* this code was inspired by the gnutls code in AwaLWM2M  */


typedef enum {
  CREDENTIAL_TYPE_NOT_SET,
  CREDENTIAL_TYPE_CLIENT_PSK,
  CREDENTIAL_TYPE_SERVER_PSK
} CredentialType;


typedef enum CertificateFormat_ {
  CERTIFICATE_FORMAT_NONE,
  CERTIFICATE_FORMAT_ASN1,
  CERTIFICATE_FORMAT_PEM
} CertificateFormat;



/* Data item in the DTLS send queue. */
struct queue_t {
  struct queue_t *next;
  coap_tid_t id;
  size_t data_length;
  unsigned char data[];
};

struct coap_dtls_session_t {
  coap_address_t network_address;
  gnutls_session_t dtls_session;
  void *credentials;
  CredentialType credential_type;
  uint8_t session_established;
  uint8_t *buf;
  size_t buf_len;
  struct queue_t *sendqueue;
  int ifindex;
  struct coap_dtls_session_t *next;
  coap_endpoint_t *local_interface;
  coap_context_t *ctx;
};

typedef struct coap_dtls_context_t {
  struct coap_dtls_session_t *sessions;
  coap_context_t *ctx;

  // gnutls stuff
  gnutls_certificate_credentials_t cert_credentials;
  uint8_t *certificate;
  const char *psk_identity;
  int certificate_length;
  gnutls_datum_t psk_key;
  gnutls_priority_t priority_cache;

  CertificateFormat certificateFormat;
  uint8_t client;
} coap_dtls_context_t;


/* Convenience macro to copy IPv6 addresses without garbage. */
#define COAP_COPY_ADDRESS(DST,SRC) do {                             \
    (DST)->size = (SRC)->size;                                      \
    if ((SRC)->addr.sa.sa_family == AF_INET6) {                     \
      (DST)->addr.sin6.sin6_family = (SRC)->addr.sin6.sin6_family;  \
      (DST)->addr.sin6.sin6_addr = (SRC)->addr.sin6.sin6_addr;      \
      (DST)->addr.sin6.sin6_port = (SRC)->addr.sin6.sin6_port;      \
    } else {                                                        \
      (DST)->addr.st = (SRC)->addr.st;                              \
    }                                                               \
  } while (0);


#if GNUTLS_VERSION_MAJOR >= 3
static int
certificate_verify(gnutls_session_t session) {
  (void)session;
  return 0;
}
#endif


void
dtls_set_psk(struct coap_dtls_context_t *ctx, const char * identity, const uint8_t * key, int key_length) {
  if (key_length > 0)  {
    ctx->psk_identity = identity;
    ctx->psk_key.data = (unsigned char *)key;
    ctx->psk_key.size = key_length;
  }
}


/** Returns 1 if support for DTLS is enabled, or 0 otherwise. */
int
coap_dtls_is_supported(void) {
  return 1;
}

/** Sets the log level to the specified value. */
void
coap_dtls_set_log_level(int level) {
  (void)level;
  return;
}

/** Returns the current log level. */
int
coap_dtls_get_log_level(void) {
  return 0;
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
      coap_debug("*** add %p to sendqueue of session %p\n", item, session);
      item->id = id;
      item->data_length = data_length;
      memcpy(item->data, data, data_length);
      LL_APPEND(session->sendqueue, item);
    }
  }
  return item != NULL;
}

/**
 * Creates a new DTLS context for the given @p coap_context. This function
 * returns a pointer to a new DTLS context object or NULL on error.
 *
 * @param coap_context The CoAP context where the DTLS object shall be used.
 * @return A DTLS context object or NULL on error;
 */
struct coap_dtls_context_t *
coap_dtls_new_context(struct coap_context_t *coap_context) {
  gnutls_global_init();

  struct coap_dtls_context_t *context;
#define CONTEXT_SIZE (sizeof(struct coap_dtls_context_t))

  context = (struct coap_dtls_context_t *)coap_malloc(CONTEXT_SIZE);
  if (context) {
    memset(context, 0, CONTEXT_SIZE);
    context->ctx = coap_context;
    context->cert_credentials = NULL;
    context->certificate = NULL;
    context->certificate_length = 0;
    dtls_set_psk(context, "Client_identity", (uint8_t*)"EodEYFJDcdTYbxcc", 16);

#if ((GNUTLS_VERSION_MAJOR > 3) || ((GNUTLS_VERSION_MAJOR == 3) && (GNUTLS_VERSION_MINOR >= 4)))
    gnutls_priority_init(&context->priority_cache, "NONE:+VERS-ALL:+ECDHE-ECDSA:+ECDHE-PSK:+PSK:+CURVE-ALL:+AES-128-CCM-8:+AES-128-CBC:+MAC-ALL:-SHA1:+COMP-ALL:+SIGN-ALL:+CTYPE-X.509", NULL);
#else
    gnutls_priority_init(&context->priority_cache, "NONE:+VERS-TLS-ALL:+ECDHE-ECDSA:+ECDHE-PSK:+PSK:+CURVE-ALL:+AES-128-CBC:+MAC-ALL:-SHA1:+COMP-ALL:+SIGN-ALL:+CTYPE-X.509", NULL);
#endif

  }
  return context;
}


/** Releases the storage allocated for @p dtls_context. */
void
coap_dtls_free_context(struct coap_dtls_context_t *dtls_context) {
  if (dtls_context->cert_credentials) {
    //free(cert_credentials);
    dtls_context->cert_credentials = NULL;
  }
  if (dtls_context->certificate) {
    //free(certificate);
    dtls_context->certificate = NULL;
  }
  if (dtls_context->psk_identity) {
    //free(psk_identity);
    dtls_context->psk_identity = NULL;
  }
  dtls_context->certificate_length = 0;

  struct coap_dtls_session_t *session;
  LL_FOREACH(dtls_context->sessions, session) {
    coap_dtls_free_session(dtls_context, session);
  }
  for (session = dtls_context->sessions; session != NULL; ) {
    struct coap_dtls_session_t *tmp = session;
    session = session->next;
    coap_free(tmp);
  }
  if (dtls_context->cert_credentials) {
    gnutls_certificate_free_credentials(dtls_context->cert_credentials);
    dtls_context->cert_credentials = NULL;

    gnutls_priority_deinit(dtls_context->priority_cache);
  }

  gnutls_global_deinit();
  coap_free(dtls_context);
}

/* callback passed to gnutls_transport_set_pull_function */
static ssize_t
decrypt_callback(gnutls_transport_ptr_t context, void *receive_buffer, size_t receive_buffer_length) {
  ssize_t result;
  struct coap_dtls_session_t * session = (struct coap_dtls_session_t *)context;

  coap_endpoint_t *local_interface;
  assert(session->ctx);
  assert(session->ctx->endpoint);

  if (session->buf_len == 0) {
    LL_SEARCH_SCALAR(session->ctx->endpoint, local_interface,
                     handle.fd, session->ifindex);

    ssize_t bytes_read = 0;
    int retries = 3;
    // TODO1: should not do socket operations in this file, use coap_network_read?
    // TODO2: case we do receive here, should select/poll, but what should be the timeout
    while (bytes_read <= 0 && retries-- >= 0) {
      bytes_read = recv(local_interface->handle.fd, receive_buffer, receive_buffer_length, 0);
      if (bytes_read < 0) {
        if (errno == EAGAIN) {
          coap_log(LOG_DEBUG, "eagain\n");
          sleep(1);
        } else {
          break;
        }
      }
    }
    return bytes_read;
  }

  if (session->buf_len > 0) {
    if (receive_buffer_length < session->buf_len) {
      result = receive_buffer_length;
    } else {
      result = session->buf_len;
    }
    memcpy(receive_buffer, session->buf, result);
    session->buf_len = session->buf_len - result;
    session->buf += result;
  } else {
    errno = EAGAIN;
    result = -1;
  }
  return result;
}


/* callback function given to gnutls for sending data over socket */
static ssize_t
dtls_send_to_peer(gnutls_transport_ptr_t context, const void * send_buffer,
                  size_t send_buffer_length) {
  int result = 0;
  struct coap_dtls_session_t *dtls_session = (struct coap_dtls_session_t *)context;
  if (dtls_session) {
    coap_endpoint_t *local_interface;
    assert(dtls_session->ctx);
    assert(dtls_session->ctx->endpoint);

    LL_SEARCH_SCALAR(dtls_session->ctx->endpoint, local_interface,
                     handle.fd, dtls_session->ifindex);

    assert(local_interface);
    result = coap_network_send(dtls_session->ctx, local_interface,
                               &dtls_session->network_address, (uint8_t*)send_buffer, send_buffer_length);
    if (result != (int)send_buffer_length) {
      coap_log(LOG_WARNING, "coap_network_send failed\n");
      result = 0;
    }
  } else {
    result = 0;
  }
  return result;
}

/* callback passed to gnutls_psk_set_client_credentials_function */
static int
psk_client_callback(gnutls_session_t session, char **username, gnutls_datum_t * key) {
  (void)session; (void)username; (void)key;
  assert(0);
  return 0;
}

/* callback passed to gnutls_psk_set_server_credentials_function(credentials, psk_callback */
static int
psk_callback(gnutls_session_t session, const char *username, gnutls_datum_t * key) {
  struct coap_dtls_session_t* dtls_session = (struct coap_dtls_session_t *)gnutls_transport_get_ptr(session);
  (void)username;
  key->data = gnutls_malloc(dtls_session->ctx->dtls_context->psk_key.size);
  key->size = dtls_session->ctx->dtls_context->psk_key.size;
  memcpy(key->data, dtls_session->ctx->dtls_context->psk_key.data, key->size);
  return 0;
}

#if GNUTLS_VERSION_MAJOR >= 3
static int
receive_timeout(gnutls_transport_ptr_t context, unsigned int ms) {
  fd_set rfds;
  struct timeval tv;
  int ret;
  struct coap_dtls_session_t *session = (struct coap_dtls_session_t*)context;

  coap_endpoint_t *local_interface;
  assert(session->ctx);
  assert(session->ctx->endpoint);

  LL_SEARCH_SCALAR(session->ctx->endpoint, local_interface,
                   handle.fd, session->ifindex);

  assert(local_interface);

  // TODO: don't do socket operations in this file
  int fd = local_interface->handle.fd;

  FD_ZERO(&rfds);
  FD_SET(fd, &rfds);
  ms = 4000;
  tv.tv_sec = ms/1000;
  tv.tv_usec = (ms % 1000) * 1000;

  ret = select(fd + 1, &rfds, NULL, NULL, &tv);
  if (ret <= 0)
    return ret;
  return ret;
}
#endif


struct coap_dtls_session_t *
coap_dtls_new_session(struct coap_dtls_context_t *dtls_context,
                      const coap_endpoint_t *local_interface,
                      const coap_address_t *remote) {
  struct coap_dtls_session_t *session;
  const size_t need = sizeof(struct coap_dtls_session_t);
  session = coap_malloc_type(COAP_DTLS_SESSION, need);
  if (session) {
    memset(session, 0, need);
    COAP_COPY_ADDRESS(&session->network_address, remote);
    session->ifindex = local_interface->handle.fd;
    assert(dtls_context->ctx);
    session->ctx = dtls_context->ctx;

    int flags = 0;
#if GNUTLS_VERSION_MAJOR >= 3
    if (dtls_context->client)
      flags = GNUTLS_CLIENT | GNUTLS_DATAGRAM | GNUTLS_NONBLOCK;
    else
      flags = GNUTLS_SERVER | GNUTLS_DATAGRAM | GNUTLS_NONBLOCK;
#else
    if (dtls_context->client)
      flags = GNUTLS_CLIENT;
    else
      flags = GNUTLS_SERVER;
#endif

    assert(gnutls_init(&session->dtls_session, flags) == GNUTLS_E_SUCCESS);

    gnutls_transport_set_pull_function(session->dtls_session, decrypt_callback);
    gnutls_transport_set_push_function(session->dtls_session, dtls_send_to_peer);
#if GNUTLS_VERSION_MAJOR >= 3
    gnutls_transport_set_pull_timeout_function(session->dtls_session, receive_timeout);
#endif
    gnutls_transport_set_ptr(session->dtls_session, session); // set user data

    if (dtls_context->certificate || !dtls_context->psk_identity) {
      if (dtls_context->cert_credentials) {
        gnutls_credentials_set(session->dtls_session, GNUTLS_CRD_CERTIFICATE, dtls_context->cert_credentials);
      } else if (gnutls_certificate_allocate_credentials(&dtls_context->cert_credentials) == GNUTLS_E_SUCCESS) {
        if (dtls_context->certificate) {
          gnutls_datum_t certificateData;
          certificateData.data = dtls_context->certificate;
          certificateData.size = dtls_context->certificate_length;
          int format = GNUTLS_X509_FMT_PEM;
          if (dtls_context->certificateFormat == CERTIFICATE_FORMAT_ASN1)
            format = GNUTLS_X509_FMT_DER;
          //                if (dtls_context->client)
          //                    gnutls_certificate_set_x509_trust_mem(session->Credentials, &certificateData, format);
          //                else
          gnutls_certificate_set_x509_key_mem(dtls_context->cert_credentials, &certificateData, &certificateData, format);
        }
#if GNUTLS_VERSION_MAJOR >= 3
        gnutls_certificate_set_verify_function(dtls_context->cert_credentials, certificate_verify);
        //gnutls_certificate_set_retrieve_function(xcred, cert_callback);
        //gnutls_session_set_verify_cert(session->dtls_session, NULL, GNUTLS_VERIFY_DISABLE_CA_SIGN);
#else
        gnutls_certificate_set_verify_flags(cert_credentials, GNUTLS_VERIFY_DISABLE_CA_SIGN);
#endif
        gnutls_credentials_set(session->dtls_session, GNUTLS_CRD_CERTIFICATE, dtls_context->cert_credentials);
      }
    }
    if (dtls_context->psk_identity) {
      if (dtls_context->client) {
        if (!dtls_context->certificate) {
          gnutls_psk_client_credentials_t credentials;
          if (gnutls_psk_allocate_client_credentials(&credentials) == GNUTLS_E_SUCCESS) {
            if (gnutls_psk_set_client_credentials(credentials, dtls_context->psk_identity, &dtls_context->psk_key, GNUTLS_PSK_KEY_RAW) == GNUTLS_E_SUCCESS) {
              gnutls_credentials_set(session->dtls_session, GNUTLS_CRD_PSK, credentials);
              session->credentials = credentials;
              session->credential_type = CREDENTIAL_TYPE_CLIENT_PSK;
            } else {
              gnutls_psk_set_client_credentials_function(credentials, psk_client_callback);
              session->credentials = credentials;
              session->credential_type = CREDENTIAL_TYPE_CLIENT_PSK;
            }
          }
        }
      } else {
        gnutls_psk_server_credentials_t credentials;
        if (gnutls_psk_allocate_server_credentials(&credentials) == GNUTLS_E_SUCCESS) {
          gnutls_psk_set_server_credentials_function(credentials, psk_callback);
          gnutls_credentials_set(session->dtls_session, GNUTLS_CRD_PSK, credentials);
          session->credentials = credentials;
          session->credential_type = CREDENTIAL_TYPE_SERVER_PSK;
        }
      }
    }

    gnutls_priority_set(session->dtls_session, dtls_context->priority_cache);
    if (!dtls_context->client) {
      gnutls_certificate_server_set_request(session->dtls_session, GNUTLS_CERT_REQUEST); // GNUTLS_CERT_IGNORE  Don't require Client Cert
    }

#if GNUTLS_VERSION_MAJOR >= 3
    gnutls_handshake_set_timeout(session->dtls_session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
#endif
  }

  LL_PREPEND(dtls_context->sessions, session);

  return session;
}

void
coap_dtls_free_session(struct coap_dtls_context_t *dtls_context,
                       struct coap_dtls_session_t *session) {

  (void)dtls_context;
  if (session->credentials) {
    if (session->credential_type == CREDENTIAL_TYPE_CLIENT_PSK) {
      gnutls_psk_free_client_credentials(session->credentials);
    } else if (session->credential_type == CREDENTIAL_TYPE_SERVER_PSK) {
      gnutls_psk_free_server_credentials(session->credentials);
    }

  }
  gnutls_deinit(session->dtls_session);
  memset(session,0, sizeof(session->dtls_session));
}

static struct coap_dtls_session_t *
coap_dtls_find_session(coap_dtls_context_t *dtls_context,
                       const coap_endpoint_t *local_interface,
                       const coap_address_t *dst) {
  struct coap_dtls_session_t *session = NULL;
  LL_FOREACH(dtls_context->sessions, session) {
    if ((session->ifindex == local_interface->handle.fd) &&
        coap_address_equals(&session->network_address, dst)) {
      return session;
    }
  }
  return session;
}

struct coap_dtls_session_t *
coap_dtls_get_session(struct coap_context_t *coap_context,
                      const coap_endpoint_t *local_interface,
                      const coap_address_t *dst) {
  struct coap_dtls_session_t *session;
  assert(coap_context);
  /* reuse existing session if available, otherwise create new session */
  session = coap_dtls_find_session(coap_context->dtls_context,
                                   local_interface, dst);
  // coap_dtls_get_session is called in a client scenario, marking client=1 in context
  // this is used later to tell gnutls we are the client
  coap_context->dtls_context->client = 1;
  if (!session &&
      ((session = coap_dtls_new_session(coap_context->dtls_context,
                                        local_interface, dst)) == NULL)) {
    coap_log(LOG_WARNING, "cannot create session object\n");
    return NULL;
  }
  return session;
}

/* coap_dlts_send is called by lib-coap in order to send data over dtls */
int
coap_dtls_send(struct coap_context_t *coap_context,
               struct coap_dtls_session_t *session,
               const coap_pdu_t *pdu) {
  int res = -2;

  assert(coap_context && coap_context->dtls_context && session);

  coap_log(LOG_DEBUG, "call dtls_write\n");
  assert(session->dtls_session);

  if (session->session_established) {
    res = gnutls_write(session->dtls_session, (uint8_t *)pdu->hdr, pdu->length);

    if (res < 0) {
      coap_log(LOG_WARNING, "coap_dtls_send: cannot send PDU\n");
    } else if (res == 0) {

      coap_tid_t id;
      coap_transaction_id((coap_address_t *)&session->dtls_session, pdu, &id);

      if (!push_data_item(session, id, (uint8_t *)pdu->hdr, pdu->length)) {
        coap_log(LOG_DEBUG, "cannot store %u bytes for deferred transmission\n",
                 pdu->length);
        res = -2;
      }
    }
  } else {
    int r = gnutls_handshake(session->dtls_session);

    session->session_established = (r == GNUTLS_E_SUCCESS);
    if (session->session_established) {
      res = 0;
      // recursive call
      coap_dtls_send(coap_context, session, pdu);
    } else {
      coap_log(LOG_WARNING, "session establish returned %d\n", r);
    }
  }
  return res;
}


/* coap_dtls_handle message is called from lib-coap */
int
coap_dtls_handle_message(struct coap_context_t *coap_context,
                         const coap_endpoint_t *local_interface,
                         const coap_address_t *dst,
                         const unsigned char *data,
                         size_t data_len) {
  struct coap_dtls_session_t *session;
  int new_session = 0;
  int ret = -1;
  session = coap_dtls_find_session(coap_context->dtls_context,
                                   local_interface, dst);

  if (session) {
    session->buf = (unsigned char*)data;
    session->buf_len = data_len; // encrypted length
    if (session->session_established) {
      int decrypted_len = gnutls_read(session->dtls_session, (uint8_t*)data, data_len);

      if ((decrypted_len <= 0) && new_session) {
        coap_dtls_free_session(coap_context->dtls_context, session);
      } else {
        ret = coap_handle_message(coap_context, local_interface, dst, (unsigned char*)data, decrypted_len);
      }
    } else {
      session->session_established = (gnutls_handshake(session->dtls_session) == GNUTLS_E_SUCCESS);
      if (session->session_established) {
        coap_log(LOG_DEBUG, "session established\n");
      }
    }
  }

  if (!session) {
    // coap_dtls_handle_message is called in a server scenario, marking client=0 in context
    // this is used later to tell gnutls we are the server
    coap_context->dtls_context->client = 0;
    if ((session = coap_dtls_new_session(coap_context->dtls_context,
                                         local_interface, dst)) != NULL) {
      new_session = 1;
      session->buf = (unsigned char*)data;
      session->buf_len = data_len;
      session->session_established = (gnutls_handshake(session->dtls_session) == GNUTLS_E_SUCCESS);
      if (session->session_established) {
        // recursive call
        coap_dtls_handle_message(coap_context, local_interface, dst, data, data_len);
      } else {
        coap_log(LOG_WARNING, "failed to establish session\n");
      }
    }
  }

  if (!session) {
    coap_log(LOG_WARNING, "cannot allocate session, drop packet\n");
  }
  return ret;
}
