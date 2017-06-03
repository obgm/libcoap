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


#if defined(HAVE_LIBTINYDTLS)
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

#elif defined(HAVE_OPENSSL)

#include <openssl/ssl.h>
#include <openssl/err.h>

/* Data item in the DTLS send queue. */
struct queue_t {
	struct queue_t *next;
	coap_tid_t id;
	size_t data_length;
	unsigned char data[];
};

/* This structure takes an SSL object to represent a session with a remote peer. */
typedef struct coap_dtls_session_t {
	SSL *ssl;					/* OpenSSL session */
	BIO *bio;					/* encrypted datagrams handler */
	coap_address_t remote;		/* remote address and port */
	struct coap_dtls_session_t *next;
	struct queue_t *sendqueue;
} coap_dtls_session_t;

/* This structure encapsulates the OpenSSL context object. */
typedef struct coap_dtls_context_t {
	SSL_CTX *ctx;
	SSL *ssl;	/* OpenSSL object for listening to connection requests */
	BIO *bio;	/* I/O stream for ClientHello / HelloVerifyRequest datagrams */
	coap_dtls_session_t *sessions;
} coap_dtls_context_t;

int coap_dtls_is_supported( void ) {
	return 1;
}

static int dtls_log_level = 0;

void coap_dtls_set_log_level( int level ) {
	level = dtls_log_level;
}

int coap_dtls_get_log_level( void ) {
	return dtls_log_level;
}

static int push_data_item( struct coap_dtls_session_t *session, coap_tid_t id, const unsigned char *data, size_t data_length ) {
	struct queue_t *item;
#define ITEM_SIZE (sizeof(struct queue_t) + data_length)

	/* Only add if we do not already have that item. */
	LL_SEARCH_SCALAR( session->sendqueue, item, id, id );
	if ( !item ) {                  /* Not found, add new item */
		if ( ( item = ( struct queue_t * )coap_malloc( ITEM_SIZE ) ) != NULL ) {
			debug( "*** add %p to sendqueue of session %p\n", item, session );
			item->id = id;
			item->data_length = data_length;
			memcpy( item->data, data, data_length );
			LL_APPEND( session->sendqueue, item );
		}
	}

	return item != NULL;
}

static int coap_dgram_write( BIO *h, const char *buf, int num );
static int coap_dgram_read( BIO *h, char *buf, int size );
static int coap_dgram_puts( BIO *h, const char *str );
static long coap_dgram_ctrl( BIO *h, int cmd, long arg1, void *arg2 );
static int coap_dgram_new( BIO *h );
static int coap_dgram_free( BIO *data );
static int coap_dgram_clear( BIO *bio );

static BIO_METHOD methods_coap = {
	BIO_TYPE_DGRAM,
	"coap socket",
	coap_dgram_write,
	coap_dgram_read,
	coap_dgram_puts,
	NULL, /* coap_dgram_gets, */
	coap_dgram_ctrl,
	coap_dgram_new,
	coap_dgram_free,
	NULL
};

typedef struct coap_ssl_st {
	const coap_endpoint_t *local_interface;
	const coap_address_t *peer;
	const void *pdu;
	unsigned pdu_len;
	unsigned mtu;
} coap_ssl_data;

static int coap_dgram_new( BIO *bi ) {
	coap_ssl_data *data = NULL;
	bi->init = 1;
	bi->num = 0;
	data = malloc( sizeof( coap_ssl_data ) );
	if ( data == NULL )
		return 0;
	memset( data, 0x00, sizeof( coap_ssl_data ) );
	data->mtu = 1280 - 40 - 8;
	bi->ptr = data;
	bi->flags = 0;
	return 1;
}

static int coap_dgram_free( BIO *a ) {
	coap_ssl_data *data;
	if ( a == NULL )
		return 0;
	if ( !coap_dgram_clear( a ) )
		return 0;
	data = (coap_ssl_data *)a->ptr;
	if ( data != NULL )
		free( data );
	return 1;
}

static int coap_dgram_clear( BIO *a ) {
	coap_ssl_data *data;
	if ( a == NULL )
		return 0;
	data = (coap_ssl_data *)a->ptr;
	if ( a->shutdown ) {
		a->flags = 0;
		if ( data ) {
			data->local_interface = NULL;
			data->peer = NULL;
		}
	}
	if ( data ) {
		data->pdu = NULL;
		data->pdu_len = 0;
	}
	return 1;
}

static int coap_dgram_read( BIO *b, char *out, int outl ) {
	int ret = 0;
	coap_ssl_data *data = (coap_ssl_data *)b->ptr;

	if ( out != NULL ) {
		if ( data != NULL && data->pdu_len > 0 ) {
			if ( outl < (int)data->pdu_len ) {
				memcpy( out, data->pdu, outl );
				ret = outl;
			} else {
				memcpy( out, data->pdu, data->pdu_len );
				ret = (int)data->pdu_len;
			}
			data->pdu_len = 0;
			data->pdu = NULL;
		} else {
			ret = -1;
		}
		BIO_clear_retry_flags( b );
		if ( ret < 0 )
			BIO_set_retry_read( b );
	}
	return ret;
}

static int coap_dgram_write( BIO *b, const char *in, int inl ) {
	int ret = 0;
	coap_ssl_data *data = (coap_ssl_data *)b->ptr;

	if ( data->peer ) {
		ret = (int)coap_network_send( data->local_interface->context, data->local_interface, data->peer, (unsigned char*)in, (size_t)inl );
		BIO_clear_retry_flags( b );
		if ( ret <= 0 )
			BIO_set_retry_write( b );
	} else {
		BIO_clear_retry_flags( b );
		ret = -1;
	}
	return ret;
}

static int coap_dgram_puts( BIO *bp, const char *str ) {
	return coap_dgram_write( bp, str, (int)strlen( str ) );
}

static long coap_dgram_ctrl( BIO *b, int cmd, long num, void *ptr ) {
	long ret = 1;
	struct sockaddr *to = NULL;
	coap_ssl_data *data = NULL;

	data = (coap_ssl_data *)b->ptr;

	switch ( cmd ) {
		case BIO_CTRL_GET_CLOSE:
			ret = b->shutdown;
			break;
		case BIO_CTRL_SET_CLOSE:
			b->shutdown = (int)num;
			break;
			ret = 0;
			break;
		case BIO_CTRL_DGRAM_QUERY_MTU:
		case BIO_CTRL_DGRAM_GET_FALLBACK_MTU:
			ret = 576 - 20 - 8;
			if ( data->peer ) {
				if ( data->peer->addr.sa.sa_family == AF_INET )
					ret = 1280 - 20 - 8;
				else if ( data->peer->addr.sa.sa_family == AF_INET6 )
					ret = 1280 - 40 - 8;
			}
			break;
		case BIO_CTRL_DGRAM_GET_MTU:
			return (long)data->mtu;
		case BIO_CTRL_DGRAM_SET_MTU:
			data->mtu = (unsigned)num;
			ret = num;
			break;
		case BIO_CTRL_DGRAM_CONNECT:
		case BIO_C_SET_FD:
		case BIO_C_GET_FD:
			ret = -1;
			break;
		case BIO_CTRL_DUP:
		case BIO_CTRL_FLUSH:
		case BIO_CTRL_DGRAM_MTU_DISCOVER:
		case BIO_CTRL_DGRAM_SET_CONNECTED:
		case BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT:
			ret = 1;
			break;
		case BIO_CTRL_RESET:
		case BIO_C_FILE_SEEK:
		case BIO_C_FILE_TELL:
		case BIO_CTRL_INFO:
		case BIO_CTRL_PENDING:
		case BIO_CTRL_WPENDING:
		case BIO_CTRL_DGRAM_GET_PEER:
		case BIO_CTRL_DGRAM_SET_PEER:
		case BIO_CTRL_DGRAM_SET_RECV_TIMEOUT:
		case BIO_CTRL_DGRAM_GET_RECV_TIMEOUT:
		case BIO_CTRL_DGRAM_SET_SEND_TIMEOUT:
		case BIO_CTRL_DGRAM_GET_SEND_TIMEOUT:
		case BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP:
		case BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP:
		case BIO_CTRL_DGRAM_MTU_EXCEEDED:
		default:
			ret = 0;
			break;
	}
	return ret ;
}

static int coap_dtls_verify_cert( int ok, X509_STORE_CTX *ctx ) {
	coap_log( LOG_WARNING, "cannot accept DTLS connection with certificate.\n" );
	return 0;	/* For now, trust no one */
}

static int coap_dtls_generate_cookie( SSL *ssl, unsigned char *cookie, unsigned int *cookie_len ) {
	memcpy( cookie, "COOKIE", 6 );
	*cookie_len = 6;
	return 1;
}

static int coap_dtls_verify_cookie( SSL *ssl, unsigned char *cookie, unsigned int cookie_len ) {
	if ( cookie_len == 6 && memcmp( cookie, "COOKIE", 6 ) == 0 )
		return 1;
	else
		return 0;
}

static unsigned coap_dtls_psk_client_callback( SSL *ssl, const char *hint, char *identity, unsigned int max_identity_len, unsigned char *buf, unsigned max_len ) {
	BIO *rbio = SSL_get_rbio( ssl );
	coap_ssl_data *data = (coap_ssl_data*)rbio->ptr;
	coap_context_t *coap_context = data->local_interface->context;
	coap_keystore_item_t *psk;
	size_t hint_len = 0;
	ssize_t length = 0;

	if ( hint )
		hint_len = strlen( hint );
	if ( hint_len )
		coap_log( LOG_DEBUG, "got psk_identity_hint: '%.*s'\n", (int)hint_len, hint );

	if ( !coap_context->keystore )
		return 0;
	psk = coap_keystore_find_psk( coap_context->keystore, hint, hint_len, NULL, 0, data->peer );
	if ( !psk ) {
		coap_log( LOG_WARNING, "no PSK identity for given realm\n" );
		return 0;
	}

	length = coap_psk_set_identity( psk, identity, max_identity_len );
	if ( length < 0 ) {
		coap_log( LOG_WARNING, "cannot set psk_identity -- buffer too small\n" );
		return 0;
	}

	length = coap_psk_set_key( psk, buf, max_len );
	if ( length < 0 ) {
		coap_log( LOG_WARNING, "cannot set psk -- buffer too small\n" );
		return 0;
	}

	return (unsigned)length;
}

static unsigned coap_dtls_psk_server_callback( SSL *ssl, const char *identity, unsigned char *buf, unsigned max_len ) {
	BIO *rbio = SSL_get_rbio( ssl );
	coap_ssl_data *data = (coap_ssl_data*)rbio->ptr;
	coap_context_t *coap_context = data->local_interface->context;
	coap_keystore_item_t *psk;
	ssize_t length = 0;

	if ( !coap_context->keystore )
		return 0;

	psk = coap_keystore_find_psk( coap_context->keystore, NULL, 0, identity, strlen( identity ), data->peer );
	if ( !psk ) {
		coap_log( LOG_WARNING, "PSK for unknown id requested, exiting\n" );
		return 0;
	}

	length = coap_psk_set_key( psk, buf, max_len );
	if ( length < 0 ) {
		coap_log( LOG_WARNING, "cannot set psk -- buffer too small\n" );
		return 0;
	}

	return (unsigned)length;
}

static void coap_dtls_info_callback( const SSL *ssl, int where, int ret ) {
	BIO *rbio = SSL_get_rbio( ssl );
	coap_dtls_session_t *session = (coap_dtls_session_t *)SSL_get_app_data( ssl );
	coap_context_t *coap_context = ( (coap_ssl_data*)rbio->ptr )->local_interface->context;
	const char *str;
	int w = where &~ SSL_ST_MASK;

	if ( w & SSL_ST_CONNECT )
		str = "SSL_connect";
	else if ( w & SSL_ST_ACCEPT )
		str = "SSL_accept";
	else
		str = "undefined";

	if ( where & SSL_CB_LOOP ) {
		if ( dtls_log_level <= LOG_INFO )
			coap_log( LOG_INFO, "%s:%s\n", str, SSL_state_string_long( ssl ) );
	} else if ( where & SSL_CB_ALERT ) {
		str = ( where & SSL_CB_READ ) ? "read" : "write";
		if ( dtls_log_level <= LOG_WARNING )
			coap_log( LOG_WARNING, "SSL3 alert %s:%s:%s\n", str, SSL_alert_type_string_long( ret ), SSL_alert_desc_string_long( ret ) );
	} else if ( where & SSL_CB_EXIT ) {
		if ( ret == 0 ) {
			if ( dtls_log_level <= LOG_WARNING ) {
				long e;
				coap_log( LOG_WARNING, "%s:failed in %s\n", str, SSL_state_string_long( ssl ) );
				while ( ( e = ERR_get_error() ) )
					coap_log( LOG_WARNING, "  %s at %s:%s\n", ERR_reason_error_string( e ), ERR_lib_error_string( e ), ERR_func_error_string( e ) );
			}
		} else if ( ret < 0 ) {
			if ( dtls_log_level <= LOG_WARNING ) {
				int err = SSL_get_error( ssl, ret );
				if ( err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE && err != SSL_ERROR_WANT_CONNECT && err != SSL_ERROR_WANT_ACCEPT && err != SSL_ERROR_WANT_X509_LOOKUP ) {
					long e;
					coap_log( LOG_WARNING, "%s:error in %s\n", str, SSL_state_string_long( ssl ) );
					while ( ( e = ERR_get_error() ) )
						coap_log( LOG_WARNING, "  %s at %s:%s\n", ERR_reason_error_string( e ), ERR_lib_error_string( e ), ERR_func_error_string( e ) );
				}
			}
		}
	}

	/* Stop all transactions that are affected from a fatal error condition. */
	
	if ( ( where & SSL_CB_ALERT ) != 0 && ( ret >> 8 ) == SSL3_AL_FATAL && session ) {
		struct queue_t *item;
		LL_FOREACH( session->sendqueue, item ) {
			coap_queue_t *node = NULL;
			coap_remove_from_queue( &coap_context->sendqueue, item->id, &node );
			coap_delete_node( node );
		}
	}

	if ( where == SSL_CB_HANDSHAKE_START && ssl->state == SSL_ST_RENEGOTIATE )
		coap_handle_event( coap_context, COAP_EVENT_DTLS_RENEGOTIATE, session );
}

static int ssl_library_loaded = 0;

struct coap_dtls_context_t *coap_dtls_new_context( struct coap_context_t *coap_context ) {
	struct coap_dtls_context_t *context;

	if ( !ssl_library_loaded ) {
		SSL_load_error_strings();
		SSL_library_init();
		ssl_library_loaded = 1;
	}

	context = ( struct coap_dtls_context_t * )coap_malloc( sizeof( struct coap_dtls_context_t ) );
	if ( context ) {
		memset( context, 0, sizeof( struct coap_dtls_context_t ) );
		context->ctx = SSL_CTX_new( DTLSv1_method() );
		if ( !context->ctx )
			goto error;
		SSL_CTX_set_read_ahead( context->ctx, 1 );
		/*SSL_CTX_set_verify( context->ctx, SSL_VERIFY_PEER, coap_dtls_verify_cert );*/
		SSL_CTX_set_cookie_generate_cb( context->ctx, coap_dtls_generate_cookie );
		SSL_CTX_set_cookie_verify_cb( context->ctx, coap_dtls_verify_cookie );
		SSL_CTX_set_info_callback( context->ctx, coap_dtls_info_callback );
		SSL_CTX_set_psk_client_callback( context->ctx, coap_dtls_psk_client_callback );
		SSL_CTX_set_psk_server_callback( context->ctx, coap_dtls_psk_server_callback );
		SSL_CTX_use_psk_identity_hint( context->ctx, "" );
		context->bio = BIO_new( &methods_coap );
		if ( !context->bio )
			goto error;
		context->ssl = SSL_new( context->ctx );
		if ( !context->ssl )
			goto error;
		SSL_set_bio( context->ssl, context->bio, context->bio );
		SSL_set_app_data( context->ssl, NULL );
		SSL_set_options( context->ssl, SSL_OP_COOKIE_EXCHANGE );
	}

	return context;

error:
	coap_dtls_free_context( context );
	return NULL;
}

void coap_dtls_free_context( struct coap_dtls_context_t *dtls_context ) {
	while ( dtls_context->sessions ) {
		if ( !( SSL_get_shutdown( dtls_context->sessions->ssl ) & SSL_SENT_SHUTDOWN ) )
			SSL_shutdown( dtls_context->sessions->ssl );
		coap_dtls_free_session( dtls_context, dtls_context->sessions );
	}
	if ( dtls_context->ssl )
		SSL_free( dtls_context->ssl );
	else if ( dtls_context->bio )
		BIO_free_all( dtls_context->bio );
	if ( dtls_context->ctx )
		SSL_CTX_free( dtls_context->ctx );
	coap_free( dtls_context );
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

struct coap_dtls_session_t *coap_dtls_new_session( coap_dtls_context_t *context, const coap_endpoint_t *local_interface, const coap_address_t *remote ) {
	struct coap_dtls_session_t *session;
	const size_t need = sizeof( struct coap_dtls_session_t );
	BIO *nbio = NULL;
	SSL *nssl = NULL;
	coap_ssl_data *data;

	session = coap_malloc_type( COAP_DTLS_SESSION, need );
	if ( !session )
		goto error;
	memset( session, 0, need );

	nbio = BIO_new( &methods_coap );
	if ( !nbio )
		goto error;
	nssl = SSL_new( context->ctx );
	if ( !nssl )
		goto error;
	SSL_set_bio( nssl, nbio, nbio );
	SSL_set_app_data( nssl, NULL );
	SSL_set_options( nssl, SSL_OP_COOKIE_EXCHANGE );
	session->bio = context->bio;
	session->ssl = context->ssl;
	context->ssl = nssl;
	context->bio = nbio;
	nssl = NULL;
	SSL_set_app_data( session->ssl, session );

	data = (coap_ssl_data*)session->bio->ptr;
	data->local_interface = local_interface;
	COAP_COPY_ADDRESS( &session->remote, remote );
	data->peer = &session->remote;

	LL_PREPEND( context->sessions, session );
	return session;

error:
	if ( session )
		coap_dtls_free_session( context, session );
	if ( nssl ) {
		SSL_free( nssl );
		nbio = NULL;
	}
	if ( nbio )
		BIO_free_all( nbio );
	return NULL;
}

void coap_dtls_free_session( coap_dtls_context_t *dtls_context, coap_dtls_session_t *session ) {
	if ( session ) {
		struct queue_t *item, *tmp;

		LL_DELETE( dtls_context->sessions, session );
		LL_FOREACH_SAFE( session->sendqueue, item, tmp ) {
			coap_free( item );
		}
		if ( session->ssl )
			SSL_free( session->ssl );
		else if ( session->bio )
			BIO_free_all( session->bio );
		coap_free_type( COAP_DTLS_SESSION, session );
	}
}

static coap_dtls_session_t *coap_dtls_find_session( coap_dtls_context_t *dtls_context,const coap_endpoint_t *local_interface,const coap_address_t *dst ) {
	struct coap_dtls_session_t *session = NULL;

	LL_FOREACH( dtls_context->sessions, session ) {
		const coap_ssl_data *data = (const coap_ssl_data*)session->bio->ptr;
		if ( data->local_interface->handle.fd == local_interface->handle.fd && coap_address_equals( &session->remote, dst ) )
			return session;
	}

	return session;
}

static int flush_data( struct coap_dtls_context_t *context, struct coap_dtls_session_t *session ) {
	struct queue_t *item, *tmp;
	int ok = 0;
	int res;

	LL_FOREACH_SAFE( session->sendqueue, item, tmp ) {
		res = SSL_write( session->ssl, item->data, (int)item->data_length );
		if ( res <= 0 ) {
			int err = SSL_get_error( session->ssl, res );
			if ( err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE )
				return ok;
		} else if ( res == (int)item->data_length ) {
			ok = 1;
		}
		LL_DELETE( session->sendqueue, item );
		coap_free( item );
	}

	return ok;
}

struct coap_dtls_session_t *coap_dtls_get_session( struct coap_context_t *coap_context, const coap_endpoint_t *local_interface, const coap_address_t *dst ) {
	coap_dtls_session_t *session;

	assert( coap_context && coap_context->dtls_context );

	/* reuse existing session if available, otherwise create new client session */
	session = coap_dtls_find_session( coap_context->dtls_context, local_interface, dst );

	if ( !session ) {
		int r;
		session = coap_dtls_new_session( coap_context->dtls_context, local_interface, dst );
		if ( session == NULL ) {
			coap_log( LOG_WARNING, "cannot create session object\n" );
			return NULL;
		}

		/* The peer connection does not yet exist. */
		r = SSL_connect( session->ssl );
		if ( r == -1 ) {
			int ret = SSL_get_error( session->ssl, r );
			if ( ret != SSL_ERROR_WANT_READ && ret != SSL_ERROR_WANT_WRITE )
				r = 0;
		}
		if ( r == 0 ) {
			coap_dtls_free_session( coap_context->dtls_context, session );
			session = NULL;
		} else if ( r == 1 ) {
			flush_data( coap_context->dtls_context, session );
		}
	}

	return session;
}

int coap_dtls_send( struct coap_context_t *coap_context, struct coap_dtls_session_t *session, const coap_pdu_t *pdu ) {
	int res = -2;

	assert( coap_context && coap_context->dtls_context );

	res = SSL_write( session->ssl, pdu->hdr, pdu->length );

	if ( res <= 0 ) {
		int err = SSL_get_error( session->ssl, res );
		if ( err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE ) {
			coap_tid_t id;
			coap_transaction_id( &session->remote, pdu, &id );
			res = 0;
			if ( !push_data_item( session, id, (const uint8_t *)pdu->hdr, pdu->length ) ) {
				coap_log( LOG_DEBUG, "cannot store %u bytes for deferred transmission\n", pdu->length );
				res = -2;
			}
		} else {
			coap_log( LOG_WARNING, "coap_dtls_send: cannot send PDU\n" );
			if ( err == SSL_ERROR_ZERO_RETURN )
				coap_handle_event( coap_context, COAP_EVENT_DTLS_CLOSED, session );
			else
				coap_handle_event( coap_context, COAP_EVENT_DTLS_ERROR, session );
			coap_dtls_free_session( coap_context->dtls_context, session );
			res = -1;
		}
	}

	return res;
}

int coap_dtls_handle_message( struct coap_context_t *coap_context, const coap_endpoint_t *local_interface, const coap_address_t *dst, const unsigned char *data, size_t data_len ) {
	coap_dtls_session_t *session;
	coap_ssl_data *ssl_data;
	int new_session = 0;
	int r = 0, err;

	session = coap_dtls_find_session( coap_context->dtls_context, local_interface, dst );

	if ( !session ) {
		ssl_data = (coap_ssl_data*)coap_context->dtls_context->bio->ptr;
		ssl_data->local_interface = local_interface;
		ssl_data->peer = dst;
		ssl_data->pdu = data;
		ssl_data->pdu_len = (unsigned)data_len;
		r = DTLSv1_listen( coap_context->dtls_context->ssl, NULL );
		if ( r <= 0 ) {
			err = SSL_get_error( coap_context->dtls_context->ssl, r );
			if ( err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE ) {
				/* Got a ClientHello, sent-out a VerifyRequest */
				r = 0;
			}
		} else {
			/* Got a valid answer to a VerifyRequest */
			session = coap_dtls_new_session( coap_context->dtls_context, local_interface, dst );
			if ( session == NULL ) {
				coap_log( LOG_WARNING, "cannot allocate session, drop packet\n" );
				return -1;
			}
			new_session = 1;
			r = SSL_accept( session->ssl );
			if ( r <= 0 ) {
				err = SSL_get_error( session->ssl, r );
				if ( err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE )
					r = 0;
				else
					r = -1;
			}
		}
	} else {
		int prev_state = session->ssl->state;
		uint8_t pdu[COAP_MAX_PDU_SIZE];
		ssl_data = (coap_ssl_data*)session->bio->ptr;
		ssl_data->pdu = data;
		ssl_data->pdu_len = (unsigned)data_len;

		r = SSL_read( session->ssl, pdu, COAP_MAX_PDU_SIZE );
		if ( r > 0 ) {
			return coap_handle_message( coap_context, local_interface, dst, pdu, r );
		} else {
			err = SSL_get_error( session->ssl, r );
			if ( err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE ) {
				if ( ( prev_state & SSL_ST_CONNECT ) && session->ssl->state == SSL_ST_OK ) {
					/* Client-side connect complete */
					flush_data( coap_context->dtls_context, session );
					coap_handle_event( coap_context, COAP_EVENT_DTLS_CONNECTED, session );
				} else if ( ( prev_state & SSL_ST_ACCEPT ) && session->ssl->state == SSL_ST_OK ) {
					/* Server-side connect complete */
					coap_handle_event( coap_context, COAP_EVENT_DTLS_CONNECTED, session );
				}
				r = 0;
			} else if ( err == SSL_ERROR_ZERO_RETURN ) {
				/* Got a close notify alert from the remote side */
				SSL_shutdown( session->ssl );
				coap_handle_event( coap_context, COAP_EVENT_DTLS_CLOSED, session );
				coap_dtls_free_session( coap_context->dtls_context, session );
				session = NULL;
				r = 0;
			} else {
				coap_handle_event( coap_context, COAP_EVENT_DTLS_ERROR, session );
				r = -1;
			}
		}
	}
	
	if ( r < 0 && session )
		coap_dtls_free_session( coap_context->dtls_context, session );

	return r;
}

#else /* HAVE_LIBTINYDTLS || HAVE_OPENSSL */

int
coap_dtls_is_supported(void) {
  return 0;
}

void
coap_dtls_set_log_level(int level) {
}

int
coap_dtls_get_log_level(void) {
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
