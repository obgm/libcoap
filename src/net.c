/* net.c -- CoAP network interface
 *
 * Copyright (C) 2010--2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#include "coap_config.h"

#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#elif HAVE_SYS_UNISTD_H
#include <sys/unistd.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif

#ifdef WITH_LWIP
#include <lwip/pbuf.h>
#include <lwip/udp.h>
#include <lwip/timers.h>
#endif

#include "libcoap.h"
#include "coap_dtls.h"
#include "utlist.h"
#include "debug.h"
#include "mem.h"
#include "str.h"
#include "async.h"
#include "resource.h"
#include "option.h"
#include "encode.h"
#include "block.h"
#include "net.h"
#include "utlist.h"

 /**
  * @defgroup cc Rate Control
  * The transmission parameters for CoAP rate control ("Congestion
  * Control" in stream-oriented protocols) are defined in
  * https://tools.ietf.org/html/rfc7252#section-4.8
  * @{
  */

#ifndef COAP_DEFAULT_ACK_TIMEOUT
  /**
   * Number of seconds when to expect an ACK or a response to an
   * outstanding CON message.
   */
#define COAP_DEFAULT_ACK_TIMEOUT  2 /* see RFC 7252, Section 4.8 */
#endif

#ifndef COAP_DEFAULT_ACK_RANDOM_FACTOR
   /**
    * A factor that is used to randomize the wait time before a message
    * is retransmitted to prevent synchronization effects.
    */
#define COAP_DEFAULT_ACK_RANDOM_FACTOR  1.5 /* see RFC 7252, Section 4.8 */
#endif

#ifndef COAP_DEFAULT_MAX_RETRANSMIT
    /**
     * Number of message retransmissions before message sending is stopped
     */
#define COAP_DEFAULT_MAX_RETRANSMIT  4 /* see RFC 7252, Section 4.8 */
#endif

#ifndef COAP_DEFAULT_NSTART
     /**
      * The number of simultaneous outstanding interactions that a client
      * maintains to a given server.
      */
#define COAP_DEFAULT_NSTART 1 /* see RFC 7252, Section 4.8 */
#endif

      /** @} */

      /**
       * The number of bits for the fractional part of ACK_TIMEOUT and
       * ACK_RANDOM_FACTOR. Must be less or equal 8.
       */
#define FRAC_BITS 6

       /**
	* The maximum number of bits for fixed point integers that are used
	* for retransmission time calculation. Currently this must be @c 8.
	*/
#define MAX_BITS 8

#if FRAC_BITS > 8
#error FRAC_BITS must be less or equal 8
#endif

	/** creates a Qx.frac from fval */
#define Q(frac,fval) ((unsigned short)(((1 << (frac)) * (fval))))

/** creates a Qx.FRAC_BITS from COAP_DEFAULT_ACK_RANDOM_FACTOR */
#define ACK_RANDOM_FACTOR					\
  Q(FRAC_BITS, COAP_DEFAULT_ACK_RANDOM_FACTOR)

/** creates a Qx.FRAC_BITS from COAP_DEFAULT_ACK_TIMEOUT */
#define ACK_TIMEOUT Q(FRAC_BITS, COAP_DEFAULT_ACK_TIMEOUT)

#if !defined(WITH_LWIP) && !defined(WITH_CONTIKI)

COAP_STATIC_INLINE coap_queue_t *
coap_malloc_node(void) {
  return (coap_queue_t *)coap_malloc_type(COAP_NODE, sizeof(coap_queue_t));
}

COAP_STATIC_INLINE void
coap_free_node(coap_queue_t *node) {
  coap_free_type(COAP_NODE, node);
}
#endif /* !defined(WITH_LWIP) && !defined(WITH_CONTIKI) */

void coap_free_endpoint(coap_endpoint_t *ep);

#ifdef WITH_LWIP

#include <lwip/memp.h>

static void coap_retransmittimer_execute(void *arg);
static void coap_retransmittimer_restart(coap_context_t *ctx);

COAP_STATIC_INLINE coap_queue_t *
coap_malloc_node() {
  return (coap_queue_t *)memp_malloc(MEMP_COAP_NODE);
}

COAP_STATIC_INLINE void
coap_free_node(coap_queue_t *node) {
  memp_free(MEMP_COAP_NODE, node);
}

#endif /* WITH_LWIP */
#ifdef WITH_CONTIKI
# ifndef DEBUG
#  define DEBUG DEBUG_PRINT
# endif /* DEBUG */

#include "mem.h"
#include "net/ip/uip-debug.h"

#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_UDP_BUF  ((struct uip_udp_hdr *)&uip_buf[UIP_LLIPH_LEN])

void coap_resources_init();

unsigned char initialized = 0;
coap_context_t the_coap_context;

PROCESS(coap_retransmit_process, "message retransmit process");

COAP_STATIC_INLINE coap_queue_t *
coap_malloc_node() {
  return (coap_queue_t *)coap_malloc_type(COAP_NODE, 0);
}

COAP_STATIC_INLINE void
coap_free_node(coap_queue_t *node) {
  coap_free_type(COAP_NODE, node);
}
#endif /* WITH_CONTIKI */

unsigned int
coap_adjust_basetime(coap_context_t *ctx, coap_tick_t now) {
  unsigned int result = 0;
  coap_tick_diff_t delta = now - ctx->sendqueue_basetime;

  if (ctx->sendqueue) {
    /* delta < 0 means that the new time stamp is before the old. */
    if (delta <= 0) {
      ctx->sendqueue->t -= delta;
    } else {
      /* This case is more complex: The time must be advanced forward,
       * thus possibly leading to timed out elements at the queue's
       * start. For every element that has timed out, its relative
       * time is set to zero and the result counter is increased. */

      coap_queue_t *q = ctx->sendqueue;
      coap_tick_t t = 0;
      while (q && (t + q->t < (coap_tick_t)delta)) {
	t += q->t;
	q->t = 0;
	result++;
	q = q->next;
      }

      /* finally adjust the first element that has not expired */
      if (q) {
	q->t = (coap_tick_t)delta - t;
      }
    }
  }

  /* adjust basetime */
  ctx->sendqueue_basetime += delta;

  return result;
}

int
coap_insert_node(coap_queue_t **queue, coap_queue_t *node) {
  coap_queue_t *p, *q;
  if (!queue || !node)
    return 0;

  /* set queue head if empty */
  if (!*queue) {
    *queue = node;
    return 1;
  }

  /* replace queue head if PDU's time is less than head's time */
  q = *queue;
  if (node->t < q->t) {
    node->next = q;
    *queue = node;
    q->t -= node->t;		/* make q->t relative to node->t */
    return 1;
  }

  /* search for right place to insert */
  do {
    node->t -= q->t;		/* make node-> relative to q->t */
    p = q;
    q = q->next;
  } while (q && q->t <= node->t);

  /* insert new item */
  if (q) {
    q->t -= node->t;		/* make q->t relative to node->t */
  }
  node->next = q;
  p->next = node;
  return 1;
}

int
coap_delete_node(coap_queue_t *node) {
  if (!node)
    return 0;

  coap_delete_pdu(node->pdu);
  if ( node->session )
    coap_session_release(node->session);
  coap_free_node(node);

  return 1;
}

void
coap_delete_all(coap_queue_t *queue) {
  if (!queue)
    return;

  coap_delete_all(queue->next);
  coap_delete_node(queue);
}

coap_queue_t *
coap_new_node(void) {
  coap_queue_t *node;
  node = coap_malloc_node();

  if (!node) {
#ifndef NDEBUG
    coap_log(LOG_WARNING, "coap_new_node: malloc\n");
#endif
    return NULL;
  }

  memset(node, 0, sizeof(*node));
  return node;
}

coap_queue_t *
coap_peek_next(coap_context_t *context) {
  if (!context || !context->sendqueue)
    return NULL;

  return context->sendqueue;
}

coap_queue_t *
coap_pop_next(coap_context_t *context) {
  coap_queue_t *next;

  if (!context || !context->sendqueue)
    return NULL;

  next = context->sendqueue;
  context->sendqueue = context->sendqueue->next;
  if (context->sendqueue) {
    context->sendqueue->t += next->t;
  }
  next->next = NULL;
  return next;
}

#ifdef COAP_DEFAULT_WKC_HASHKEY
/** Checks if @p Key is equal to the pre-defined hash key for.well-known/core. */
#define is_wkc(Key)							\
  (memcmp((Key), COAP_DEFAULT_WKC_HASHKEY, sizeof(coap_key_t)) == 0)
#else
/* Implements a singleton to store a hash key for the .wellknown/core
 * resources. */
int
is_wkc(coap_key_t k) {
  static coap_key_t wkc;
  static unsigned char _initialized = 0;
  if (!_initialized) {
    _initialized = coap_hash_path((unsigned char *)COAP_DEFAULT_URI_WELLKNOWN,
      sizeof(COAP_DEFAULT_URI_WELLKNOWN) - 1, wkc);
  }
  return memcmp(k, wkc, sizeof(coap_key_t)) == 0;
}
#endif

static size_t
coap_get_session_client_psk(
  const coap_session_t *session,
  const uint8_t *hint, size_t hint_len,
  uint8_t *identity, size_t *identity_len, size_t max_identity_len,
  uint8_t *psk, size_t max_psk_len
) {
  (void)hint;
  (void)hint_len;
  if (session->psk_identity && session->psk_identity_len > 0 && session->psk_key && session->psk_key_len > 0) {
    if (session->psk_identity_len <= max_identity_len && session->psk_key_len <= max_psk_len) {
      memcpy(identity, session->psk_identity, session->psk_identity_len);
      memcpy(psk, session->psk_key, session->psk_key_len);
      *identity_len = session->psk_identity_len;
      return session->psk_key_len;
    }
  } else if (session->context && session->context->psk_key && session->context->psk_key_len > 0) {
    if (session->context->psk_key_len <= max_psk_len) {
      *identity_len = 0;
      memcpy(psk, session->context->psk_key, session->context->psk_key_len);
      return session->context->psk_key_len;
    }
  }
  *identity_len = 0;
  return 0;
}

static size_t
coap_get_context_server_psk(
  const coap_session_t *session,
  const uint8_t *identity, size_t identity_len,
  uint8_t *psk, size_t max_psk_len
) {
  (void)identity;
  (void)identity_len;
  const coap_context_t *ctx = session->context;
  if (ctx && ctx->psk_key && ctx->psk_key_len > 0 && ctx->psk_key_len <= max_psk_len) {
    memcpy(psk, ctx->psk_key, ctx->psk_key_len);
    return ctx->psk_key_len;
  }
  return 0;
}

static size_t
coap_get_context_server_hint(
  const coap_session_t *session,
  uint8_t *hint, size_t max_hint_len
) {
  const coap_context_t *ctx = session->context;
  if (ctx && ctx->psk_hint && ctx->psk_hint_len > 0 && ctx->psk_hint_len <= max_hint_len) {
    memcpy(hint, ctx->psk_hint, ctx->psk_hint_len);
    return ctx->psk_hint_len;
  }
  return 0;
}

void coap_context_set_psk(coap_context_t *ctx,
  const char *hint,
  const uint8_t *key, size_t key_len
) {

  if (ctx->psk_hint)
    coap_free(ctx->psk_hint);
  ctx->psk_hint = NULL;
  ctx->psk_hint_len = 0;

  if (hint) {
    size_t hint_len = strlen(hint);
    ctx->psk_hint = (uint8_t*)coap_malloc(hint_len);
    if (ctx->psk_hint) {
      memcpy(ctx->psk_hint, hint, hint_len);
      ctx->psk_hint_len = hint_len;
    } else {
      coap_log(LOG_ERR, "No memory to store PSK hint");
    }
  }

  if (ctx->psk_key)
    coap_free(ctx->psk_key);
  ctx->psk_key = NULL;
  ctx->psk_key_len = 0;

  if (key && key_len > 0) {
    ctx->psk_key = (uint8_t *)coap_malloc(key_len);
    if (ctx->psk_key) {
      memcpy(ctx->psk_key, key, key_len);
      ctx->psk_key_len = key_len;
    } else {
      coap_log(LOG_ERR, "No memory to store PSK key");
    }
  }
}

coap_context_t *
coap_new_context(
  const coap_address_t *listen_addr) {
  coap_context_t *c;

#ifdef WITH_CONTIKI
  if (initialized)
    return NULL;
#endif /* WITH_CONTIKI */

  coap_startup();

#ifndef WITH_CONTIKI
  c = coap_malloc_type(COAP_CONTEXT, sizeof(coap_context_t));
#endif /* not WITH_CONTIKI */

#ifndef WITH_CONTIKI
  if (!c) {
#ifndef NDEBUG
    coap_log(LOG_EMERG, "coap_init: malloc:\n");
#endif
    return NULL;
  }
#endif /* not WITH_CONTIKI */
#ifdef WITH_CONTIKI
  coap_resources_init();
  coap_memory_init();

  c = &the_coap_context;
  initialized = 1;
#endif /* WITH_CONTIKI */

  memset(c, 0, sizeof(coap_context_t));

  if (coap_dtls_is_supported()) {
    c->dtls_context = coap_dtls_new_context(c);
    if (!c->dtls_context) {
      coap_log(LOG_EMERG, "coap_init: no DTLS context available\n");
      coap_free_context(c);
      return NULL;
    }
  }

  /* initialize message id */
  prng((unsigned char *)&c->message_id, sizeof(unsigned short));

  if (listen_addr) {
    coap_endpoint_t *endpoint = coap_new_endpoint(c, listen_addr, COAP_PROTO_UDP);
    if (endpoint == NULL) {
      goto onerror;
    }
  }

#if !defined(WITH_LWIP)
  c->network_send = coap_network_send;
  c->network_read = coap_network_read;
#endif

  c->get_client_psk = coap_get_session_client_psk;
  c->get_server_psk = coap_get_context_server_psk;
  c->get_server_hint = coap_get_context_server_hint;

#ifdef WITH_CONTIKI
  process_start(&coap_retransmit_process, (char *)c);

  PROCESS_CONTEXT_BEGIN(&coap_retransmit_process);
#ifndef WITHOUT_OBSERVE
  etimer_set(&c->notify_timer, COAP_RESOURCE_CHECK_TIME * COAP_TICKS_PER_SECOND);
#endif /* WITHOUT_OBSERVE */
  /* the retransmit timer must be initialized to some large value */
  etimer_set(&the_coap_context.retransmit_timer, 0xFFFF);
  PROCESS_CONTEXT_END(&coap_retransmit_process);
#endif /* WITH_CONTIKI */

  return c;

onerror:
  coap_free_type(COAP_CONTEXT, c);
  return NULL;
}

void
coap_set_app_data(coap_context_t *ctx, void *app_data) {
  assert(ctx);
  ctx->app = app_data;
}

void *
coap_get_app_data(coap_context_t *ctx) {
  assert(ctx);
  return ctx->app;
}

void
coap_free_context(coap_context_t *context) {
  coap_endpoint_t *ep, *tmp;

  if (!context)
    return;

  coap_delete_all(context->sendqueue);

#ifdef WITH_LWIP
  context->sendqueue = NULL;
  coap_retransmittimer_restart(context);
#endif

  coap_delete_all_resources(context);

  if (context->dtls_context)
    coap_dtls_free_context(context->dtls_context);

  LL_FOREACH_SAFE(context->endpoint, ep, tmp) {
    coap_free_endpoint(ep);
  }

  if (context->psk_hint)
    coap_free(context->psk_hint);

  if (context->psk_key)
    coap_free(context->psk_key);

#ifndef WITH_CONTIKI
  coap_free_type(COAP_CONTEXT, context);
#endif/* not WITH_CONTIKI */
#ifdef WITH_CONTIKI
  memset(&the_coap_context, 0, sizeof(coap_context_t));
  initialized = 0;
#endif /* WITH_CONTIKI */
}

int
coap_option_check_critical(coap_context_t *ctx,
  coap_pdu_t *pdu,
  coap_opt_filter_t unknown) {

  coap_opt_iterator_t opt_iter;
  int ok = 1;

  coap_option_iterator_init(pdu, &opt_iter, COAP_OPT_ALL);

  while (coap_option_next(&opt_iter)) {

    /* The following condition makes use of the fact that
     * coap_option_getb() returns -1 if type exceeds the bit-vector
     * filter. As the vector is supposed to be large enough to hold
     * the largest known option, we know that everything beyond is
     * bad.
     */
    if (opt_iter.type & 0x01) {
      /* first check the built-in critical options */
      switch (opt_iter.type) {
      case COAP_OPTION_IF_MATCH:
      case COAP_OPTION_URI_HOST:
      case COAP_OPTION_IF_NONE_MATCH:
      case COAP_OPTION_URI_PORT:
      case COAP_OPTION_URI_PATH:
      case COAP_OPTION_URI_QUERY:
      case COAP_OPTION_ACCEPT:
      case COAP_OPTION_PROXY_URI:
      case COAP_OPTION_PROXY_SCHEME:
      case COAP_OPTION_BLOCK2:
      case COAP_OPTION_BLOCK1:
	break;
      default:
	if (coap_option_filter_get(ctx->known_options, opt_iter.type) <= 0) {
	  debug("unknown critical option %d\n", opt_iter.type);
	  ok = 0;

	  /* When opt_iter.type is beyond our known option range,
	   * coap_option_filter_set() will return -1 and we are safe to leave
	   * this loop. */
	  if (coap_option_filter_set(unknown, opt_iter.type) == -1) {
	    break;
	  }
	}
      }
    }
  }

  return ok;
}

coap_tid_t
coap_send_ack(coap_session_t *session, coap_pdu_t *request) {
  coap_pdu_t *response;
  coap_tid_t result = COAP_INVALID_TID;

  if (request && request->hdr->type == COAP_MESSAGE_CON) {
    response = coap_pdu_init(COAP_MESSAGE_ACK, 0, request->hdr->id,
      sizeof(coap_pdu_t));
    if (response)
      result = coap_send(session, response);
  }
  return result;
}

static ssize_t
coap_send_pdu(coap_session_t *session, coap_pdu_t *pdu, coap_queue_t *node) {
  ssize_t bytes_written;

#ifdef LWIP

  coap_socket_t *sock = &session->sock;
  if (sock->flags == COAP_SOCKET_EMPTY) {
    assert(session->endpoint != NULL);
    sock = &session->endpoint->sock;
  }
  bytes_written = coap_socket_send_pdu(sock, session, pdu);
  coap_ticks(&session->last_rx_tx);

#else

  /* Do not send error responses for requests that were received via
  * IP multicast.
  * FIXME: If No-Response option indicates interest, these responses
  *        must not be dropped. */
  if (coap_is_mcast(&session->local_addr) &&
    COAP_RESPONSE_CLASS(pdu->hdr->code) > 2) {
    return COAP_DROPPED_RESPONSE;
  }

  if (session->state == COAP_SESSION_STATE_NONE) {
    if (session->proto == COAP_PROTO_DTLS && !session->tls) {
      session->tls = coap_dtls_new_client_session(session);
      if (session->tls) {
	session->state = COAP_SESSION_STATE_HANDSHAKE;
	return coap_session_delay_pdu(session, pdu, node);
      }
    }
    return -1;
  }

  if (session->state != COAP_SESSION_STATE_ESTABLISHED)
    return coap_session_delay_pdu(session, pdu, node);

  /* Pass to DTLS module for sending if local_interface is for secure
   * communication. */
  if (session->proto == COAP_PROTO_DTLS)
    bytes_written = coap_dtls_send(session, (const uint8_t*)pdu->hdr, pdu->length);
  else
    bytes_written = coap_session_send(session, (const uint8_t*)pdu->hdr, pdu->length);

#endif /* WITH_LWIP */

  return bytes_written;
}

coap_tid_t
coap_send_error(coap_session_t *session,
  coap_pdu_t *request,
  unsigned char code,
  coap_opt_filter_t opts) {
  coap_pdu_t *response;
  coap_tid_t result = COAP_INVALID_TID;

  assert(request);
  assert(session);

  response = coap_new_error_response(request, code, opts);
  if (response)
    result = coap_send(session, response);

  return result;
}

coap_tid_t
coap_send_message_type(coap_session_t *session, coap_pdu_t *request, unsigned char type) {
  coap_pdu_t *response;
  coap_tid_t result = COAP_INVALID_TID;

  if (request) {
    response = coap_pdu_init(type, 0, request->hdr->id, sizeof(coap_pdu_t));
    if (response)
      result = coap_send(session, response);
  }
  return result;
}

/**
 * Calculates the initial timeout based on the global CoAP transmission
 * parameters ACK_TIMEOUT, ACK_RANDOM_FACTOR, and COAP_TICKS_PER_SECOND.
 * The calculation requires ACK_TIMEOUT and ACK_RANDOM_FACTOR to be in
 * Qx.FRAC_BITS fixed point notation, whereas the passed parameter @p r
 * is interpreted as the fractional part of a Q0.MAX_BITS random value.
 *
 * @param r  random value as fractional part of a Q0.MAX_BITS fixed point
 *           value
 * @return   COAP_TICKS_PER_SECOND * ACK_TIMEOUT * (1 + (ACK_RANDOM_FACTOR - 1) * r)
 */
unsigned int
calc_timeout(unsigned char r) {
  unsigned int result;

  /* The integer 1.0 as a Qx.FRAC_BITS */
#define FP1 Q(FRAC_BITS, 1)

  /* rounds val up and right shifts by frac positions */
#define SHR_FP(val,frac) (((val) + (1 << ((frac) - 1))) >> (frac))

  /* Inner term: multiply ACK_RANDOM_FACTOR by Q0.MAX_BITS[r] and
   * make the result a rounded Qx.FRAC_BITS */
  result = SHR_FP((ACK_RANDOM_FACTOR - FP1) * r, MAX_BITS);

  /* Add 1 to the inner term and multiply with ACK_TIMEOUT, then
   * make the result a rounded Qx.FRAC_BITS */
  result = SHR_FP(((result + FP1) * ACK_TIMEOUT), FRAC_BITS);

  /* Multiply with COAP_TICKS_PER_SECOND to yield system ticks
   * (yields a Qx.FRAC_BITS) and shift to get an integer */
  return SHR_FP((COAP_TICKS_PER_SECOND * result), FRAC_BITS);

#undef FP1
#undef SHR_FP
}

coap_tid_t
coap_wait_ack(coap_context_t *context, coap_session_t *session,
              coap_queue_t *node) {
  coap_tick_t now;

  node->session = coap_session_reference(session);

  /* Set timer for pdu retransmission. If this is the first element in
  * the retransmission queue, the base time is set to the current
  * time and the retransmission time is node->timeout. If there is
  * already an entry in the sendqueue, we must check if this node is
  * to be retransmitted earlier. Therefore, node->timeout is first
  * normalized to the base time and then inserted into the queue with
  * an adjusted relative time.
  */
  coap_ticks(&now);
  if (context->sendqueue == NULL) {
    node->t = node->timeout;
    context->sendqueue_basetime = now;
  } else {
    /* make node->t relative to context->sendqueue_basetime */
    node->t = (now - context->sendqueue_basetime) + node->timeout;
  }

  coap_insert_node(&context->sendqueue, node);

#ifdef WITH_LWIP
  if (node == context->sendqueue) /* don't bother with timer stuff if there are earlier retransmits */
    coap_retransmittimer_restart(context);
#endif

#ifdef WITH_CONTIKI
  {			    /* (re-)initialize retransmission timer */
    coap_queue_t *nextpdu;

    nextpdu = coap_peek_next(context);
    assert(nextpdu);		/* we have just inserted a node */

				/* must set timer within the context of the retransmit process */
    PROCESS_CONTEXT_BEGIN(&coap_retransmit_process);
    etimer_set(&context->retransmit_timer, nextpdu->t);
    PROCESS_CONTEXT_END(&coap_retransmit_process);
  }
#endif /* WITH_CONTIKI */

  debug("** %s tid=%d added to retransmit queue (%ums)\n",
    coap_session_str(node->session), node->id,
    (unsigned)(node->t * 1000 / COAP_TICKS_PER_SECOND));

  return node->id;
}

coap_tid_t
coap_send(coap_session_t *session, coap_pdu_t *pdu) {
  uint8_t r;
  ssize_t bytes_written = coap_send_pdu(session, pdu, NULL);

  if (bytes_written == COAP_PDU_DELAYED)
    return ntohs(pdu->hdr->id);

  if (bytes_written < 0) {
    coap_delete_pdu(pdu);
    return (coap_tid_t)bytes_written;
  }

  if (pdu->hdr->type != COAP_MESSAGE_CON) {
    coap_tid_t id = ntohs(pdu->hdr->id);
    coap_delete_pdu(pdu);
    return id;
  }

  coap_queue_t *node = coap_new_node();
  if (!node) {
    debug("coap_wait_ack: insufficient memory\n");
    return COAP_INVALID_TID;
  }

  node->id = ntohs(pdu->hdr->id);
  node->pdu = pdu;
  prng(&r, sizeof(r));
  /* add timeout in range [ACK_TIMEOUT...ACK_TIMEOUT * ACK_RANDOM_FACTOR] */
  node->timeout = calc_timeout(r);
  return coap_wait_ack(session->context, session, node);
}

coap_tid_t
coap_retransmit(coap_context_t *context, coap_queue_t *node) {
  if (!context || !node)
    return COAP_INVALID_TID;

  /* re-initialize timeout when maximum number of retransmissions are not reached yet */
  if (node->retransmit_cnt < COAP_DEFAULT_MAX_RETRANSMIT) {
    ssize_t bytes_written;
    coap_tick_t now;

    node->retransmit_cnt++;
    coap_ticks(&now);
    if (context->sendqueue == NULL) {
      node->t = node->timeout << node->retransmit_cnt;
      context->sendqueue_basetime = now;
    } else {
      /* make node->t relative to context->sendqueue_basetime */
      node->t = (now - context->sendqueue_basetime) + (node->timeout << node->retransmit_cnt);
    }
    coap_insert_node(&context->sendqueue, node);
#ifdef WITH_LWIP
    if (node == context->sendqueue) /* don't bother with timer stuff if there are earlier retransmits */
      coap_retransmittimer_restart(context);
#endif

    debug("** %s tid=%d: retransmission #%d\n",
      coap_session_str(node->session), node->id, node->retransmit_cnt);

    bytes_written = coap_send_pdu(node->session, node->pdu, node);

    if (bytes_written == COAP_PDU_DELAYED) {
      /* PDU was not retransmitted immediately because a new handshake is
	 in progress. node was moved to the send queue of the session. */
      return node->id;
    }

    if (bytes_written < 0)
      return (int)bytes_written;

    return node->id;
  }

  /* no more retransmissions, remove node from system */

#ifndef WITH_CONTIKI
  debug("** %s tid=%d: give up after %d attempts\n",
    coap_session_str(node->session), node->id, node->retransmit_cnt);
#endif

#ifndef WITHOUT_OBSERVE
  /* Check if subscriptions exist that should be canceled after
     COAP_MAX_NOTIFY_FAILURES */
  if (node->pdu->hdr->code >= 64) {
    str token = { 0, NULL };

    token.length = node->pdu->hdr->token_length;
    token.s = node->pdu->hdr->token;

    coap_handle_failed_notify(context, node->session, &token);
  }
#endif /* WITHOUT_OBSERVE */

  /* And finally delete the node */
  coap_delete_node(node);
  return COAP_INVALID_TID;
}

void coap_dispatch(coap_context_t *context, coap_queue_t *rcvd);

#ifdef WITH_LWIP
/* WITH_LWIP, this is handled by coap_recv in a different way */
int
coap_read(coap_context_t *ctx) {
  return -1;
}
#else /* WITH_LWIP */

static int
coap_handle_message_for_proto(coap_context_t *ctx, coap_session_t *session, coap_packet_t *packet) {
  uint8_t *data;
  size_t data_len;
  int result = -1;

  coap_packet_get_memmapped(packet, &data, &data_len);

  if (session->proto == COAP_PROTO_DTLS) {
    if (session->type == COAP_SESSION_TYPE_HELLO)
      result = coap_dtls_hello(session, data, data_len);
    else if (session->tls)
      result = coap_dtls_receive(session, data, data_len);
  } else if (session->proto == COAP_PROTO_UDP) {
    result = coap_handle_message(ctx, session, data, data_len);
  }

  return result;
}

static int
coap_read_session(coap_context_t *ctx, coap_session_t *session, coap_tick_t now) {
  ssize_t bytes_read = -1;
  int result = -1;		/* the value to be returned */
#ifdef WITH_CONTIKI
  coap_packet_t *packet = coap_malloc_packet();
#else /* WITH_CONTIKI */
  coap_packet_t s_packet;
  coap_packet_t *packet = &s_packet;
#endif /* WITH_CONTIKI */

  assert(session->sock.flags & COAP_SOCKET_CONNECTED);

  if (packet) {
    coap_address_copy(&packet->src, &session->remote_addr);
    coap_address_copy(&packet->dst, &session->local_addr);
    bytes_read = ctx->network_read(&session->sock, packet);
  }

  if (bytes_read < 0) {
    if (bytes_read == -2)
      coap_session_reset(session);
    else
      warn("*  %s: read error\n", coap_session_str(session));
  } else if (bytes_read > 0) {
    debug("*  %s: received %zd bytes\n", coap_session_str(session), bytes_read);
    session->last_rx_tx = now;
    coap_packet_set_addr(packet, &session->remote_addr, &session->local_addr);
    result = coap_handle_message_for_proto(ctx, session, packet);
  }

#ifdef WITH_CONTIKI
  if ( packet )
    coap_free_packet(packet);
#endif

  return result;
}

static int
coap_read_endpoint(coap_context_t *ctx, coap_endpoint_t *endpoint, coap_tick_t now) {
  ssize_t bytes_read = -1;
  int result = -1;		/* the value to be returned */
#ifdef WITH_CONTIKI
  coap_packet_t *packet = coap_malloc_packet();
#else /* WITH_CONTIKI */
  coap_packet_t s_packet;
  coap_packet_t *packet = &s_packet;
#endif /* WITH_CONTIKI */

  assert(endpoint->sock.flags&COAP_SOCKET_BOUND);

  if (packet) {
    coap_address_init(&packet->src);
    coap_address_copy(&packet->dst, &endpoint->bind_addr);
    bytes_read = ctx->network_read(&endpoint->sock, packet);
  }

  if (bytes_read < 0) {
    warn("*  %s: read failed\n", coap_endpoint_str(endpoint));
  } else if (bytes_read > 0) {
    coap_session_t *session = coap_endpoint_get_session(endpoint, packet, now);
    if (session) {
      debug("*  %s: received %zd bytes\n", coap_session_str(session), bytes_read);
      result = coap_handle_message_for_proto(ctx, session, packet);
      if (endpoint->proto == COAP_PROTO_DTLS && session->type == COAP_SESSION_TYPE_HELLO && result == 1)
	coap_endpoint_new_dtls_session(endpoint, packet, now);
    }
  }

#ifdef WITH_CONTIKI
  if (packet)
    coap_free_packet(packet);
#endif

  return result;
}

void
coap_read(coap_context_t *ctx, coap_tick_t now) {
  coap_endpoint_t *ep, *tmp;
  coap_session_t *s, *tmp_s;

  LL_FOREACH_SAFE(ctx->endpoint, ep, tmp) {
    if ((ep->sock.flags & COAP_SOCKET_HAS_DATA) != 0)
      coap_read_endpoint(ctx, ep, now);
  }

  LL_FOREACH_SAFE(ctx->sessions, s, tmp_s) {
    if ((s->sock.flags & COAP_SOCKET_HAS_DATA) != 0)
      coap_read_session(ctx, s, now);
  }

}
#endif /* not WITH_LWIP */

int
coap_handle_message(coap_context_t *ctx, coap_session_t *session,
  uint8_t *msg, size_t msg_len) {
  coap_queue_t *node;

  /* the negated result code */
  enum result_t { RESULT_OK, RESULT_ERR_EARLY, RESULT_ERR };
  int result = RESULT_ERR_EARLY;

  if (msg_len < sizeof(coap_hdr_t)) {
    debug("coap_handle_message: discarded invalid frame\n");
    goto error_early;
  }

  /* check version identifier */
  if (((*msg >> 6) & 0x03) != COAP_DEFAULT_VERSION) {
    debug("coap_handle_message: unknown protocol version %d\n", (*msg >> 6) & 0x03);
    goto error_early;
  }

  node = coap_new_node();
  if (!node) {
    goto error_early;
  }

  /* from this point, the result code indicates that */
  result = RESULT_ERR;

#ifdef WITH_LWIP
  node->pdu = coap_pdu_from_pbuf(coap_packet_extract_pbuf(packet));
#else
  node->pdu = coap_pdu_init(0, 0, 0, msg_len);
#endif
  if (!node->pdu) {
    goto error;
  }

  if (!coap_pdu_parse(msg, msg_len, node->pdu)) {
    warn("discard malformed PDU\n");
    goto error;
  }

  coap_ticks(&node->t);

  /* and add new node to receive queue */
  node->session = coap_session_reference(session);
  node->id = ntohs(node->pdu->hdr->id);

#ifndef NDEBUG
  if (LOG_DEBUG <= coap_get_log_level()) {
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 40
#endif
    /** @FIXME get debug to work again **
    unsigned char addr[INET6_ADDRSTRLEN+8], localaddr[INET6_ADDRSTRLEN+8];
    if (coap_print_addr(remote, addr, INET6_ADDRSTRLEN+8) &&
	coap_print_addr(&packet->dst, localaddr, INET6_ADDRSTRLEN+8) )
      debug("** received %d bytes from %s on interface %s:\n",
	    (int)msg_len, addr, localaddr);

	    */
    coap_show_pdu(node->pdu);
  }
#endif

  coap_dispatch(ctx, node);
  return -RESULT_OK;

error:
  /* FIXME: send back RST? */
  coap_delete_node(node);
  return -result;

error_early:
  return -result;
}

int
coap_remove_from_queue(coap_queue_t **queue, coap_session_t *session, coap_tid_t id, coap_queue_t **node) {
  coap_queue_t *p, *q;

  if (!queue || !*queue)
    return 0;

  /* replace queue head if PDU's time is less than head's time */

  if (session == (*queue)->session && id == (*queue)->id) { /* found transaction */
    *node = *queue;
    *queue = (*queue)->next;
    if (*queue) {	  /* adjust relative time of new queue head */
      (*queue)->t += (*node)->t;
    }
    (*node)->next = NULL;
    debug("** %s tid=%d: removed\n", coap_session_str(session), id);
    return 1;
  }

  /* search transaction to remove (only first occurence will be removed) */
  q = *queue;
  do {
    p = q;
    q = q->next;
  } while (q && session != q->session && id != q->id);

  if (q) {			/* found transaction */
    p->next = q->next;
    if (p->next) {		/* must update relative time of p->next */
      p->next->t += q->t;
    }
    q->next = NULL;
    *node = q;
    debug("** %s tid=%d: removed\n", coap_session_str(session), id);
    return 1;
  }

  return 0;

}

COAP_STATIC_INLINE int
token_match(const unsigned char *a, size_t alen,
  const unsigned char *b, size_t blen) {
  return alen == blen && (alen == 0 || memcmp(a, b, alen) == 0);
}

void
coap_cancel_session_messages(coap_context_t *context, coap_session_t *session) {
  coap_queue_t *p, *q;

  while (context->sendqueue && context->sendqueue->session == session) {
    q = context->sendqueue;
    context->sendqueue = q->next;
    debug("** %s tid=%d: removed\n", coap_session_str(session), q->id);
    coap_delete_node(q);
  }

  if (!context->sendqueue)
    return;

  p = context->sendqueue;
  q = p->next;

  while (q) {
    if (q->session == session) {
      p->next = q->next;
      debug("** %s tid=%d: removed\n", coap_session_str(session), q->id);
      coap_delete_node(q);
      q = p->next;
    } else {
      p = q;
      q = q->next;
    }
  }
}

void
coap_cancel_all_messages(coap_context_t *context, coap_session_t *session,
  const unsigned char *token, size_t token_length) {
  /* cancel all messages in sendqueue that are for dst
   * and use the specified token */
  coap_queue_t *p, *q;

  while (context->sendqueue && context->sendqueue->session == session &&
    token_match(token, token_length,
      context->sendqueue->pdu->hdr->token,
      context->sendqueue->pdu->hdr->token_length)) {
    q = context->sendqueue;
    context->sendqueue = q->next;
    debug("** %s tid=%d: removed\n", coap_session_str(session), q->id);
    coap_delete_node(q);
  }

  if (!context->sendqueue)
    return;

  p = context->sendqueue;
  q = p->next;

  /* when q is not NULL, it does not match (dst, token), so we can skip it */
  while (q) {
    if (q->session == session &&
      token_match(token, token_length,
	q->pdu->hdr->token, q->pdu->hdr->token_length)) {
      p->next = q->next;
      debug("** %s tid=%d: removed\n", coap_session_str(session), q->id);
      coap_delete_node(q);
      q = p->next;
    } else {
      p = q;
      q = q->next;
    }
  }
}

coap_queue_t *
coap_find_transaction(coap_queue_t *queue, coap_session_t *session, coap_tid_t id) {
  while (queue && queue->session != session && queue->id != id)
    queue = queue->next;

  return queue;
}

coap_pdu_t *
coap_new_error_response(coap_pdu_t *request, unsigned char code,
  coap_opt_filter_t opts) {
  coap_opt_iterator_t opt_iter;
  coap_pdu_t *response;
  size_t size = sizeof(coap_hdr_t) + request->hdr->token_length;
  unsigned char type;
  coap_opt_t *option;
  unsigned short opt_type = 0;	/* used for calculating delta-storage */

#if COAP_ERROR_PHRASE_LENGTH > 0
  char *phrase = coap_response_phrase(code);

  /* Need some more space for the error phrase and payload start marker */
  if (phrase)
    size += strlen(phrase) + 1;
#endif

  assert(request);

  /* cannot send ACK if original request was not confirmable */
  type = request->hdr->type == COAP_MESSAGE_CON
    ? COAP_MESSAGE_ACK
    : COAP_MESSAGE_NON;

  /* Estimate how much space we need for options to copy from
   * request. We always need the Token, for 4.02 the unknown critical
   * options must be included as well. */
  coap_option_clrb(opts, COAP_OPTION_CONTENT_TYPE); /* we do not want this */

  coap_option_iterator_init(request, &opt_iter, opts);

  /* Add size of each unknown critical option. As known critical
     options as well as elective options are not copied, the delta
     value might grow.
   */
  while ((option = coap_option_next(&opt_iter))) {
    unsigned short delta = opt_iter.type - opt_type;
    /* calculate space required to encode (opt_iter.type - opt_type) */
    if (delta < 13) {
      size++;
    } else if (delta < 269) {
      size += 2;
    } else {
      size += 3;
    }

    /* add coap_opt_length(option) and the number of additional bytes
     * required to encode the option length */

    size += coap_opt_length(option);
    switch (*option & 0x0f) {
    case 0x0e:
      size++;
      /* fall through */
    case 0x0d:
      size++;
      break;
    default:
      ;
    }

    opt_type = opt_iter.type;
  }

  /* Now create the response and fill with options and payload data. */
  response = coap_pdu_init(type, code, request->hdr->id, size);
  if (response) {
    /* copy token */
    if (!coap_add_token(response, request->hdr->token_length,
      request->hdr->token)) {
      debug("cannot add token to error response\n");
      coap_delete_pdu(response);
      return NULL;
    }

    /* copy all options */
    coap_option_iterator_init(request, &opt_iter, opts);
    while ((option = coap_option_next(&opt_iter))) {
      coap_add_option(response, opt_iter.type,
	COAP_OPT_LENGTH(option),
	COAP_OPT_VALUE(option));
    }

#if COAP_ERROR_PHRASE_LENGTH > 0
    /* note that diagnostic messages do not need a Content-Format option. */
    if (phrase)
      coap_add_data(response, (unsigned int)strlen(phrase), (unsigned char *)phrase);
#endif
  }

  return response;
}

/**
 * Quick hack to determine the size of the resource description for
 * .well-known/core.
 */
COAP_STATIC_INLINE size_t
get_wkc_len(coap_context_t *context, coap_opt_t *query_filter) {
  unsigned char buf[1];
  size_t len = 0;

  if (coap_print_wellknown(context, buf, &len, UINT_MAX, query_filter)
    & COAP_PRINT_STATUS_ERROR) {
    warn("cannot determine length of /.well-known/core\n");
    return 0;
  }

  debug("get_wkc_len: coap_print_wellknown() returned %zu\n", len);

  return len;
}

#define SZX_TO_BYTES(SZX) ((size_t)(1 << ((SZX) + 4)))

coap_pdu_t *
coap_wellknown_response(coap_context_t *context, coap_session_t *session,
  coap_pdu_t *request) {
  coap_pdu_t *resp;
  coap_opt_iterator_t opt_iter;
  size_t len, wkc_len;
  unsigned char buf[2];
  int result = 0;
  int need_block2 = 0;	   /* set to 1 if Block2 option is required */
  coap_block_t block;
  coap_opt_t *query_filter;
  size_t offset = 0;

  resp = coap_pdu_init(request->hdr->type == COAP_MESSAGE_CON
    ? COAP_MESSAGE_ACK
    : COAP_MESSAGE_NON,
    COAP_RESPONSE_CODE(205),
    request->hdr->id, coap_session_max_pdu_size(session));
  if (!resp) {
    debug("coap_wellknown_response: cannot create PDU\n");
    return NULL;
  }

  if (!coap_add_token(resp, request->hdr->token_length, request->hdr->token)) {
    debug("coap_wellknown_response: cannot add token\n");
    goto error;
  }

  query_filter = coap_check_option(request, COAP_OPTION_URI_QUERY, &opt_iter);
  wkc_len = get_wkc_len(context, query_filter);

  /* The value of some resources is undefined and get_wkc_len will return 0.*/
  if (wkc_len == 0) {
    debug("coap_wellknown_response: undefined resource\n");
    /* set error code 4.00 Bad Request*/
    resp->hdr->code = COAP_RESPONSE_CODE(400);
    resp->length = sizeof(coap_hdr_t) + resp->hdr->token_length;
    return resp;
  }

  /* check whether the request contains the Block2 option */
  if (coap_get_block(request, COAP_OPTION_BLOCK2, &block)) {
    debug("create block\n");
    offset = block.num << (block.szx + 4);
    if (block.szx > 6) {  /* invalid, MUST lead to 4.00 Bad Request */
      resp->hdr->code = COAP_RESPONSE_CODE(400);
      return resp;
    } else if (block.szx > COAP_MAX_BLOCK_SZX) {
      block.szx = COAP_MAX_BLOCK_SZX;
      block.num = (unsigned int)(offset >> (block.szx + 4));
    }

    need_block2 = 1;
  }

  /* Check if there is sufficient space to add Content-Format option
   * and data. We do this before adding the Content-Format option to
   * avoid sending error responses with that option but no actual
   * content. */
  if (resp->max_size <= (size_t)resp->length + 3) {
    debug("coap_wellknown_response: insufficient storage space\n");
    goto error;
  }

  /* Add Content-Format. As we have checked for available storage,
   * nothing should go wrong here. */
  assert(coap_encode_var_bytes(buf,
    COAP_MEDIATYPE_APPLICATION_LINK_FORMAT) == 1);
  coap_add_option(resp, COAP_OPTION_CONTENT_FORMAT,
    coap_encode_var_bytes(buf,
      COAP_MEDIATYPE_APPLICATION_LINK_FORMAT), buf);

  /* check if Block2 option is required even if not requested */
  if (!need_block2 && (resp->max_size - (size_t)resp->length < wkc_len)) {
    assert(resp->length <= resp->max_size);
    const size_t payloadlen = resp->max_size - resp->length;
    /* yes, need block-wise transfer */
    block.num = 0;
    block.m = 0;      /* the M bit is set by coap_write_block_opt() */
    block.szx = COAP_MAX_BLOCK_SZX;
    while (payloadlen < SZX_TO_BYTES(block.szx)) {
      if (block.szx == 0) {
	debug("coap_wellknown_response: message to small even for szx == 0\n");
	goto error;
      } else {
	block.szx--;
      }
    }

    need_block2 = 1;
  }

  /* write Block2 option if necessary */
  if (need_block2) {
    if (coap_write_block_opt(&block, COAP_OPTION_BLOCK2, resp, wkc_len) < 0) {
      debug("coap_wellknown_response: cannot add Block2 option\n");
      goto error;
    }
  }

  /* Manually set payload of response to let print_wellknown() write,
   * into our buffer without copying data. */

  resp->data = (unsigned char *)resp->hdr + resp->length;
  *resp->data = COAP_PAYLOAD_START;
  resp->data++;
  resp->length++;
  len = need_block2 ? SZX_TO_BYTES(block.szx) : resp->max_size - resp->length;

  result = coap_print_wellknown(context, resp->data, &len, offset, query_filter);
  if ((result & COAP_PRINT_STATUS_ERROR) != 0) {
    debug("coap_print_wellknown failed\n");
    goto error;
  }

  unsigned int new_resp_length = resp->length + COAP_PRINT_OUTPUT_LENGTH(result);
  if (new_resp_length > USHRT_MAX) {
    debug("coap_print_wellknown failed - print result too large\n");
    goto error;
  }

  resp->length = (unsigned short)new_resp_length;
  return resp;

error:
  /* set error code 5.03 and remove all options and data from response */
  resp->hdr->code = COAP_RESPONSE_CODE(503);
  resp->length = sizeof(coap_hdr_t) + resp->hdr->token_length;
  return resp;
}

/**
 * This function cancels outstanding messages for the session and
 * token specified in @p sent. Any observation relationship for
 * sent->session and the token are removed. Calling this function is
 * required when receiving an RST message (usually in response to a
 * notification) or a GET request with the Observe option set to 1.
 *
 * This function returns @c 0 when the token is unknown with this
 * peer, or a value greater than zero otherwise.
 */
static int
coap_cancel(coap_context_t *context, const coap_queue_t *sent) {
#ifndef WITHOUT_OBSERVE
  str token = { 0, NULL };
  int num_cancelled = 0;    /* the number of observers cancelled */

  /* remove observer for this resource, if any
   * get token from sent and try to find a matching resource. Uh!
   */

  COAP_SET_STR(&token, sent->pdu->hdr->token_length, sent->pdu->hdr->token);

  RESOURCES_ITER(context->resources, r) {
    num_cancelled += coap_delete_observer(r, sent->session, &token);
    coap_cancel_all_messages(context, sent->session, token.s, token.length);
  }

  return num_cancelled;
#else /* WITOUT_OBSERVE */  
  return 0;
#endif /* WITOUT_OBSERVE */  
}

/**
 * Internal flags to control the treatment of responses (specifically
 * in presence of the No-Response option).
 */
enum respond_t { RESPONSE_DEFAULT, RESPONSE_DROP, RESPONSE_SEND };

/**
 * Checks for No-Response option in given @p request and
 * returns @c 1 if @p response should be suppressed
 * according to RFC 7967.
 *
 * The value of the No-Response option is encoded as
 * follows:
 *
 *  +-------+-----------------------+-----------------------------------+
 *  | Value | Binary Representation |          Description              |
 *  +-------+-----------------------+-----------------------------------+
 *  |   0   |      <empty>          | Interested in all responses.      |
 *  +-------+-----------------------+-----------------------------------+
 *  |   2   |      00000010         | Not interested in 2.xx responses. |
 *  +-------+-----------------------+-----------------------------------+
 *  |   8   |      00001000         | Not interested in 4.xx responses. |
 *  +-------+-----------------------+-----------------------------------+
 *  |  16   |      00010000         | Not interested in 5.xx responses. |
 *  +-------+-----------------------+-----------------------------------+
 *
 * @param request  The CoAP request to check for the No-Response option.
 *                 This parameter must not be NULL.
 * @param response The response that is potentially suppressed.
 *                 This parameter must not be NULL.
 * @return RESPONSE_DEFAULT when no special treatment is requested,
 *         RESPONSE_DROP    when the response must be discarded, or
 *         RESPONSE_SEND    when the response must be sent.
 */
static enum respond_t
no_response(coap_pdu_t *request, coap_pdu_t *response) {
  coap_opt_t *nores;
  coap_opt_iterator_t opt_iter;
  unsigned int val = 0;

  assert(request);
  assert(response);

  if (COAP_RESPONSE_CLASS(response->hdr->code) > 0) {
    nores = coap_check_option(request, COAP_OPTION_NORESPONSE, &opt_iter);

    if (nores) {
      val = coap_decode_var_bytes(coap_opt_value(nores), coap_opt_length(nores));

      /* The response should be dropped when the bit corresponding to
       * the response class is set (cf. table in funtion
       * documentation). When a No-Response option is present and the
       * bit is not set, the sender explicitly indicates interest in
       * this response. */
      if (((1 << (COAP_RESPONSE_CLASS(response->hdr->code) - 1)) & val) > 0) {
	return RESPONSE_DROP;
      } else {
	return RESPONSE_SEND;
      }
    }
  }

  /* Default behavior applies when we are not dealing with a response
   * (class == 0) or the request did not contain a No-Response option.
   */
  return RESPONSE_DEFAULT;
}

#define WANT_WKC(Pdu,Key)					\
  (((Pdu)->hdr->code == COAP_REQUEST_GET) && is_wkc(Key))

static void
handle_request(coap_context_t *context, coap_queue_t *node) {
  coap_method_handler_t h = NULL;
  coap_pdu_t *response = NULL;
  coap_opt_filter_t opt_filter;
  coap_resource_t *resource;
  coap_key_t key;
  /* The respond field indicates whether a response must be treated
   * specially due to a No-Response option that declares disinterest
   * or interest in a specific response class. DEFAULT indicates that
   * No-Response has not been specified. */
  enum respond_t respond = RESPONSE_DEFAULT;

  coap_option_filter_clear(opt_filter);

  /* try to find the resource from the request URI */
  coap_hash_request_uri(node->pdu, key);
  resource = coap_get_resource_from_key(context, key);

  if (!resource) {
    /* The resource was not found. Check if the request URI happens to
     * be the well-known URI. In that case, we generate a default
     * response, otherwise, we return 4.04 */

    if (is_wkc(key)) {	/* request for .well-known/core */
      if (node->pdu->hdr->code == COAP_REQUEST_GET) { /* GET */
	info("create default response for %s\n", COAP_DEFAULT_URI_WELLKNOWN);
	response = coap_wellknown_response(context, node->session, node->pdu);
      } else {
	debug("method not allowed for .well-known/core\n");
	response = coap_new_error_response(node->pdu, COAP_RESPONSE_CODE(405),
	  opt_filter);
      }
    } else { /* request for any another resource, return 4.04 */

      debug("request for unknown resource 0x%02x%02x%02x%02x, return 4.04\n",
	key[0], key[1], key[2], key[3]);
      response =
	coap_new_error_response(node->pdu, COAP_RESPONSE_CODE(404),
	  opt_filter);
    }

    if (response && (no_response(node->pdu, response) != RESPONSE_DROP)) {
      if (coap_send(node->session, response) == COAP_INVALID_TID)
	warn("cannot send response for transaction %u\n", node->id);
    } else {
      coap_delete_pdu(response);
    }

    response = NULL;

    return;
  }

  /* the resource was found, check if there is a registered handler */
  if ((size_t)node->pdu->hdr->code - 1 <
    sizeof(resource->handler) / sizeof(coap_method_handler_t))
    h = resource->handler[node->pdu->hdr->code - 1];

  if (h) {
    debug("call custom handler for resource 0x%02x%02x%02x%02x\n",
      key[0], key[1], key[2], key[3]);
    response = coap_pdu_init(node->pdu->hdr->type == COAP_MESSAGE_CON
      ? COAP_MESSAGE_ACK
      : COAP_MESSAGE_NON,
      0, node->pdu->hdr->id, coap_session_max_pdu_size(node->session));

    /* Implementation detail: coap_add_token() immediately returns 0
       if response == NULL */
    if (coap_add_token(response, node->pdu->hdr->token_length,
      node->pdu->hdr->token)) {
      str token = { node->pdu->hdr->token_length, node->pdu->hdr->token };
      coap_opt_iterator_t opt_iter;
      coap_opt_t *observe = NULL;
      int observe_action = COAP_OBSERVE_CANCEL;

      /* check for Observe option */
      if (resource->observable) {
	observe = coap_check_option(node->pdu, COAP_OPTION_OBSERVE, &opt_iter);
	if (observe) {
	  observe_action =
	    coap_decode_var_bytes(coap_opt_value(observe),
	      coap_opt_length(observe));

	  if ((observe_action & COAP_OBSERVE_CANCEL) == 0) {
	    coap_subscription_t *subscription;

	    coap_log(LOG_DEBUG, "create new subscription\n");
	    subscription = coap_add_observer(resource, node->session, &token);
	    if (subscription) {
	      coap_touch_observer(context, node->session, &token);
	    }
	  } else {
	    coap_log(LOG_DEBUG, "removed observer\n");
	    coap_delete_observer(resource, node->session, &token);
	  }
	}
      }

      h(context, resource, node->session, node->pdu, &token, response);

      respond = no_response(node->pdu, response);
      if (respond != RESPONSE_DROP) {
	if (observe && (COAP_RESPONSE_CLASS(response->hdr->code) > 2)) {
	  coap_log(LOG_DEBUG, "removed observer\n");
	  coap_delete_observer(resource, node->session, &token);
	}

	/* If original request contained a token, and the registered
	 * application handler made no changes to the response, then
	 * this is an empty ACK with a token, which is a malformed
	 * PDU */
	if ((response->hdr->type == COAP_MESSAGE_ACK)
	  && (response->hdr->code == 0)) {
	  /* Remove token from otherwise-empty acknowledgment PDU */
	  response->hdr->token_length = 0;
	  response->length = sizeof(coap_hdr_t);
	}

	if ((respond == RESPONSE_SEND)
	  || /* RESPOND_DEFAULT */
	  (response->hdr->type != COAP_MESSAGE_NON ||
	  (response->hdr->code >= 64
	    && !coap_mcast_interface(&node->local_if)))) {

	  if (coap_send(node->session, response) == COAP_INVALID_TID)
	    debug("cannot send response for message %d\n", node->pdu->hdr->id);
	} else {
	  coap_delete_pdu(response);
	}
      } else {
	coap_delete_pdu(response);
      }
      response = NULL;
    } else {
      warn("cannot generate response\r\n");
    }
  } else {
    if (WANT_WKC(node->pdu, key)) {
      debug("create default response for %s\n", COAP_DEFAULT_URI_WELLKNOWN);
      response = coap_wellknown_response(context, node->session, node->pdu);
      debug("have wellknown response %p\n", (void *)response);
    } else
      response = coap_new_error_response(node->pdu, COAP_RESPONSE_CODE(405),
	opt_filter);

    if (response && (no_response(node->pdu, response) != RESPONSE_DROP)) {
      if (coap_send(node->session, response) == COAP_INVALID_TID)
	debug("cannot send response for transaction %d\n", node->id);
    } else {
      coap_delete_pdu(response);
    }
    response = NULL;
  }

  assert(response == NULL);
}

COAP_STATIC_INLINE void
handle_response(coap_context_t *context,
  coap_queue_t *sent, coap_queue_t *rcvd) {

  coap_send_ack(rcvd->session, rcvd->pdu);

  /* In a lossy context, the ACK of a separate response may have
   * been lost, so we need to stop retransmitting requests with the
   * same token.
   */
  coap_cancel_all_messages(context, rcvd->session,
    rcvd->pdu->hdr->token,
    rcvd->pdu->hdr->token_length);

  /* Call application-specific response handler when available. */
  if (context->response_handler) {
    context->response_handler(context, rcvd->session, sent ? sent->pdu : NULL,
      rcvd->pdu, rcvd->id);
  }
}

void
coap_dispatch(coap_context_t *context, coap_queue_t *rcvd) {
  coap_queue_t *sent = NULL;
  coap_pdu_t *response;
  coap_opt_filter_t opt_filter;

  if (!context)
    return;

  memset(opt_filter, 0, sizeof(coap_opt_filter_t));

  {
    /* version has been checked in coap_handle_message() */
    /* if ( rcvd->pdu->hdr->version != COAP_DEFAULT_VERSION ) { */
    /*   debug("dropped packet with unknown version %u\n", rcvd->pdu->hdr->version); */
    /*   goto cleanup; */
    /* } */

    switch (rcvd->pdu->hdr->type) {
    case COAP_MESSAGE_ACK:
      /* find transaction in sendqueue to stop retransmission */
      coap_remove_from_queue(&context->sendqueue, rcvd->session, rcvd->id, &sent);

      if (rcvd->pdu->hdr->code == 0)
	goto cleanup;

      /* if sent code was >= 64 the message might have been a
       * notification. Then, we must flag the observer to be alive
       * by setting obs->fail_cnt = 0. */
      if (sent && COAP_RESPONSE_CLASS(sent->pdu->hdr->code) == 2) {
	const str token =
	{ sent->pdu->hdr->token_length, sent->pdu->hdr->token };
	coap_touch_observer(context, sent->session, &token);
      }
      break;

    case COAP_MESSAGE_RST:
      /* We have sent something the receiver disliked, so we remove
       * not only the transaction but also the subscriptions we might
       * have. */

#ifndef WITH_CONTIKI
      coap_log(LOG_ALERT, "got RST for message %u\n", ntohs(rcvd->pdu->hdr->id));
#else /* WITH_CONTIKI */
      coap_log(LOG_ALERT, "got RST for message %u\n", uip_ntohs(rcvd->pdu->hdr->id));
#endif /* WITH_CONTIKI */

      /* find transaction in sendqueue to stop retransmission */
      coap_remove_from_queue(&context->sendqueue, rcvd->session, rcvd->id, &sent);

      if (sent)
	coap_cancel(context, sent);
      goto cleanup;

    case COAP_MESSAGE_NON:	/* check for unknown critical options */
      if (coap_option_check_critical(context, rcvd->pdu, opt_filter) == 0)
	goto cleanup;
      break;

    case COAP_MESSAGE_CON:	/* check for unknown critical options */
      if (coap_option_check_critical(context, rcvd->pdu, opt_filter) == 0) {

	/* FIXME: send response only if we have received a request. Otherwise,
	 * send RST. */
	response =
	  coap_new_error_response(rcvd->pdu, COAP_RESPONSE_CODE(402), opt_filter);

	if (!response) {
	  warn("coap_dispatch: cannot create error response\n");
	} else {
	  if (coap_send(rcvd->session, response) == COAP_INVALID_TID)
	    warn("coap_dispatch: error sending response\n");
	}

	goto cleanup;
      }
    default: break;
    }

    /* Pass message to upper layer if a specific handler was
     * registered for a request that should be handled locally. */
    if (COAP_MESSAGE_IS_REQUEST(rcvd->pdu->hdr))
      handle_request(context, rcvd);
    else if (COAP_MESSAGE_IS_RESPONSE(rcvd->pdu->hdr))
      handle_response(context, sent, rcvd);
    else {
      debug("dropped message with invalid code (%d.%02d)\n",
	COAP_RESPONSE_CLASS(rcvd->pdu->hdr->code),
	rcvd->pdu->hdr->code & 0x1f);

      if (!coap_is_mcast(&rcvd->session->local_addr)) {
	coap_send_message_type(rcvd->session,
	  rcvd->pdu, COAP_MESSAGE_RST);
      }
    }

  cleanup:
    coap_delete_node(sent);
    coap_delete_node(rcvd);
  }
}

int
coap_handle_event(coap_context_t *context, coap_event_t event, void *data) {
  coap_log(LOG_DEBUG, "*** EVENT: 0x%04x\n", event);

  if (context->handle_event) {
    return context->handle_event(context, event, data);
  } else {
    return 0;
  }
}

int
coap_can_exit(coap_context_t *context) {
  coap_endpoint_t *ep;
  coap_session_t *s;
  if (!context)
    return 1;
  if (context->sendqueue)
    return 0;
  LL_FOREACH(context->endpoint, ep) {
    LL_FOREACH(ep->sessions, s) {
      if (s->sendqueue)
        return 0;
    }
  }
  LL_FOREACH(context->sessions, s) {
    if (s->sendqueue)
      return 0;
  }
  return 1;
}

static int coap_started = 0;

void coap_startup(void) {
  if (coap_started)
    return;
  coap_started = 1;
#if defined(HAVE_WINSOCK2_H)
  WORD wVersionRequested = MAKEWORD(2, 2);
  WSADATA wsaData;
  WSAStartup(wVersionRequested, &wsaData);
#endif
  coap_clock_init();
#if defined(WITH_LWIP)
  prng_init(LWIP_RAND());
#elif defined(WITH_CONTIKI)
  prng_init(0);
#elif !defined(_WIN32)
  prng_init(0);
#endif
  coap_dtls_startup();
}

void coap_cleanup(void) {
#if defined(HAVE_WINSOCK2_H)
  WSACleanup();
#endif
}

#ifdef WITH_CONTIKI

/*---------------------------------------------------------------------------*/
/* CoAP message retransmission */
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(coap_retransmit_process, ev, data) {
  coap_tick_t now;
  coap_queue_t *nextpdu;

  PROCESS_BEGIN();

  debug("Started retransmit process\r\n");

  while (1) {
    PROCESS_YIELD();
    if (ev == PROCESS_EVENT_TIMER) {
      if (etimer_expired(&the_coap_context.retransmit_timer)) {

	nextpdu = coap_peek_next(&the_coap_context);

	coap_ticks(&now);
	while (nextpdu && nextpdu->t <= now) {
	  coap_retransmit(&the_coap_context, coap_pop_next(&the_coap_context));
	  nextpdu = coap_peek_next(&the_coap_context);
	}

	/* need to set timer to some value even if no nextpdu is available */
	etimer_set(&the_coap_context.retransmit_timer,
	  nextpdu ? nextpdu->t - now : 0xFFFF);
      }
#ifndef WITHOUT_OBSERVE
      if (etimer_expired(&the_coap_context.notify_timer)) {
	coap_check_notify(&the_coap_context);
	etimer_reset(&the_coap_context.notify_timer);
      }
#endif /* WITHOUT_OBSERVE */
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/

#endif /* WITH_CONTIKI */

#ifdef WITH_LWIP
/* FIXME: retransmits that are not required any more due to incoming packages
 * do *not* get cleared at the moment, the wakeup when the transmission is due
 * is silently accepted. this is mainly due to the fact that the required
 * checks are similar in two places in the code (when receiving ACK and RST)
 * and that they cause more than one patch chunk, as it must be first checked
 * whether the sendqueue item to be dropped is the next one pending, and later
 * the restart function has to be called. nothing insurmountable, but it can
 * also be implemented when things have stabilized, and the performance
 * penality is minimal
 *
 * also, this completely ignores COAP_RESOURCE_CHECK_TIME.
 * */

static void coap_retransmittimer_execute(void *arg) {
  coap_context_t *ctx = (coap_context_t*)arg;
  coap_tick_t now;
  coap_tick_t elapsed;
  coap_queue_t *nextinqueue;

  ctx->timer_configured = 0;

  coap_ticks(&now);

  elapsed = now - ctx->sendqueue_basetime; /* that's positive for sure, and unless we haven't been called for a complete wrapping cycle, did not wrap */

  nextinqueue = coap_peek_next(ctx);
  while (nextinqueue != NULL) {
    if (nextinqueue->t > elapsed) {
      nextinqueue->t -= elapsed;
      break;
    } else {
      elapsed -= nextinqueue->t;
      coap_retransmit(ctx, coap_pop_next(ctx));
      nextinqueue = coap_peek_next(ctx);
    }
  }

  ctx->sendqueue_basetime = now;

  coap_retransmittimer_restart(ctx);
}

static void coap_retransmittimer_restart(coap_context_t *ctx) {
  coap_tick_t now, elapsed, delay;

  if (ctx->timer_configured) {
    printf("clearing\n");
    sys_untimeout(coap_retransmittimer_execute, (void*)ctx);
    ctx->timer_configured = 0;
  }
  if (ctx->sendqueue != NULL) {
    coap_ticks(&now);
    elapsed = now - ctx->sendqueue_basetime;
    if (ctx->sendqueue->t >= elapsed) {
      delay = ctx->sendqueue->t - elapsed;
    } else {
      /* a strange situation, but not completely impossible.
       *
       * this happens, for example, right after
       * coap_retransmittimer_execute, when a retransmission
       * was *just not yet* due, and the clock ticked before
       * our coap_ticks was called.
       *
       * not trying to retransmit anything now, as it might
       * cause uncontrollable recursion; let's just try again
       * with the next main loop run.
       * */
      delay = 0;
    }

    printf("scheduling for %d ticks\n", delay);
    sys_timeout(delay, coap_retransmittimer_execute, (void*)ctx);
    ctx->timer_configured = 1;
  }
}
#endif
