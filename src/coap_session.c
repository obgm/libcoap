/* session.c -- Session management for libcoap
*
* Copyright (C) 2017 Jean-Claue Michelou <jcm@spinetix.com>
*
* This file is part of the CoAP library libcoap. Please see
* README for terms of use.
*/

#ifndef _COAP_SESSION_H_
#define _COAP_SESSION_H_


#include "coap_config.h"
#include "coap_io.h"
#include "coap_session.h"
#include "net.h"
#include "debug.h"
#include "mem.h"
#include "resource.h"
#include "utlist.h"
#include "encode.h"
#include <stdio.h>

void
coap_session_set_max_retransmit (coap_session_t *session, unsigned int value) {
  if (value > 0)
    session->max_retransmit = value;
  coap_log(LOG_DEBUG, "*** %s: session max_retransmit set to %d\n",
           coap_session_str(session), session->max_retransmit);
  return;
}

void
coap_session_set_ack_timeout (coap_session_t *session, coap_fixed_point_t value) {
  if (value.integer_part > 0 && value.fractional_part < 1000)
    session->ack_timeout = value;
  coap_log(LOG_DEBUG, "*** %s: session ack_timeout set to %d.%03d\n",
           coap_session_str(session), session->ack_timeout.integer_part,
           session->ack_timeout.fractional_part);
  return;
}

void
coap_session_set_ack_random_factor (coap_session_t *session,
                                    coap_fixed_point_t value) {
  if (value.integer_part > 0 && value.fractional_part < 1000)
    session->ack_random_factor = value;
  coap_log(LOG_DEBUG, "*** %s: session ack_random_factor set to %d.%03d\n",
           coap_session_str(session), session->ack_random_factor.integer_part,
           session->ack_random_factor.fractional_part);
  return;
}

unsigned int
coap_session_get_max_transmit (coap_session_t *session) {
  return session->max_retransmit;
}

coap_fixed_point_t
coap_session_get_ack_timeout (coap_session_t *session) {
  return session->ack_timeout;
}

coap_fixed_point_t
coap_session_get_ack_random_factor (coap_session_t *session) {
  return session->ack_random_factor;
}

coap_session_t *
coap_session_reference(coap_session_t *session) {
  ++session->ref;
  return session;
}

void
coap_session_release(coap_session_t *session) {
  if (session) {
    assert(session->ref > 0);
    if (session->ref > 0)
      --session->ref;
    if (session->ref == 0 && session->type == COAP_SESSION_TYPE_CLIENT)
      coap_session_free(session);
  }
}

void
coap_session_set_app_data(coap_session_t *session, void *app_data) {
  assert(session);
  session->app = app_data;
}

void *
coap_session_get_app_data(const coap_session_t *session) {
  assert(session);
  return session->app;
}

static coap_session_t *
coap_make_session(coap_proto_t proto, coap_session_type_t type,
  const coap_address_t *local_if, const coap_address_t *local_addr,
  const coap_address_t *remote_addr, int ifindex, coap_context_t *context,
  coap_endpoint_t *endpoint) {
  coap_session_t *session = (coap_session_t*)coap_malloc_type(COAP_SESSION, sizeof(coap_session_t));
  if (!session)
    return NULL;
  memset(session, 0, sizeof(*session));
  session->proto = proto;
  session->type = type;
  if (local_if)
    coap_address_copy(&session->local_if, local_if);
  else
    coap_address_init(&session->local_if);
  if (local_addr)
    coap_address_copy(&session->local_addr, local_addr);
  else
    coap_address_init(&session->local_addr);
  if (remote_addr)
    coap_address_copy(&session->remote_addr, remote_addr);
  else
    coap_address_init(&session->remote_addr);
  session->ifindex = ifindex;
  session->context = context;
  session->endpoint = endpoint;
  if (endpoint)
    session->mtu = endpoint->default_mtu;
  else
    session->mtu = COAP_DEFAULT_MTU;
  if (proto == COAP_PROTO_DTLS) {
    session->tls_overhead = 29;
    if (session->tls_overhead >= session->mtu) {
      session->tls_overhead = session->mtu;
      coap_log(LOG_ERR, "DTLS overhead exceeds MTU\n");
    }
  }
  session->max_retransmit = COAP_DEFAULT_MAX_RETRANSMIT;
  session->ack_timeout = COAP_DEFAULT_ACK_TIMEOUT;
  session->ack_random_factor = COAP_DEFAULT_ACK_RANDOM_FACTOR;

  /* initialize message id */
  prng((unsigned char *)&session->tx_mid, sizeof(session->tx_mid));

  return session;
}

void coap_session_free(coap_session_t *session) {
  coap_queue_t *q, *tmp;

  if (!session)
    return;
  assert(session->ref == 0);
  if (session->ref)
    return;
  if (session->partial_pdu)
    coap_delete_pdu(session->partial_pdu);
  if (session->proto == COAP_PROTO_DTLS)
    coap_dtls_free_session(session);
  else if (session->proto == COAP_PROTO_TLS)
    coap_tls_free_session(session);
  if (session->sock.flags != COAP_SOCKET_EMPTY)
    coap_socket_close(&session->sock);
  if (session->endpoint) {
    if (session->endpoint->sessions)
      LL_DELETE(session->endpoint->sessions, session);
  } else if (session->context) {
    if (session->context->sessions)
      LL_DELETE(session->context->sessions, session);
  }
  if (session->psk_identity)
    coap_free(session->psk_identity);
  if (session->psk_key)
    coap_free(session->psk_key);

  LL_FOREACH_SAFE(session->sendqueue, q, tmp) {
    if (q->pdu->type==COAP_MESSAGE_CON && session->context && session->context->nack_handler)
      session->context->nack_handler(session->context, session, q->pdu, session->proto == COAP_PROTO_DTLS ? COAP_NACK_TLS_FAILED : COAP_NACK_NOT_DELIVERABLE, q->id);
    coap_delete_node(q);
  }

  debug("*** %s: session closed\n", coap_session_str(session));

  coap_free_type(COAP_SESSION, session);
}

size_t coap_session_max_pdu_size(coap_session_t *session) {
  size_t max_with_header = (size_t)(session->mtu - session->tls_overhead);
  if (COAP_PROTO_NOT_RELIABLE(session->proto))
    return max_with_header > 4 ? max_with_header - 4 : 0;
  /* we must assume there is no token to be on the safe side */
  if (max_with_header <= 2)
    return 0;
  else if (max_with_header <= COAP_MAX_MESSAGE_SIZE_TCP0 + 2)
    return max_with_header - 2;
  else if (max_with_header <= COAP_MAX_MESSAGE_SIZE_TCP8 + 3)
    return max_with_header - 3;
  else if (max_with_header <= COAP_MAX_MESSAGE_SIZE_TCP16 + 4)
    return max_with_header - 4;
  else
    return max_with_header - 6;
}

void coap_session_set_mtu(coap_session_t *session, unsigned mtu) {
#if defined(WITH_CONTIKI) || defined(WITH_LWIP)
  if (mtu > COAP_MAX_MESSAGE_SIZE_TCP16 + 4)
    mtu = COAP_MAX_MESSAGE_SIZE_TCP16 + 4;
#endif
  session->mtu = mtu;
  if (session->tls_overhead >= session->mtu) {
    session->tls_overhead = session->mtu;
    coap_log(LOG_ERR, "DTLS overhead exceeds MTU\n");
  }
}

ssize_t coap_session_send(coap_session_t *session, const uint8_t *data, size_t datalen) {
  ssize_t bytes_written;

  coap_socket_t *sock = &session->sock;
  if (sock->flags == COAP_SOCKET_EMPTY) {
    assert(session->endpoint != NULL);
    sock = &session->endpoint->sock;
  }

  bytes_written = coap_socket_send(sock, session, data, datalen);
  if (bytes_written == (ssize_t)datalen) {
    coap_ticks(&session->last_rx_tx);
    debug("*  %s: sent %zd bytes\n", coap_session_str(session), datalen);
  } else {
    debug("*  %s: failed to send %zd bytes\n", coap_session_str(session), datalen);
  }
  return bytes_written;
}

ssize_t coap_session_write(coap_session_t *session, const uint8_t *data, size_t datalen) {
  ssize_t bytes_written = coap_socket_write(&session->sock, data, datalen);
  if (bytes_written > 0) {
    coap_ticks(&session->last_rx_tx);
    debug("*  %s: sent %zd bytes\n", coap_session_str(session), datalen);
  } else if (bytes_written < 0) {
    debug( "*  %s: failed to send %zd bytes\n", coap_session_str(session), datalen );
  }
  return bytes_written;
}

ssize_t
coap_session_delay_pdu(coap_session_t *session, coap_pdu_t *pdu,
                       coap_queue_t *node)
{
  if ( node ) {
    coap_queue_t *removed = NULL;
    coap_remove_from_queue(&session->context->sendqueue, session, node->id, &removed);
    assert(removed == node);
    coap_session_release(node->session);
    node->session = NULL;
    node->t = 0;
  } else {
    coap_queue_t *q = NULL;
    /* Check that the same tid is not getting re-used in violation of RFC7252 */
    LL_FOREACH(session->sendqueue, q) {
      if (q->id == pdu->tid) {
        coap_log(LOG_ERR, "**  %s tid=%d: already in-use - dropped\n", coap_session_str(session), pdu->tid);
        return COAP_INVALID_TID;
      }
    }
    node = coap_new_node();
    if (node == NULL)
      return COAP_INVALID_TID;
    node->id = pdu->tid;
    node->pdu = pdu;
    if (pdu->type == COAP_MESSAGE_CON && COAP_PROTO_NOT_RELIABLE(session->proto)) {
      uint8_t r;
      prng(&r, sizeof(r));
      /* add timeout in range [ACK_TIMEOUT...ACK_TIMEOUT * ACK_RANDOM_FACTOR] */
      node->timeout = coap_calc_timeout(session, r);
    }
  }
  LL_APPEND(session->sendqueue, node);
  debug("** %s tid=%d: delayed\n", coap_session_str(session), node->id);
  return COAP_PDU_DELAYED;
}

void coap_session_send_csm(coap_session_t *session) {
  coap_pdu_t *pdu;
  uint8_t buf[4];
  assert(COAP_PROTO_RELIABLE(session->proto));
  debug("*** %s: sending CSM\n", coap_session_str(session));
  session->state = COAP_SESSION_STATE_CSM;
  session->partial_write = 0;
  if (session->mtu == 0)
    session->mtu = COAP_DEFAULT_MTU;  /* base value */
  pdu = coap_pdu_init(COAP_MESSAGE_CON, COAP_SIGNALING_CSM, 0, 16);
  if ( pdu == NULL
    || coap_add_option(pdu, COAP_SIGNALING_OPTION_MAX_MESSAGE_SIZE,
         coap_encode_var_safe(buf, sizeof(buf),
                                COAP_DEFAULT_MAX_PDU_RX_SIZE), buf) == 0
    || coap_pdu_encode_header(pdu, session->proto) == 0
  ) {
    coap_session_disconnected(session, COAP_NACK_NOT_DELIVERABLE);
  } else {
    ssize_t bytes_written = coap_session_send_pdu(session, pdu);
    if (bytes_written != (ssize_t)pdu->used_size + pdu->hdr_size)
      coap_session_disconnected(session, COAP_NACK_NOT_DELIVERABLE);
  }
  if (pdu)
    coap_delete_pdu(pdu);
}

void coap_session_connected(coap_session_t *session) {
  debug("*** %s: session connected\n", coap_session_str(session));

  session->state = COAP_SESSION_STATE_ESTABLISHED;
  session->partial_write = 0;

  if ( session->proto==COAP_PROTO_DTLS) {
    session->tls_overhead = coap_dtls_get_overhead(session);
    if (session->tls_overhead >= session->mtu) {
      session->tls_overhead = session->mtu;
      coap_log(LOG_ERR, "DTLS overhead exceeds MTU\n");
    }
  }

  while (session->sendqueue && session->state == COAP_SESSION_STATE_ESTABLISHED) {
    ssize_t bytes_written;
    coap_queue_t *q = session->sendqueue;
    session->sendqueue = q->next;
    q->next = NULL;
    debug("** %s tid=%d: transmitted after delay\n", coap_session_str(session), (int)q->pdu->tid);
    bytes_written = coap_session_send_pdu(session, q->pdu);
    if (q->pdu->type == COAP_MESSAGE_CON && COAP_PROTO_NOT_RELIABLE(session->proto)) {
      if (coap_wait_ack(session->context, session, q) >= 0)
	q = NULL;
    }
    if (COAP_PROTO_NOT_RELIABLE(session->proto)) {
      if (q)
	coap_delete_node(q);
      if (bytes_written < 0)
	break;
    } else {
      if (bytes_written <= 0 || (size_t)bytes_written < q->pdu->used_size + q->pdu->hdr_size) {
	q->next = session->sendqueue;
	session->sendqueue = q;
	if (bytes_written > 0)
	  session->partial_write = (size_t)bytes_written;
	break;
      } else {
        coap_delete_node(q);
      }
    }
  }
}

void coap_session_disconnected(coap_session_t *session, coap_nack_reason_t reason) {
  (void)reason;
  debug("*** %s: session disconnected\n", coap_session_str(session));
  if (session->proto == COAP_PROTO_DTLS && session->tls) {
    coap_dtls_free_session(session);
    session->tls = NULL;
  } else if (session->proto == COAP_PROTO_TLS && session->tls) {
    coap_tls_free_session(session);
    session->tls = NULL;
  }

  session->state = COAP_SESSION_STATE_NONE;
  if (session->partial_pdu) {
    coap_delete_pdu(session->partial_pdu);
    session->partial_pdu = NULL;
  }
  session->partial_read = 0;
  if (COAP_PROTO_NOT_RELIABLE(session->proto)) {
    while (session->sendqueue) {
      coap_queue_t *q = session->sendqueue;
      session->sendqueue = q->next;
      q->next = NULL;
      debug("** %s tid=%d: not transmitted after delay\n", coap_session_str(session), q->id);
      if (q->pdu->type==COAP_MESSAGE_CON && COAP_PROTO_NOT_RELIABLE(session->proto)) {
	if (coap_wait_ack(session->context, session, q) >= 0)
	  q = NULL;
      }
      if (q)
	coap_delete_node(q);
    }
  }
  if (COAP_PROTO_RELIABLE(session->proto)) {
    coap_socket_close(&session->sock);
#ifndef WITHOUT_OBSERVE
    coap_delete_observers(session->context, session);
#endif
  }
}

void coap_session_reset(coap_session_t *session) {
  debug("*** %s: session reset\n", coap_session_str(session));
#ifndef WITHOUT_OBSERVE
  coap_delete_observers(session->context, session);
#endif
  coap_cancel_session_messages(session->context, session, COAP_NACK_NOT_DELIVERABLE);
  if (session->proto == COAP_PROTO_DTLS && session->tls) {
    coap_dtls_free_session(session);
    session->tls = NULL;
  } else if (session->proto == COAP_PROTO_TLS && session->tls) {
    coap_tls_free_session(session);
    session->tls = NULL;
  }

  session->state = COAP_SESSION_STATE_NONE;
  if (session->partial_pdu) {
    coap_delete_pdu(session->partial_pdu);
    session->partial_pdu = NULL;
  }
  session->partial_read = 0;
  while (session->sendqueue) {
    coap_queue_t *q = session->sendqueue;
    session->sendqueue = q->next;
    q->next = NULL;
    debug("** %s tid=%d: not transmitted after delay\n", coap_session_str(session), (int)q->id);
    if (q->pdu->type == COAP_MESSAGE_CON && session->context->nack_handler)
      session->context->nack_handler(session->context, session, q->pdu, COAP_NACK_NOT_DELIVERABLE, q->id);
    coap_delete_node(q);
  }
}

coap_session_t *
coap_endpoint_get_session(coap_endpoint_t *endpoint,
  const coap_packet_t *packet, coap_tick_t now) {
  coap_session_t *session = NULL;
  unsigned int num_idle = 0;
  coap_session_t *oldest = NULL;

  endpoint->hello.ifindex = -1;

  LL_FOREACH(endpoint->sessions, session) {
    if (session->ifindex == packet->ifindex &&
      coap_address_equals(&session->local_addr, &packet->dst) &&
      coap_address_equals(&session->remote_addr, &packet->src))
    {
      session->last_rx_tx = now;
      return session;
    }
    if (session->ref == 0 && session->sendqueue == NULL && session->type == COAP_SESSION_TYPE_SERVER) {
      ++num_idle;
      if (oldest==NULL || session->last_rx_tx < oldest->last_rx_tx)
	oldest = session;
    }
  }

  if (endpoint->context->max_idle_sessions > 0 && num_idle >= endpoint->context->max_idle_sessions)
    coap_session_free(oldest);

  if (endpoint->proto == COAP_PROTO_DTLS) {
    session = &endpoint->hello;
    coap_address_copy(&session->local_addr, &packet->dst);
    coap_address_copy(&session->remote_addr, &packet->src);
    session->ifindex = packet->ifindex;
  } else {
    session = coap_make_session(endpoint->proto, COAP_SESSION_TYPE_SERVER,
      NULL, &packet->dst, &packet->src, packet->ifindex, endpoint->context,
      endpoint);
    if (session) {
      session->last_rx_tx = now;
      if (endpoint->proto == COAP_PROTO_UDP)
	session->state = COAP_SESSION_STATE_ESTABLISHED;
      LL_PREPEND(endpoint->sessions, session);
      debug("*** %s: new incoming session\n", coap_session_str(session));
    }
  }

  return session;
}

coap_session_t *
coap_endpoint_new_dtls_session(coap_endpoint_t *endpoint,
  const coap_packet_t *packet, coap_tick_t now) {
  coap_session_t *session = coap_make_session(COAP_PROTO_DTLS,
    COAP_SESSION_TYPE_SERVER, NULL, &packet->dst, &packet->src,
    packet->ifindex, endpoint->context, endpoint);
  if (session) {
    session->last_rx_tx = now;
    session->state = COAP_SESSION_STATE_HANDSHAKE;
    session->tls = coap_dtls_new_server_session(session);
    if (session->tls) {
      session->state = COAP_SESSION_STATE_HANDSHAKE;
      LL_PREPEND(endpoint->sessions, session);
      debug("*** %s: new incoming session\n", coap_session_str(session));
    } else {
      coap_session_free(session);
      session = NULL;
    }
  }
  return session;
}

static coap_session_t *
coap_session_create_client(
  coap_context_t *ctx,
  const coap_address_t *local_if,
  const coap_address_t *server,
  coap_proto_t proto
) {
  coap_session_t *session = NULL;

  assert(server);
  assert(proto != COAP_PROTO_NONE);

  session = coap_make_session(proto, COAP_SESSION_TYPE_CLIENT, local_if,
    local_if, server, 0, ctx, NULL);
  if (!session)
    goto error;

  coap_session_reference(session);

  if (proto == COAP_PROTO_UDP || proto == COAP_PROTO_DTLS) {
    if (!coap_socket_connect_udp(&session->sock, &session->local_if, server,
      proto == COAP_PROTO_DTLS ? COAPS_DEFAULT_PORT : COAP_DEFAULT_PORT,
      &session->local_addr, &session->remote_addr)) {
      goto error;
    }
  } else if (proto == COAP_PROTO_TCP || proto == COAP_PROTO_TLS) {
    if (!coap_socket_connect_tcp1(&session->sock, &session->local_if, server,
      proto == COAP_PROTO_TLS ? COAPS_DEFAULT_PORT : COAP_DEFAULT_PORT,
      &session->local_addr, &session->remote_addr)) {
      goto error;
    }
  }

  session->sock.flags |= COAP_SOCKET_NOT_EMPTY | COAP_SOCKET_WANT_READ;
  if (local_if)
    session->sock.flags |= COAP_SOCKET_BOUND;
  LL_PREPEND(ctx->sessions, session);
  return session;

error:
  coap_session_release(session);
  return NULL;
}

static coap_session_t *
coap_session_connect(coap_session_t *session) {
  if (session->proto == COAP_PROTO_UDP) {
    session->state = COAP_SESSION_STATE_ESTABLISHED;
  } else if (session->proto == COAP_PROTO_DTLS) {
    session->tls = coap_dtls_new_client_session(session);
    if (session->tls) {
      session->state = COAP_SESSION_STATE_HANDSHAKE;
    } else {
      /* Need to free session object. As a new session may not yet
       * have been referenced, we call coap_session_reference() first
       * before trying to release the object.
       */
      coap_session_reference(session);
      coap_session_release(session);
      return NULL;
    }
  } else if (session->proto == COAP_PROTO_TCP || session->proto == COAP_PROTO_TLS) {
    if (session->sock.flags & COAP_SOCKET_WANT_CONNECT) {
      session->state = COAP_SESSION_STATE_CONNECTING;
    } else if (session->proto == COAP_PROTO_TLS) {
      int connected = 0;
      session->tls = coap_tls_new_client_session(session, &connected);
      if (session->tls) {
	session->state = COAP_SESSION_STATE_HANDSHAKE;
        if (connected) {
          coap_handle_event(session->context, COAP_EVENT_DTLS_CONNECTED, session);
          coap_session_send_csm(session);
        }
      } else {
        /* Need to free session object. As a new session may not yet
         * have been referenced, we call coap_session_reference()
         * first before trying to release the object.
         */
        coap_session_reference(session);
	coap_session_release(session);
	return NULL;
      }
    } else {
      coap_session_send_csm(session);
    }
  }
  coap_ticks(&session->last_rx_tx);
  return session;
}

static coap_session_t *
coap_session_accept(coap_session_t *session) {
  if (session->proto == COAP_PROTO_TCP) {
    coap_session_send_csm(session);
  } else if (session->proto == COAP_PROTO_TLS) {
    int connected = 0;
    session->tls = coap_tls_new_server_session(session, &connected);
    if (session->tls) {
      session->state = COAP_SESSION_STATE_HANDSHAKE;
      if (connected) {
        coap_handle_event(session->context, COAP_EVENT_DTLS_CONNECTED, session);
        coap_session_send_csm(session);
      }
    } else {
      /* Need to free session object. As a new session may not yet
       * have been referenced, we call coap_session_reference() first
       * before trying to release the object.
       */
      coap_session_reference(session);
      coap_session_release(session);
      session = NULL;
    }
  }
  return session;
}

coap_session_t *coap_new_client_session(
  struct coap_context_t *ctx,
  const coap_address_t *local_if,
  const coap_address_t *server,
  coap_proto_t proto
) {
  coap_session_t *session = coap_session_create_client(ctx, local_if, server, proto);
  if (session) {
    debug("*** %s: new outgoing session\n", coap_session_str(session));
    session = coap_session_connect(session);
  }
  return session;
}

coap_session_t *coap_new_client_session_psk(
  struct coap_context_t *ctx,
  const coap_address_t *local_if,
  const coap_address_t *server,
  coap_proto_t proto,
  const char *identity,
  const uint8_t *key,
  unsigned key_len
) {
  coap_session_t *session = coap_session_create_client(ctx, local_if, server, proto);

  if (!session)
    return NULL;

  if (identity) {
    size_t identity_len = strlen(identity);
    session->psk_identity = (uint8_t*)coap_malloc(identity_len);
    if (session->psk_identity) {
      memcpy(session->psk_identity, identity, identity_len);
      session->psk_identity_len = identity_len;
    } else {
      coap_log(LOG_WARNING, "Cannot store session PSK identity");
      coap_session_release(session);
      return NULL;
    }
  }

  if (key && key_len > 0) {
    session->psk_key = (uint8_t*)coap_malloc(key_len);
    if (session->psk_key) {
      memcpy(session->psk_key, key, key_len);
      session->psk_key_len = key_len;
    } else {
      coap_log(LOG_WARNING, "Cannot store session PSK key");
      coap_session_release(session);
      return NULL;
    }
  }

  if (coap_dtls_is_supported()) {
    if (!coap_dtls_context_set_psk(ctx, NULL, key, key_len)) {
      coap_session_release(session);
      return NULL;
    }
  }
  debug("*** %s: new outgoing session\n", coap_session_str(session));
  return coap_session_connect(session);
}

coap_session_t *coap_new_client_session_pki(
  struct coap_context_t *ctx,
  const coap_address_t *local_if,
  const coap_address_t *server,
  coap_proto_t proto,
  coap_dtls_pki_t* setup_data
) {
  coap_session_t *session = coap_session_create_client(ctx, local_if, server, proto);

  if (!session)
    return NULL;

  if (coap_dtls_is_supported()) {
    if (!coap_dtls_context_set_pki(ctx, setup_data)) {
      coap_session_release(session);
      return NULL;
    }
  }
  debug("*** %s: new outgoing session\n", coap_session_str(session));
  return coap_session_connect(session);
}


coap_session_t *coap_new_server_session(
  struct coap_context_t *ctx,
  coap_endpoint_t *ep
) {
  coap_session_t *session;
  session = coap_make_session( ep->proto, COAP_SESSION_TYPE_SERVER,
                               &ep->bind_addr, NULL, NULL, 0, ctx, ep );
  if (!session)
    goto error;

  if (!coap_socket_accept_tcp(&ep->sock, &session->sock,
                              &session->local_addr, &session->remote_addr))
    goto error;
  session->sock.flags |= COAP_SOCKET_NOT_EMPTY | COAP_SOCKET_CONNECTED
                       | COAP_SOCKET_WANT_READ;
  LL_PREPEND(ep->sessions, session);
  if (session) {
    debug("*** %s: new incoming session\n", coap_session_str(session));
    session = coap_session_accept(session);
  }
  return session;

error:
  coap_session_free(session);
  return NULL;
}

coap_endpoint_t *
coap_new_endpoint(coap_context_t *context, const coap_address_t *listen_addr, coap_proto_t proto) {
  struct coap_endpoint_t *ep = NULL;

  assert(context);
  assert(listen_addr);
  assert(proto != COAP_PROTO_NONE);

  if (proto == COAP_PROTO_DTLS && !coap_dtls_is_supported()) {
    coap_log(LOG_CRIT, "coap_new_endpoint: DTLS not supported\n");
    goto error;
  }

  if (proto == COAP_PROTO_TLS && !coap_tls_is_supported()) {
    coap_log(LOG_CRIT, "coap_new_endpoint: TLS not supported\n");
    goto error;
  }

  if (proto == COAP_PROTO_DTLS || proto == COAP_PROTO_TLS) {
    if (!coap_dtls_context_check_keys_enabled(context)) {
      coap_log(LOG_INFO, "coap_new_endpoint: one of coap_dtls_context_set_psk() or coap_dtls_context_set_pki() not called\n");
      goto error;
    }
  }

  ep = coap_malloc_endpoint();
  if (!ep) {
    coap_log(LOG_WARNING, "coap_new_endpoint: malloc");
    goto error;
  }

  memset(ep, 0, sizeof(struct coap_endpoint_t));
  ep->context = context;
  ep->proto = proto;

  if (proto==COAP_PROTO_TCP || proto==COAP_PROTO_TLS) {
    if (!coap_socket_bind_tcp(&ep->sock, listen_addr, &ep->bind_addr))
      goto error;
    ep->sock.flags |= COAP_SOCKET_WANT_ACCEPT;
  } else if (proto==COAP_PROTO_UDP || proto==COAP_PROTO_DTLS) {
    if (!coap_socket_bind_udp(&ep->sock, listen_addr, &ep->bind_addr))
      goto error;
    ep->sock.flags |= COAP_SOCKET_WANT_READ;
  } else {
    coap_log(LOG_CRIT, "coap_new_endpoint: protocol not supported\n");
    goto error;
  }

#ifndef NDEBUG
  if (LOG_DEBUG <= coap_get_log_level()) {
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 40
#endif
    unsigned char addr_str[INET6_ADDRSTRLEN + 8];

    if (coap_print_addr(&ep->bind_addr, addr_str, INET6_ADDRSTRLEN + 8)) {
      debug("created %s endpoint %s\n",
	  ep->proto == COAP_PROTO_TLS ? "TLS"
	: ep->proto == COAP_PROTO_TCP ? "TCP"
	: ep->proto == COAP_PROTO_DTLS ? "DTLS " : "UDP",
	addr_str);
    }
  }
#endif /* NDEBUG */

  ep->sock.flags |= COAP_SOCKET_NOT_EMPTY | COAP_SOCKET_BOUND;

  if (proto == COAP_PROTO_DTLS) {
    ep->hello.proto = proto;
    ep->hello.type = COAP_SESSION_TYPE_HELLO;
    ep->hello.mtu = ep->default_mtu;
    ep->hello.context = context;
    ep->hello.endpoint = ep;
  }

  ep->default_mtu = COAP_DEFAULT_MTU;

  LL_PREPEND(context->endpoint, ep);
  return ep;

error:
  coap_free_endpoint(ep);
  return NULL;
}

void coap_endpoint_set_default_mtu(coap_endpoint_t *ep, unsigned mtu) {
  ep->default_mtu = (uint16_t)mtu;
}

void
coap_free_endpoint(coap_endpoint_t *ep) {
  if (ep) {
    coap_session_t *session, *tmp;

    if (ep->sock.flags != COAP_SOCKET_EMPTY)
      coap_socket_close(&ep->sock);

    LL_FOREACH_SAFE(ep->sessions, session, tmp) {
      assert(session->ref == 0);
      if (session->ref == 0) {
        session->endpoint = NULL;
        session->context = NULL;
        coap_session_free(session);
      }
    }

    coap_mfree_endpoint(ep);
  }
}

coap_session_t *
coap_session_get_by_peer(coap_context_t *ctx,
  const coap_address_t *remote_addr,
  int ifindex) {
  coap_session_t *s;
  coap_endpoint_t *ep;
  LL_FOREACH(ctx->sessions, s) {
    if (s->ifindex == ifindex && coap_address_equals(&s->remote_addr, remote_addr))
      return s;
  }
  LL_FOREACH(ctx->endpoint, ep) {
    if (ep->hello.ifindex == ifindex && coap_address_equals(&ep->hello.remote_addr, remote_addr))
      return &ep->hello;
    LL_FOREACH(ep->sessions, s) {
      if (s->ifindex == ifindex && coap_address_equals(&s->remote_addr, remote_addr))
	return s;
    }
  }
  return NULL;
}

const char *coap_session_str(const coap_session_t *session) {
  static char szSession[256];
  char *p = szSession, *end = szSession + sizeof(szSession);
  if (coap_print_addr(&session->local_addr, (unsigned char*)p, end - p) > 0)
    p += strlen(p);
  if (p + 6 < end) {
    strcpy(p, " <-> ");
    p += 5;
  }
  if (p + 1 < end) {
    if (coap_print_addr(&session->remote_addr, (unsigned char*)p, end - p) > 0)
      p += strlen(p);
  }
  if (session->ifindex > 0 && p + 1 < end)
    p += snprintf(p, end - p, " (if%d)", session->ifindex);
  if (p + 6 < end) {
    if (session->proto == COAP_PROTO_UDP) {
      strcpy(p, " UDP");
      p += 4;
    } else if (session->proto == COAP_PROTO_DTLS) {
      strcpy(p, " DTLS");
      p += 5;
    } else if (session->proto == COAP_PROTO_TCP) {
      strcpy(p, " TCP");
      p += 4;
    } else if (session->proto == COAP_PROTO_TLS) {
      strcpy(p, " TLS");
      p += 4;
    } else {
      strcpy(p, " NONE");
      p += 5;
    }
  }

  return szSession;
}

const char *coap_endpoint_str(const coap_endpoint_t *endpoint) {
  static char szEndpoint[128];
  char *p = szEndpoint, *end = szEndpoint + sizeof(szEndpoint);
  if (coap_print_addr(&endpoint->bind_addr, (unsigned char*)p, end - p) > 0)
    p += strlen(p);
  if (p + 6 < end) {
    if (endpoint->proto == COAP_PROTO_UDP) {
      strcpy(p, " UDP");
      p += 4;
    } else if (endpoint->proto == COAP_PROTO_DTLS) {
      strcpy(p, " DTLS");
      p += 5;
    } else {
      strcpy(p, " NONE");
      p += 5;
    }
  }

  return szEndpoint;
}

#endif  /* _COAP_SESSION_H_ */
