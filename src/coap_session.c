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
#include "coap_dtls.h"
#include "coap_session.h"
#include "net.h"
#include "debug.h"
#include "mem.h"
#include "resource.h"
#include "utlist.h"
#include <stdio.h>

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
coap_make_session(coap_proto_t proto, coap_session_type_t type, const coap_address_t *local, const coap_address_t *remote, int ifindex, coap_context_t *context, coap_endpoint_t *endpoint) {
  coap_session_t *session = (coap_session_t*)coap_malloc_type(COAP_SESSION, sizeof(coap_session_t));
  if (!session)
    return NULL;
  memset(session, 0, sizeof(*session));
  session->proto = proto;
  session->type = type;
  if (local)
    coap_address_copy(&session->local_addr, local);
  else
    coap_address_init(&session->local_addr);
  if (remote)
    coap_address_copy(&session->remote_addr, remote);
  else
    coap_address_init(&session->remote_addr);
  session->ifindex = ifindex;
  session->context = context;
  session->endpoint = endpoint;
  if (endpoint)
    session->mtu = endpoint->default_mtu;
  else
    session->mtu = COAP_DEFAULT_PDU_SIZE;
  if (proto == COAP_PROTO_DTLS) {
    session->tls_overhead = 29;
    if (session->tls_overhead >= session->mtu) {
      session->tls_overhead = session->mtu;
      coap_log(LOG_ERR, "DTLS overhead exceeds MTU\n");
    }
  }

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
  if (session->proto == COAP_PROTO_DTLS)
    coap_dtls_free_session(session);
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
    if (q->pdu->hdr->type==COAP_MESSAGE_CON && session->context->nack_handler)
      session->context->nack_handler(session->context, session, q->pdu, session->proto == COAP_PROTO_DTLS ? COAP_NACK_TLS_FAILED : COAP_NACK_NOT_DELIVERABLE, q->id);
    coap_delete_node(q);
  }

  debug("*** %s: session closed\n", coap_session_str(session));

  coap_free_type(COAP_SESSION, session);
}

unsigned int coap_session_max_pdu_size(coap_session_t *session) {
  return session->mtu - session->tls_overhead;
}

void coap_session_set_mtu(coap_session_t *session, unsigned mtu) {
  session->mtu = (uint16_t)mtu;
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
    node = coap_new_node();
    if (node == NULL)
      return COAP_INVALID_TID;
    node->id = ntohs(pdu->hdr->id);
    node->pdu = pdu;
    if (pdu->hdr->type == COAP_MESSAGE_CON) {
      uint8_t r;
      prng(&r, sizeof(r));
      /* add timeout in range [ACK_TIMEOUT...ACK_TIMEOUT * ACK_RANDOM_FACTOR] */
      node->timeout = calc_timeout(r);
    }
  }
  LL_APPEND(session->sendqueue, node);
  debug("** %s tid=%d: delayed\n", coap_session_str(session), node->id);
  return COAP_PDU_DELAYED;
}

void coap_session_connected(coap_session_t *session) {
  debug("*** %s: session connected\n", coap_session_str(session));

  session->state = COAP_SESSION_STATE_ESTABLISHED;

  if ( session->proto==COAP_PROTO_DTLS) {
    session->tls_overhead = (uint16_t)coap_dtls_get_overhead(session);
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
    debug("** %s tid=%d: transmitted after delay\n", coap_session_str(session), (int)ntohs(q->pdu->hdr->id));
    if (session->proto == COAP_PROTO_DTLS)
      bytes_written = coap_dtls_send(session, (const uint8_t*)q->pdu->hdr, q->pdu->length);
    else
      bytes_written = coap_session_send(session, (const uint8_t*)q->pdu->hdr, q->pdu->length);
    if (q->pdu->hdr->type == COAP_MESSAGE_CON) {
      if (coap_wait_ack(session->context, session, q) >= 0)
	q = NULL;
    }
    if ( q )
      coap_delete_node(q);
    if (bytes_written < 0)
      break;
  }
}

void coap_session_disconnected(coap_session_t *session, coap_nack_reason_t reason) {
  (void)reason;
  debug("*** %s: session disconnected\n", coap_session_str(session));
  if (session->proto == COAP_PROTO_DTLS && session->tls) {
    coap_dtls_free_session(session);
    session->tls = NULL;
  }
  session->state = COAP_SESSION_STATE_NONE;
  while (session->sendqueue) {
    coap_queue_t *q = session->sendqueue;
    session->sendqueue = q->next;
    q->next = NULL;
    debug("** %s tid=%d: not transmitted after delay\n", coap_session_str(session), q->id);
    if (q->pdu->hdr->type == COAP_MESSAGE_CON) {
      if (coap_wait_ack(session->context, session, q) >= 0)
	q = NULL;
    }
    if (q)
      coap_delete_node(q);
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
  }
  session->state = COAP_SESSION_STATE_NONE;
  while (session->sendqueue) {
    coap_queue_t *q = session->sendqueue;
    session->sendqueue = q->next;
    q->next = NULL;
    debug("** %s tid=%d: not transmitted after delay\n", coap_session_str(session), (int)q->id);
    if (q->pdu->hdr->type == COAP_MESSAGE_CON && session->context->nack_handler)
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
      &packet->dst, &packet->src, packet->ifindex, endpoint->context,
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
  coap_session_t *session = coap_make_session(COAP_PROTO_DTLS, COAP_SESSION_TYPE_SERVER, &packet->dst, &packet->src, packet->ifindex, endpoint->context, endpoint);
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

  session = coap_make_session(proto, COAP_SESSION_TYPE_CLIENT, local_if, server, 0, ctx, NULL);
  if (!session)
    goto error;

  if (!coap_socket_connect_udp(&session->sock, local_if, server,
    proto == COAP_PROTO_DTLS ? COAPS_DEFAULT_PORT : COAP_DEFAULT_PORT,
    &session->local_addr, &session->remote_addr
  )
    ) {
    goto error;
  }

  session->ref = 1;
  session->sock.flags = COAP_SOCKET_NOT_EMPTY | COAP_SOCKET_CONNECTED | COAP_SOCKET_WANT_DATA;
  if (local_if)
    session->sock.flags |= COAP_SOCKET_BOUND;
  LL_PREPEND(ctx->sessions, session);
  return session;

error:
  if (session)
    coap_session_free(session);
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
      coap_session_free(session);
      return NULL;
    }
  }
  coap_ticks(&session->last_rx_tx);
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
    }
  }

  if (key && key_len > 0) {
    session->psk_key = (uint8_t*)coap_malloc(key_len);
    if (session->psk_key) {
      memcpy(session->psk_key, key, key_len);
      session->psk_key_len = key_len;
    } else {
      coap_log(LOG_WARNING, "Cannot store session PSK key");
    }
  }

  debug("*** %s: new outgoing session\n", coap_session_str(session));
  return coap_session_connect(session);
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

  ep = coap_malloc_endpoint();
  if (!ep) {
    coap_log(LOG_WARNING, "coap_new_endpoint: malloc");
    goto error;
  }

  memset(ep, 0, sizeof(struct coap_endpoint_t));
  ep->context = context;
  ep->proto = proto;

  if (!coap_socket_bind_udp(&ep->sock, listen_addr, &ep->bind_addr))
    goto error;

#ifndef NDEBUG
  if (LOG_DEBUG <= coap_get_log_level()) {
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 40
#endif
    unsigned char addr_str[INET6_ADDRSTRLEN + 8];

    if (coap_print_addr(&ep->bind_addr, addr_str, INET6_ADDRSTRLEN + 8)) {
      debug("created %s endpoint %s\n",
	ep->proto == COAP_PROTO_DTLS ? "DTLS " : "UDP",
	addr_str);
    }
  }
#endif /* NDEBUG */

  ep->sock.flags = COAP_SOCKET_NOT_EMPTY | COAP_SOCKET_BOUND | COAP_SOCKET_WANT_DATA;

  if (proto == COAP_PROTO_DTLS) {
    ep->hello.proto = proto;
    ep->hello.type = COAP_SESSION_TYPE_HELLO;
    ep->hello.mtu = ep->default_mtu;
    ep->hello.context = context;
    ep->hello.endpoint = ep;
  }

  ep->default_mtu = COAP_DEFAULT_PDU_SIZE;

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
    coap_session_t *session;

    if (ep->sock.flags != COAP_SOCKET_EMPTY)
      coap_socket_close(&ep->sock);

    LL_FOREACH(ep->sessions, session) {
      assert(session->ref == 0);
      if (session->ref == 0) {
	if (session->sock.flags != COAP_SOCKET_EMPTY)
	  coap_socket_close(&session->sock);
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
