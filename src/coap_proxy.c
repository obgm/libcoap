/* coap_proxy.c -- helper functions for proxy handling
 *
 * Copyright (C) 2024 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file coap_proxy.c
 * @brief Proxy handling functions
 */

#include "coap3/coap_libcoap_build.h"

#if COAP_PROXY_SUPPORT
#include <stdio.h>

#ifdef _WIN32
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#endif

int
coap_proxy_is_supported(void) {
  return 1;
}

void
coap_proxy_cleanup(coap_context_t *context) {
  size_t i;
  size_t j;

  for (i = 0; i < context->proxy_list_count; i++) {
    for (j = 0; j < context->proxy_list[i].req_count; j++) {
      coap_delete_pdu(context->proxy_list[i].req_list[j].pdu);
      coap_delete_cache_key(context->proxy_list[i].req_list[j].cache_key);
    }
    coap_free_type(COAP_STRING, context->proxy_list[i].req_list);
  }
  coap_free_type(COAP_STRING, context->proxy_list);
}

/*
 * return 1 if there is a future expire time, else 0.
 * update tim_rem with remaining value if return is 1.
 */
int
coap_proxy_check_timeouts(coap_context_t *context, coap_tick_t now,
                          coap_tick_t *tim_rem) {
  size_t i;
  int ret = 0;

  *tim_rem = -1;
  for (i = 0; i < context->proxy_list_count; i++) {
    coap_proxy_list_t *proxy_list = &context->proxy_list[i];

    if (proxy_list->ongoing && proxy_list->idle_timeout_ticks) {
      if (proxy_list->last_used + proxy_list->idle_timeout_ticks <= now) {
        /* Drop session to upstream server */
        coap_session_release_lkd(proxy_list->ongoing);
        proxy_list->ongoing = NULL;
      } else {
        if (*tim_rem > proxy_list->last_used + proxy_list->idle_timeout_ticks - now) {
          *tim_rem = proxy_list->last_used + proxy_list->idle_timeout_ticks - now;
        }
        ret = 1;
      }
    }
  }
  return ret;
}

static int
coap_get_uri_proxy_scheme_info(const coap_pdu_t *request,
                               coap_opt_t *opt,
                               coap_uri_t *uri,
                               coap_string_t **uri_path,
                               coap_string_t **uri_query) {

  const char *opt_val = (const char *)coap_opt_value(opt);
  int opt_len = coap_opt_length(opt);
  coap_opt_iterator_t opt_iter;

  if (opt_len == 9 &&
      strncasecmp(opt_val, "coaps+tcp", 9) == 0) {
    uri->scheme = COAP_URI_SCHEME_COAPS_TCP;
    uri->port = COAPS_DEFAULT_PORT;
  } else if (opt_len == 8 &&
             strncasecmp(opt_val, "coap+tcp", 8) == 0) {
    uri->scheme = COAP_URI_SCHEME_COAP_TCP;
    uri->port = COAP_DEFAULT_PORT;
  } else if (opt_len == 5 &&
             strncasecmp(opt_val, "coaps", 5) == 0) {
    uri->scheme = COAP_URI_SCHEME_COAPS;
    uri->port = COAPS_DEFAULT_PORT;
  } else if (opt_len == 4 &&
             strncasecmp(opt_val, "coap", 4) == 0) {
    uri->scheme = COAP_URI_SCHEME_COAP;
    uri->port = COAP_DEFAULT_PORT;
  } else if (opt_len == 7 &&
             strncasecmp(opt_val, "coap+ws", 7) == 0) {
    uri->scheme = COAP_URI_SCHEME_COAP_WS;
    uri->port = 80;
  } else if (opt_len == 8 &&
             strncasecmp(opt_val, "coaps+ws", 8) == 0) {
    uri->scheme = COAP_URI_SCHEME_COAPS_WS;
    uri->port = 443;
  } else {
    coap_log_warn("Unsupported Proxy Scheme '%*.*s'\n",
                  opt_len, opt_len, opt_val);
    return 0;
  }

  opt = coap_check_option(request, COAP_OPTION_URI_HOST, &opt_iter);
  if (opt) {
    uri->host.length = coap_opt_length(opt);
    uri->host.s = coap_opt_value(opt);
  } else {
    coap_log_warn("Proxy Scheme requires Uri-Host\n");
    return 0;
  }
  opt = coap_check_option(request, COAP_OPTION_URI_PORT, &opt_iter);
  if (opt) {
    uri->port =
        coap_decode_var_bytes(coap_opt_value(opt),
                              coap_opt_length(opt));
  }
  *uri_path = coap_get_uri_path(request);
  if (*uri_path) {
    uri->path.s = (*uri_path)->s;
    uri->path.length = (*uri_path)->length;
  } else {
    uri->path.s = NULL;
    uri->path.length = 0;
  }
  *uri_query = coap_get_query(request);
  if (*uri_query) {
    uri->query.s = (*uri_query)->s;
    uri->query.length = (*uri_query)->length;
  } else {
    uri->query.s = NULL;
    uri->query.length = 0;
  }
  return 1;
}

int
coap_verify_proxy_scheme_supported(coap_uri_scheme_t scheme) {

  /* Sanity check that the connection can be forwarded on */
  switch (scheme) {
  case COAP_URI_SCHEME_HTTP:
  case COAP_URI_SCHEME_HTTPS:
    coap_log_warn("Proxy URI http or https not supported\n");
    return 0;
  case COAP_URI_SCHEME_COAP:
    break;
  case COAP_URI_SCHEME_COAPS:
    if (!coap_dtls_is_supported()) {
      coap_log_warn("coaps URI scheme not supported for proxy\n");
      return 0;
    }
    break;
  case COAP_URI_SCHEME_COAP_TCP:
    if (!coap_tcp_is_supported()) {
      coap_log_warn("coap+tcp URI scheme not supported for proxy\n");
      return 0;
    }
    break;
  case COAP_URI_SCHEME_COAPS_TCP:
    if (!coap_tls_is_supported()) {
      coap_log_warn("coaps+tcp URI scheme not supported for proxy\n");
      return 0;
    }
    break;
  case COAP_URI_SCHEME_COAP_WS:
    if (!coap_ws_is_supported()) {
      coap_log_warn("coap+ws URI scheme not supported for proxy\n");
      return 0;
    }
    break;
  case COAP_URI_SCHEME_COAPS_WS:
    if (!coap_wss_is_supported()) {
      coap_log_warn("coaps+ws URI scheme not supported for proxy\n");
      return 0;
    }
    break;
  case COAP_URI_SCHEME_LAST:
  default:
    coap_log_warn("%d URI scheme not supported\n", scheme);
    return 0;
  }
  return 1;
}

static coap_proxy_list_t *
coap_proxy_get_session(coap_session_t *session, const coap_pdu_t *request,
                       coap_pdu_t *response,
                       coap_proxy_server_list_t *server_list,
                       coap_proxy_server_t *server_use) {
  size_t i;
  coap_proxy_list_t *new_proxy_list;
  coap_proxy_list_t *proxy_list = session->context->proxy_list;
  size_t proxy_list_count = session->context->proxy_list_count;

  coap_opt_iterator_t opt_iter;
  coap_opt_t *proxy_scheme;
  coap_opt_t *proxy_uri;
  coap_string_t *uri_path = NULL;
  coap_string_t *uri_query = NULL;

  /* Round robin the defined next server list (which usually is just one */
  server_list->next_entry++;
  if (server_list->next_entry >= server_list->entry_count)
    server_list->next_entry = 0;

  memcpy(server_use, &server_list->entry[server_list->next_entry], sizeof(*server_use));

  switch (server_list->type) {
  case COAP_PROXY_REVERSE:
  case COAP_PROXY_FORWARD:
  case COAP_PROXY_DIRECT:
    /* Nothing else needs to be done */
    break;
  case COAP_PROXY_REVERSE_STRIP:
  case COAP_PROXY_FORWARD_STRIP:
  case COAP_PROXY_DIRECT_STRIP:
    /* Need to get actual server from CoAP options */
    /*
     * See if Proxy-Scheme
     */
    proxy_scheme = coap_check_option(request, COAP_OPTION_PROXY_SCHEME, &opt_iter);
    if (proxy_scheme) {
      if (!coap_get_uri_proxy_scheme_info(request, proxy_scheme, &server_use->uri, &uri_path,
                                          &uri_query)) {
        response->code = COAP_RESPONSE_CODE(505);
        return NULL;
      }
    }
    /*
     * See if Proxy-Uri
     */
    proxy_uri = coap_check_option(request, COAP_OPTION_PROXY_URI, &opt_iter);
    if (proxy_uri) {
      coap_log_info("Proxy URI '%.*s'\n",
                    (int)coap_opt_length(proxy_uri),
                    (const char *)coap_opt_value(proxy_uri));
      if (coap_split_proxy_uri(coap_opt_value(proxy_uri),
                               coap_opt_length(proxy_uri),
                               &server_use->uri) < 0) {
        /* Need to return a 5.05 RFC7252 Section 5.7.2 */
        coap_log_warn("Proxy URI not decodable\n");
        response->code = COAP_RESPONSE_CODE(505);
        return NULL;
      }
    }

    if (!(proxy_scheme || proxy_uri)) {
      response->code = COAP_RESPONSE_CODE(404);
      return NULL;
    }

    if (server_use->uri.host.length == 0) {
      /* Ongoing connection not well formed */
      response->code = COAP_RESPONSE_CODE(505);
      return NULL;
    }

    if (!coap_verify_proxy_scheme_supported(server_use->uri.scheme)) {
      response->code = COAP_RESPONSE_CODE(505);
      return NULL;
    }
    break;
  default:
    assert(0);
    return NULL;
  }

  /* See if we are already connected to the Server */
  for (i = 0; i < proxy_list_count; i++) {
    if (coap_string_equal(&proxy_list[i].uri.host, &server_use->uri.host) &&
        proxy_list[i].uri.port == server_use->uri.port &&
        proxy_list[i].uri.scheme == server_use->uri.scheme) {
      if (!server_list->track_client_session) {
        coap_ticks(&proxy_list[i].last_used);
        return &proxy_list[i];
      } else {
        if (proxy_list[i].incoming == session) {
          coap_ticks(&proxy_list[i].last_used);
          return &proxy_list[i];
        }
      }
    }
  }

  /* Need to create a new forwarding mapping */
  new_proxy_list = coap_realloc_type(COAP_STRING, proxy_list, (i+1)*sizeof(proxy_list[0]));

  if (new_proxy_list == NULL) {
    response->code = COAP_RESPONSE_CODE(500);
    return NULL;
  }
  session->context->proxy_list = proxy_list = new_proxy_list;
  memset(&proxy_list[i], 0, sizeof(proxy_list[i]));

  proxy_list[i].uri = server_use->uri;
  if (server_list->track_client_session) {
    proxy_list[i].incoming = session;
  }
  session->context->proxy_list_count++;
  proxy_list[i].idle_timeout_ticks = server_list->idle_timeout_secs * COAP_TICKS_PER_SECOND;
  coap_ticks(&proxy_list[i].last_used);
  return &proxy_list[i];
}

void
coap_proxy_remove_association(coap_session_t *session, int send_failure) {

  size_t i;
  size_t j;
  coap_proxy_list_t *proxy_list = session->context->proxy_list;
  size_t proxy_list_count = session->context->proxy_list_count;

  for (i = 0; i < proxy_list_count; i++) {
    /* Check for incoming match */
    for (j = 0; j < proxy_list[i].req_count; j++) {
      if (proxy_list[i].req_list[j].incoming == session) {
        coap_delete_pdu(proxy_list[i].req_list[j].pdu);
        coap_delete_bin_const(proxy_list[i].req_list[j].token_used);
        coap_delete_cache_key(proxy_list[i].req_list[j].cache_key);
        if (proxy_list[i].req_count-j > 1) {
          memmove(&proxy_list[i].req_list[j], &proxy_list[i].req_list[j+1],
                  (proxy_list[i].req_count-j-1) * sizeof(proxy_list[i].req_list[0]));
        }
        proxy_list[i].req_count--;
        break;
      }
    }
    if (proxy_list[i].incoming == session) {
      /* Only if there is a one-to-one tracking */
      coap_session_release_lkd(proxy_list[i].ongoing);
      break;
    }

    /* Check for outgoing match */
    if (proxy_list[i].ongoing == session) {
      coap_session_t *ongoing;

      for (j = 0; j < proxy_list[i].req_count; j++) {
        if (send_failure) {
          coap_pdu_t *response;
          coap_bin_const_t l_token;

          /* Need to send back a gateway failure */
          response = coap_pdu_init(proxy_list[i].req_list[j].pdu->type,
                                   COAP_RESPONSE_CODE(502),
                                   coap_new_message_id_lkd(proxy_list[i].incoming),
                                   coap_session_max_pdu_size_lkd(proxy_list[i].incoming));
          if (!response) {
            coap_log_info("PDU creation issue\n");
            goto cleanup;
          }

          l_token = coap_pdu_get_token(proxy_list[i].req_list[j].pdu);
          if (!coap_add_token(response, l_token.length,
                              l_token.s)) {
            coap_log_debug("Cannot add token to incoming proxy response PDU\n");
          }

          if (coap_send_lkd(proxy_list[i].incoming, response) == COAP_INVALID_MID) {
            coap_log_info("Failed to send PDU with 5.02 gateway issue\n");
          }
cleanup:
          coap_delete_pdu(proxy_list[i].req_list[j].pdu);
          coap_delete_bin_const(proxy_list[i].req_list[j].token_used);
          coap_delete_cache_key(proxy_list[i].req_list[j].cache_key);
        }
      }
      ongoing = proxy_list[i].ongoing;
      coap_free_type(COAP_STRING, proxy_list[i].req_list);
      if (proxy_list_count-i > 1) {
        memmove(&proxy_list[i],
                &proxy_list[i+1],
                (proxy_list_count-i-1) * sizeof(proxy_list[0]));
      }
      session->context->proxy_list_count--;
      coap_session_release_lkd(ongoing);
      break;
    }
  }
}

static coap_proxy_list_t *
coap_proxy_get_ongoing_session(coap_session_t *session,
                               const coap_pdu_t *request,
                               coap_pdu_t *response,
                               coap_proxy_server_list_t *server_list,
                               coap_proxy_server_t *server_use) {

  coap_address_t dst;
  coap_proto_t proto;
  coap_addr_info_t *info_list = NULL;
  coap_proxy_list_t *proxy_entry;
  coap_context_t *context = session->context;
  static char client_sni[256];

  proxy_entry = coap_proxy_get_session(session, request, response, server_list, server_use);
  if (!proxy_entry) {
    /* Response code should be set */
    return NULL;
  }

  if (!proxy_entry->ongoing) {
    /* Need to create a new session */

    /* resolve destination address where data should be sent */
    info_list = coap_resolve_address_info(&server_use->uri.host,
                                          server_use->uri.port,
                                          server_use->uri.port,
                                          server_use->uri.port,
                                          server_use->uri.port,
                                          0,
                                          1 << server_use->uri.scheme,
                                          COAP_RESOLVE_TYPE_REMOTE);

    if (info_list == NULL) {
      response->code = COAP_RESPONSE_CODE(502);
      coap_proxy_remove_association(session, 0);
      return NULL;
    }
    proto = info_list->proto;
    memcpy(&dst, &info_list->addr, sizeof(dst));
    coap_free_address_info(info_list);

    snprintf(client_sni, sizeof(client_sni), "%*.*s", (int)server_use->uri.host.length,
             (int)server_use->uri.host.length, server_use->uri.host.s);

    switch (server_use->uri.scheme) {
    case COAP_URI_SCHEME_COAP:
    case COAP_URI_SCHEME_COAP_TCP:
    case COAP_URI_SCHEME_COAP_WS:
#if COAP_OSCORE_SUPPORT
      if (server_use->oscore_conf) {
        proxy_entry->ongoing =
            coap_new_client_session_oscore_lkd(context, NULL, &dst,
                                               proto, server_use->oscore_conf);
      } else {
#endif /* COAP_OSCORE_SUPPORT */
        proxy_entry->ongoing =
            coap_new_client_session_lkd(context, NULL, &dst, proto);
#if COAP_OSCORE_SUPPORT
      }
#endif /* COAP_OSCORE_SUPPORT */
      break;
    case COAP_URI_SCHEME_COAPS:
    case COAP_URI_SCHEME_COAPS_TCP:
    case COAP_URI_SCHEME_COAPS_WS:
#if COAP_OSCORE_SUPPORT
      if (server_use->oscore_conf) {
        if (server_use->dtls_pki) {
          server_use->dtls_pki->client_sni = client_sni;
          proxy_entry->ongoing =
              coap_new_client_session_oscore_pki_lkd(context, NULL, &dst,
                                                     proto, server_use->dtls_pki, server_use->oscore_conf);
        } else if (server_use->dtls_cpsk) {
          server_use->dtls_cpsk->client_sni = client_sni;
          proxy_entry->ongoing =
              coap_new_client_session_oscore_psk_lkd(context, NULL, &dst,
                                                     proto, server_use->dtls_cpsk, server_use->oscore_conf);
        } else {
          coap_log_warn("Proxy: (D)TLS not configured for secure session\n");
        }
      } else {
#endif /* COAP_OSCORE_SUPPORT */
        /* Not doing OSCORE */
        if (server_use->dtls_pki) {
          server_use->dtls_pki->client_sni = client_sni;
          proxy_entry->ongoing =
              coap_new_client_session_pki_lkd(context, NULL, &dst,
                                              proto, server_use->dtls_pki);
        } else if (server_use->dtls_cpsk) {
          server_use->dtls_cpsk->client_sni = client_sni;
          proxy_entry->ongoing =
              coap_new_client_session_psk2_lkd(context, NULL, &dst,
                                               proto, server_use->dtls_cpsk);
        } else {
          coap_log_warn("Proxy: (D)TLS not configured for secure session\n");
        }
#if COAP_OSCORE_SUPPORT
      }
#endif /* COAP_OSCORE_SUPPORT */
      break;
    case COAP_URI_SCHEME_HTTP:
    case COAP_URI_SCHEME_HTTPS:
    case COAP_URI_SCHEME_LAST:
    default:
      assert(0);
      break;
    }
    if (proxy_entry->ongoing == NULL) {
      response->code = COAP_RESPONSE_CODE(505);
      coap_proxy_remove_association(session, 0);
      return NULL;
    }
  }

  return proxy_entry;
}

static void
coap_proxy_release_body_data(coap_session_t *session COAP_UNUSED,
                             void *app_ptr) {
  coap_delete_binary(app_ptr);
}

int COAP_API
coap_proxy_forward_request(coap_session_t *session,
                           const coap_pdu_t *request,
                           coap_pdu_t *response,
                           coap_resource_t *resource,
                           coap_cache_key_t *cache_key,
                           coap_proxy_server_list_t *server_list) {
  int ret;

  coap_lock_lock(session->context, return 0);
  ret = coap_proxy_forward_request_lkd(session,
                                       request,
                                       response,
                                       resource,
                                       cache_key,
                                       server_list);
  coap_lock_unlock(session->context);
  return ret;
}

int
coap_proxy_forward_request_lkd(coap_session_t *session,
                               const coap_pdu_t *request,
                               coap_pdu_t *response,
                               coap_resource_t *resource,
                               coap_cache_key_t *cache_key,
                               coap_proxy_server_list_t *server_list) {
  coap_proxy_list_t *proxy_entry;
  size_t size;
  size_t offset;
  size_t total;
  coap_binary_t *body_data = NULL;
  const uint8_t *data;
  coap_pdu_t *pdu = NULL;
  coap_bin_const_t r_token = coap_pdu_get_token(request);
  uint8_t token[8];
  size_t token_len;
  coap_proxy_req_t *new_req_list;
  coap_optlist_t *optlist = NULL;
  coap_opt_t *option;
  coap_opt_iterator_t opt_iter;
  coap_proxy_server_t server_use;

  /* Set up ongoing session (if not already done) */

  proxy_entry = coap_proxy_get_ongoing_session(session, request, response,
                                               server_list, &server_use);
  if (!proxy_entry)
    /* response code already set */
    return 0;

  /* Need to save the request pdu entry */
  new_req_list = coap_realloc_type(COAP_STRING, proxy_entry->req_list,
                                   (proxy_entry->req_count + 1)*sizeof(coap_proxy_req_t));

  if (new_req_list == NULL) {
    goto failed;
  }
  proxy_entry->req_list = new_req_list;
  /* Get a new token for ongoing session */
  coap_session_new_token(proxy_entry->ongoing, &token_len, token);
  new_req_list[proxy_entry->req_count].token_used = coap_new_bin_const(token, token_len);
  if (new_req_list[proxy_entry->req_count].token_used == NULL) {
    goto failed;
  }
  new_req_list[proxy_entry->req_count].pdu = coap_pdu_duplicate_lkd(request, session,
                                             r_token.length, r_token.s, NULL);
  if (new_req_list[proxy_entry->req_count].pdu == NULL) {
    coap_delete_bin_const(new_req_list[proxy_entry->req_count].token_used);
    new_req_list[proxy_entry->req_count].token_used = NULL;
    goto failed;
  }
  new_req_list[proxy_entry->req_count].resource = resource;
  new_req_list[proxy_entry->req_count].incoming = session;
  new_req_list[proxy_entry->req_count].cache_key = cache_key;
  proxy_entry->req_count++;

  switch (server_list->type) {
  case COAP_PROXY_REVERSE_STRIP:
  case COAP_PROXY_FORWARD_STRIP:
  case COAP_PROXY_DIRECT_STRIP:
    /*
     * Need to replace Proxy-Uri with Uri-Host (and Uri-Port)
     * or strip out Proxy-Scheme.
     */

    /*
     * Build up the ongoing PDU that we are going to send
     */
    pdu = coap_pdu_init(request->type, request->code,
                        coap_new_message_id_lkd(proxy_entry->ongoing),
                        coap_session_max_pdu_size_lkd(proxy_entry->ongoing));
    if (!pdu) {
      goto failed;
    }

    if (!coap_add_token(pdu, token_len, token)) {
      goto failed;
    }

    if (!coap_uri_into_optlist(&server_use.uri,
                               &proxy_entry->ongoing->addr_info.remote,
                               &optlist, 1)) {
      coap_log_err("Failed to create options for URI\n");
      goto failed;
    }

    /* Copy the remaining options across */
    coap_option_iterator_init(request, &opt_iter, COAP_OPT_ALL);
    while ((option = coap_option_next(&opt_iter))) {
      switch (opt_iter.number) {
      case COAP_OPTION_PROXY_URI:
        break;
      case COAP_OPTION_PROXY_SCHEME:
        break;
      case COAP_OPTION_BLOCK1:
      case COAP_OPTION_BLOCK2:
      case COAP_OPTION_Q_BLOCK1:
      case COAP_OPTION_Q_BLOCK2:
        /* These are not passed on */
        break;
      default:
        coap_insert_optlist(&optlist,
                            coap_new_optlist(opt_iter.number,
                                             coap_opt_length(option),
                                             coap_opt_value(option)));
        break;
      }
    }

    /* Update pdu with options */
    coap_add_optlist_pdu(pdu, &optlist);
    coap_delete_optlist(optlist);
    break;
  case COAP_PROXY_REVERSE:
  case COAP_PROXY_FORWARD:
  case COAP_PROXY_DIRECT:
  default:
    /*
     * Duplicate request PDU for onward transmission (with new token).
     */
    pdu = coap_pdu_duplicate_lkd(request, proxy_entry->ongoing, token_len, token, NULL);
    if (!pdu) {
      coap_log_debug("proxy: PDU generation error\n");
      goto failed;
    }
    break;
  }

  if (coap_get_data_large(request, &size, &data, &offset, &total)) {
    /* COAP_BLOCK_SINGLE_BODY is set, so single body should be given */
    assert(size == total);
    /*
     * Need to take a copy of the data as request PDU may go away before
     * all data is transmitted.
     */
    body_data = coap_new_binary(total);
    if (!body_data) {
      coap_log_debug("proxy: body build memory error\n");
      goto failed;
    }
    memcpy(body_data->s, data, size);
    if (!coap_add_data_large_request_lkd(proxy_entry->ongoing, pdu, total, data,
                                         coap_proxy_release_body_data, body_data)) {
      coap_log_debug("proxy: add data error\n");
      goto failed;
    }
  }

  if (coap_send_lkd(proxy_entry->ongoing, pdu) == COAP_INVALID_MID) {
    pdu = NULL;
    coap_log_debug("proxy: upstream PDU send error\n");
    goto failed;
  }

  /*
   * Do not update the response code (hence empty ACK) as will be sending
   * separate response when response comes back from upstream server
   */

  return 1;

failed:
  response->code = COAP_RESPONSE_CODE(500);
  coap_delete_pdu(pdu);
  return 0;
}

coap_response_t COAP_API
coap_proxy_forward_response(coap_session_t *session,
                            const coap_pdu_t *received,
                            coap_cache_key_t **cache_key) {
  int ret;

  coap_lock_lock(session->context, return 0);
  ret = coap_proxy_forward_response_lkd(session,
                                        received,
                                        cache_key);
  coap_lock_unlock(session->context);
  return ret;
}

coap_response_t
coap_proxy_forward_response_lkd(coap_session_t *session,
                                const coap_pdu_t *received,
                                coap_cache_key_t **cache_key) {
  coap_pdu_t *pdu = NULL;
  coap_session_t *incoming = NULL;
  size_t i;
  size_t j = 0;
  size_t size;
  const uint8_t *data;
  coap_optlist_t *optlist = NULL;
  coap_opt_t *option;
  coap_opt_iterator_t opt_iter;
  size_t offset;
  size_t total;
  coap_proxy_list_t *proxy_entry = NULL;
  uint16_t media_type = COAP_MEDIATYPE_TEXT_PLAIN;
  int maxage = -1;
  uint64_t etag = 0;
  coap_pdu_code_t rcv_code = coap_pdu_get_code(received);
  coap_bin_const_t rcv_token = coap_pdu_get_token(received);
  coap_bin_const_t req_token;
  coap_binary_t *body_data = NULL;
  coap_pdu_t *req_pdu;
  coap_proxy_list_t *proxy_list = session->context->proxy_list;
  size_t proxy_list_count = session->context->proxy_list_count;
  coap_resource_t *resource;
  struct coap_proxy_req_t *proxy_req = NULL;

  for (i = 0; i < proxy_list_count; i++) {
    proxy_entry = &proxy_list[i];
    for (j = 0; j < proxy_entry->req_count; j++) {
      if (coap_binary_equal(&rcv_token, proxy_entry->req_list[j].token_used)) {
        proxy_req = &proxy_entry->req_list[j];
        break;
      }
    }
    if (j != proxy_entry->req_count) {
      break;
    }
  }
  if (i == proxy_list_count) {
    coap_log_warn("Unknown proxy ongoing session response received\n");
    return COAP_RESPONSE_OK;
  }

  req_pdu = proxy_req->pdu;
  req_token = coap_pdu_get_token(req_pdu);
  resource = proxy_req->resource;
  incoming = proxy_req->incoming;

  coap_log_debug("** process upstream incoming %d.%02d response:\n",
                 COAP_RESPONSE_CLASS(rcv_code), rcv_code & 0x1F);

  if (coap_get_data_large(received, &size, &data, &offset, &total)) {
    /* COAP_BLOCK_SINGLE_BODY is set, so single body should be given */
    assert(size == total);
    body_data = coap_new_binary(total);
    if (!body_data) {
      coap_log_debug("body build memory error\n");
      goto remove_match;
    }
    memcpy(body_data->s, data, size);
    data = body_data->s;
  }

  /*
   * Build up the ongoing PDU that we are going to send to proxy originator
   * as separate response
   */
  pdu = coap_pdu_init(req_pdu->type, rcv_code,
                      coap_new_message_id_lkd(incoming),
                      coap_session_max_pdu_size_lkd(incoming));
  if (!pdu) {
    coap_log_debug("Failed to create ongoing proxy response PDU\n");
    goto remove_match;
  }

  if (!coap_add_token(pdu, req_token.length, req_token.s)) {
    coap_log_debug("cannot add token to ongoing proxy response PDU\n");
  }

  /*
   * Copy the options across, skipping those needed for
   * coap_add_data_response_large()
   */
  coap_option_iterator_init(received, &opt_iter, COAP_OPT_ALL);
  while ((option = coap_option_next(&opt_iter))) {
    switch (opt_iter.number) {
    case COAP_OPTION_CONTENT_FORMAT:
      media_type = coap_decode_var_bytes(coap_opt_value(option),
                                         coap_opt_length(option));
      break;
    case COAP_OPTION_MAXAGE:
      maxage = coap_decode_var_bytes(coap_opt_value(option),
                                     coap_opt_length(option));
      break;
    case COAP_OPTION_ETAG:
      etag = coap_decode_var_bytes8(coap_opt_value(option),
                                    coap_opt_length(option));
      break;
    case COAP_OPTION_BLOCK2:
    case COAP_OPTION_Q_BLOCK2:
    case COAP_OPTION_SIZE2:
      break;
    default:
      coap_insert_optlist(&optlist,
                          coap_new_optlist(opt_iter.number,
                                           coap_opt_length(option),
                                           coap_opt_value(option)));
      break;
    }
  }
  coap_add_optlist_pdu(pdu, &optlist);
  coap_delete_optlist(optlist);

  if (size > 0) {
    coap_string_t *l_query = coap_get_query(req_pdu);

    coap_add_data_large_response_lkd(resource, incoming, req_pdu, pdu,
                                     l_query,
                                     media_type, maxage, etag, size, data,
                                     coap_proxy_release_body_data,
                                     body_data);
    body_data = NULL;
    coap_delete_string(l_query);
  }

  if (cache_key)
    *cache_key = proxy_req->cache_key;

  coap_send_lkd(incoming, pdu);

remove_match:
  option = coap_check_option(received, COAP_OPTION_OBSERVE, &opt_iter);
  /* Need to remove matching token entry (apart from on Observe response) */
  if (option == NULL && proxy_entry->req_count) {
    coap_delete_pdu(proxy_entry->req_list[j].pdu);
    coap_delete_bin_const(proxy_entry->req_list[j].token_used);
    /* Do not delete cache key here - caller's responsibility */
    proxy_entry->req_count--;
    if (proxy_entry->req_count-j > 0) {
      memmove(&proxy_entry->req_list[j], &proxy_entry->req_list[j+1],
              (proxy_entry->req_count-j) * sizeof(proxy_entry->req_list[0]));
    }
  }
  coap_delete_binary(body_data);
  return COAP_RESPONSE_OK;
}

#else /* ! COAP_PROXY_SUPPORT */

int
coap_proxy_is_supported(void) {
  return 0;
}

COAP_API int
coap_proxy_forward_request(coap_session_t *session,
                           const coap_pdu_t *request,
                           coap_pdu_t *response,
                           coap_resource_t *resource,
                           coap_cache_key_t *cache_key,
                           coap_proxy_server_list_t *server_list) {
  (void)session;
  (void)request;
  (void)resource;
  (void)cache_key;
  (void)server_list;
  response->code = COAP_RESPONSE_CODE(500);
  return 0;
}

COAP_API coap_response_t
coap_proxy_forward_response(coap_session_t *session,
                            const coap_pdu_t *received,
                            coap_cache_key_t **cache_key) {
  (void)session;
  (void)received;
  (void)cache_key;
  return COAP_RESPONSE_OK;
}

int
coap_verify_proxy_scheme_supported(coap_uri_scheme_t scheme) {
  (void)scheme;
  return 0;
}
#endif /* ! COAP_PROXY_SUPPORT */
