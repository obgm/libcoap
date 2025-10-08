/* coap_proxy.c -- helper functions for proxy handling
 *
 * Copyright (C) 2024-2025 Jon Shallow <supjps-libcoap@jpshallow.com>
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
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

#if COAP_CLIENT_SUPPORT == 0
#error For Proxy support, COAP_CLIENT_SUPPORT must be set
#endif
#if COAP_SERVER_SUPPORT == 0
#error For Proxy support, COAP_SERVER_SUPPORT must be set
#endif

#ifdef _WIN32
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#endif

int
coap_proxy_is_supported(void) {
  return 1;
}

static void
coap_proxy_log_entry(coap_session_t *incoming, const coap_pdu_t *pdu,
                     coap_bin_const_t *upstream_token, const char *type) {
  if (coap_get_log_level() >= COAP_LOG_DEBUG) {
    coap_string_t *url;

    url = coap_get_uri_path(pdu);
    if (url) {
      coap_opt_iterator_t opt_iter;
      uint8_t addr[INET6_ADDRSTRLEN + 8];
      char scratch_d[24];
      char scratch_u[24];
      size_t size;
      size_t i;

      scratch_d[0] = '\000';
      for (i = 0; i < pdu->actual_token.length; i++) {
        size = strlen(scratch_d);
        snprintf(&scratch_d[size], sizeof(scratch_d)-size,
                 "%02x", pdu->actual_token.s[i]);
      }
      scratch_u[0] = '\000';
      if (upstream_token) {
        for (i = 0; i < upstream_token->length; i++) {
          size = strlen(scratch_u);
          snprintf(&scratch_u[size], sizeof(scratch_u)-size,
                   "%02x", upstream_token->s[i]);
        }
      }
      coap_print_addr(coap_session_get_addr_remote(incoming), addr, sizeof(addr));
      coap_log_debug("   proxy %-4s %s {%s}-{%s} \"%s\"%s\n", type, addr, scratch_u, scratch_d,
                     url->s, coap_check_option(pdu, COAP_OPTION_OBSERVE, &opt_iter) ? " Observe" : "");
      coap_delete_string(url);
    }
  }
}

void
coap_proxy_del_req(coap_proxy_list_t *proxy_entry, coap_proxy_req_t *proxy_req) {
  coap_proxy_log_entry(proxy_req->incoming, proxy_req->pdu,  proxy_req->token_used, "del");

  coap_delete_pdu_lkd(proxy_req->pdu);
  coap_delete_bin_const(proxy_req->token_used);
  coap_delete_cache_key(proxy_req->cache_key);
  if (proxy_req->proxy_cache) {
    if (coap_get_log_level() >= COAP_LOG_DEBUG) {
      coap_string_t *url;

      url = coap_get_uri_path(proxy_req->proxy_cache->req_pdu);
      coap_log_debug("***%s: Removing Proxy Cache \"%s\" (Active %d)\n",
                     coap_session_str(proxy_req->incoming),
                     url ? (char *)url->s : "???",
                     proxy_req->proxy_cache->ref);
      coap_delete_string(url);
    }
    assert(proxy_req->proxy_cache->ref);
    proxy_req->proxy_cache->ref--;
    if (proxy_req->proxy_cache->ref == 0) {
      PROXY_CACHE_DELETE(proxy_entry->rsp_cache, proxy_req->proxy_cache);
      coap_delete_pdu_lkd(proxy_req->proxy_cache->req_pdu);
      coap_delete_pdu_lkd(proxy_req->proxy_cache->rsp_pdu);
      coap_free_type(COAP_STRING, proxy_req->proxy_cache);
      proxy_req->proxy_cache = NULL;
    }
    if (proxy_req->doing_observe) {
      assert(proxy_req->incoming->ref_proxy_subs);
      proxy_req->incoming->ref_proxy_subs--;
      proxy_req->doing_observe = 0;
    }
  }
  /* To prevent potential loops */
  proxy_req->incoming = NULL;

  LL_DELETE(proxy_entry->proxy_req, proxy_req);
  coap_free_type(COAP_STRING, proxy_req);
}

static void
coap_proxy_cleanup_entry(coap_proxy_list_t *proxy_entry, int send_failure) {
  coap_proxy_req_t *proxy_req, *treq;

  LL_FOREACH_SAFE(proxy_entry->proxy_req, proxy_req, treq) {
    if (send_failure) {
      coap_pdu_t *response;
      coap_bin_const_t l_token;

      /* Need to send back a gateway failure */
      response = coap_pdu_init(proxy_req->pdu->type,
                               COAP_RESPONSE_CODE(502),
                               coap_new_message_id_lkd(proxy_entry->incoming),
                               coap_session_max_pdu_size_lkd(proxy_entry->incoming));
      if (!response) {
        coap_log_info("PDU creation issue\n");
        goto cleanup;
      }

      l_token = coap_pdu_get_token(proxy_req->pdu);
      if (!coap_add_token(response, l_token.length,
                          l_token.s)) {
        coap_log_debug("Cannot add token to incoming proxy response PDU\n");
      }

      if (coap_send_lkd(proxy_entry->incoming, response) == COAP_INVALID_MID) {
        coap_log_info("Failed to send PDU with 5.02 gateway issue\n");
      }
    }
cleanup:
    coap_proxy_del_req(proxy_entry, proxy_req);
  }
  coap_free_type(COAP_STRING, proxy_entry->uri_host_keep);
}

void
coap_proxy_cleanup(coap_context_t *context) {
  size_t i;

  for (i = 0; i < context->proxy_list_count; i++) {
    /* All sessions have now been closed down */
    coap_log_debug("proxy_entry %p cleaned up\n",
                   (void *)&context->proxy_list[i]);
    coap_proxy_cleanup_entry(&context->proxy_list[i], 0);
  }
  coap_free_type(COAP_STRING, context->proxy_list);
}

static int
coap_proxy_check_observe(coap_proxy_list_t *proxy_entry) {
  if (proxy_entry && proxy_entry->ongoing) {
    /* Need to see if there are any Observes active */
    coap_lg_crcv_t *lg_crcv;

    LL_FOREACH(proxy_entry->ongoing->lg_crcv, lg_crcv) {
      if (lg_crcv->observe_set) {
        return 1;
      }
    }
  }
  return 0;
}

/*
 * Return 1 if there is a future expire time, else 0.
 * Update tim_rem with remaining value if return is 1.
 */
int
coap_proxy_check_timeouts(coap_context_t *context, coap_tick_t now,
                          coap_tick_t *tim_rem) {
  size_t i;
  int ret = 0;

  *tim_rem = COAP_MAX_DELAY_TICKS;
  for (i = 0; i < context->proxy_list_count; i++) {
    coap_proxy_list_t *proxy_entry = &context->proxy_list[i];

    if (coap_proxy_check_observe(proxy_entry))
      continue;

    if (proxy_entry->ongoing && proxy_entry->idle_timeout_ticks) {
      if (proxy_entry->last_used + proxy_entry->idle_timeout_ticks <= now) {
        /* Drop session to upstream server (which may remove proxy entry) */
        if (coap_proxy_remove_association(proxy_entry->ongoing, 0))
          i--;
      } else {
        if (*tim_rem > proxy_entry->last_used + proxy_entry->idle_timeout_ticks - now) {
          *tim_rem = proxy_entry->last_used + proxy_entry->idle_timeout_ticks - now;
          ret = 1;
        }
      }
    }
  }
  return ret;
}

static int
coap_get_uri_proxy_scheme_info(const coap_pdu_t *request,
                               coap_opt_t *opt,
                               coap_uri_t *uri) {
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
    uri->host.s = NULL;
    uri->host.length = 0;
    coap_log_warn("Proxy Scheme requires Uri-Host\n");
    return 0;
  }
  opt = coap_check_option(request, COAP_OPTION_URI_PORT, &opt_iter);
  if (opt) {
    uri->port =
        coap_decode_var_bytes(coap_opt_value(opt),
                              coap_opt_length(opt));
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
                       coap_proxy_server_t *server_use, int *proxy_entry_created) {
  size_t i;
  coap_proxy_list_t *new_proxy_list;
  coap_proxy_list_t *proxy_list = session->context->proxy_list;
  size_t proxy_list_count = session->context->proxy_list_count;
  coap_opt_iterator_t opt_iter;
  coap_opt_t *proxy_scheme;
  coap_opt_t *proxy_uri;

  *proxy_entry_created = 0;

  /*
   * Maintain server stickability. server_use not needed as there is
   * ongoing session in place.
   */
  if (session->proxy_entry) {
    for (i = 0; i < proxy_list_count; i++) {
      if (&proxy_list[i] == session->proxy_entry) {
        if (session->proxy_entry->ongoing) {
          memset(server_use, 0, sizeof(*server_use));
          return session->proxy_entry;
        }
      }
    }
  }

  /* Round robin the defined next server list (which usually is just one */
  server_list->next_entry++;
  if (server_list->next_entry >= server_list->entry_count)
    server_list->next_entry = 0;

  if (server_list->entry_count) {
    memcpy(server_use, &server_list->entry[server_list->next_entry], sizeof(*server_use));
  } else {
    memset(server_use, 0, sizeof(*server_use));
  }

  switch (server_list->type) {
  case COAP_PROXY_REVERSE:
  case COAP_PROXY_REVERSE_STRIP:
  case COAP_PROXY_FORWARD_STATIC:
  case COAP_PROXY_FORWARD_STATIC_STRIP:
    /* Nothing else needs to be done here */
    break;
  case COAP_PROXY_FORWARD_DYNAMIC:
  case COAP_PROXY_FORWARD_DYNAMIC_STRIP:
    /* Need to get actual server from CoAP Proxy-Uri or Proxy-Scheme options */
    /*
     * See if Proxy-Scheme
     */
    proxy_scheme = coap_check_option(request, COAP_OPTION_PROXY_SCHEME, &opt_iter);
    if (proxy_scheme) {
      if (!coap_get_uri_proxy_scheme_info(request, proxy_scheme, &server_use->uri)) {
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
    break;
  default:
    assert(0);
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

  /* See if we are already connected to the Server */
  for (i = 0; i < proxy_list_count; i++) {
    if (coap_string_equal(&proxy_list[i].uri.host, &server_use->uri.host) &&
        proxy_list[i].uri.port == server_use->uri.port &&
        proxy_list[i].uri.scheme == server_use->uri.scheme) {
      if (!server_list->track_client_session && session->context->proxy_response_handler) {
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

  /* Keep a copy of the host as server_use->uri pointed to will be going away */
  proxy_list[i].uri = server_use->uri;
  proxy_list[i].uri_host_keep = coap_malloc_type(COAP_STRING,
                                                 server_use->uri.host.length);
  if (!proxy_list[i].uri_host_keep) {
    response->code = COAP_RESPONSE_CODE(500);
    return NULL;
  }
  memcpy(proxy_list[i].uri_host_keep, server_use->uri.host.s,
         server_use->uri.host.length);
  proxy_list[i].uri.host.s = proxy_list[i].uri_host_keep;
  /* Unset uri parts which point to going away information */
  proxy_list[i].uri.path.s = NULL;
  proxy_list[i].uri.path.length = 0;
  proxy_list[i].uri.query.s = NULL;
  proxy_list[i].uri.query.length = 0;

  if (server_list->track_client_session) {
    proxy_list[i].incoming = session;
  }
  *proxy_entry_created = 1;
  session->context->proxy_list_count++;
  proxy_list[i].idle_timeout_ticks = server_list->idle_timeout_secs * COAP_TICKS_PER_SECOND;
  coap_ticks(&proxy_list[i].last_used);
  session->proxy_entry = &proxy_list[i];
  return &proxy_list[i];
}

int
coap_proxy_remove_association(coap_session_t *session, int send_failure) {

  size_t i;
  coap_proxy_list_t *proxy_list = session->context->proxy_list;
  size_t proxy_list_count = session->context->proxy_list_count;

  for (i = 0; i < proxy_list_count; i++) {
    coap_proxy_list_t *proxy_entry = &proxy_list[i];
    coap_proxy_req_t *proxy_req;

    /* Check for incoming match */
retry:
    LL_FOREACH(proxy_entry->proxy_req, proxy_req) {
      if (proxy_req->incoming == session) {
        coap_proxy_del_req(proxy_entry, proxy_req);
        goto retry;
      }
    }
    if (proxy_entry->incoming == session) {
      /* Only if there is a one-to-one tracking */
      coap_session_t *ongoing = proxy_entry->ongoing;

      proxy_entry->ongoing = NULL;
      coap_session_release_lkd(ongoing);
      return 0;
    }

    /* Check for outgoing match */
    if (proxy_entry->ongoing == session) {
      coap_session_t *ongoing;

      coap_proxy_cleanup_entry(proxy_entry, send_failure);
      ongoing = proxy_entry->ongoing;
      coap_log_debug("*  %s: proxy_entry %p released (rem count = %zd)\n",
                     coap_session_str(ongoing),
                     (void *)proxy_entry,
                     session->context->proxy_list_count - 1);
      if (proxy_list_count-i > 1) {
        memmove(&proxy_list[i],
                &proxy_list[i+1],
                (proxy_list_count-i-1) * sizeof(proxy_list[0]));
      }
      session->context->proxy_list_count--;
      coap_session_release_lkd(ongoing);
      return 1;
    }
  }
  return 0;
}

static coap_proxy_list_t *
coap_proxy_get_ongoing_session(coap_session_t *session,
                               const coap_pdu_t *request,
                               coap_pdu_t *response,
                               coap_proxy_server_list_t *server_list) {

  coap_address_t dst;
  coap_proto_t proto;
  coap_addr_info_t *info_list = NULL;
  coap_proxy_list_t *proxy_entry;
  coap_context_t *context = session->context;
  static char client_sni[256];
  coap_proxy_server_t server_use;
  int proxy_entry_created;

  proxy_entry = coap_proxy_get_session(session, request, response, server_list,
                                       &server_use, &proxy_entry_created);
  if (!proxy_entry) {
    /* Error response code already set */
    return NULL;
  }

  if (!proxy_entry->ongoing) {
    /* Need to create a new session */
    coap_address_t *local_addr = NULL;

    /* resolve destination address where data should be sent */
    info_list = coap_resolve_address_info(&server_use.uri.host,
                                          server_use.uri.port,
                                          server_use.uri.port,
                                          server_use.uri.port,
                                          server_use.uri.port,
                                          0,
                                          1 << server_use.uri.scheme,
                                          COAP_RESOLVE_TYPE_REMOTE);

    if (info_list == NULL) {
      response->code = COAP_RESPONSE_CODE(502);
      coap_proxy_remove_association(session, 0);
      return NULL;
    }
    proto = info_list->proto;
    memcpy(&dst, &info_list->addr, sizeof(dst));
    coap_free_address_info(info_list);

#if COAP_AF_UNIX_SUPPORT
    coap_address_t bind_addr;
    if (coap_is_af_unix(&dst)) {
      char buf[COAP_UNIX_PATH_MAX];
      coap_tick_t now;

      /* Need a unique 'client' address */
      coap_ticks(&now);
      snprintf(buf, COAP_UNIX_PATH_MAX,
               "/tmp/coap-pr-cl-%" PRIu64, (uint64_t)now);
      if (!coap_address_set_unix_domain(&bind_addr, (const uint8_t *)buf,
                                        strlen(buf))) {
        fprintf(stderr, "coap_address_set_unix_domain: %s: failed\n",
                buf);
        remove(buf);
        return NULL;
      }
      (void)remove(buf);
      local_addr = &bind_addr;
    }
#endif /* COAP_AF_UNIX_SUPPORT */

    snprintf(client_sni, sizeof(client_sni), "%*.*s", (int)server_use.uri.host.length,
             (int)server_use.uri.host.length, server_use.uri.host.s);

    switch (server_use.uri.scheme) {
    case COAP_URI_SCHEME_COAP:
    case COAP_URI_SCHEME_COAP_TCP:
    case COAP_URI_SCHEME_COAP_WS:
#if COAP_OSCORE_SUPPORT
      if (server_use.oscore_conf) {
        proxy_entry->ongoing =
            coap_new_client_session_oscore_lkd(context, local_addr, &dst,
                                               proto, server_use.oscore_conf);
      } else {
#endif /* COAP_OSCORE_SUPPORT */
        proxy_entry->ongoing =
            coap_new_client_session_lkd(context, local_addr, &dst, proto);
#if COAP_OSCORE_SUPPORT
      }
#endif /* COAP_OSCORE_SUPPORT */
      break;
    case COAP_URI_SCHEME_COAPS:
    case COAP_URI_SCHEME_COAPS_TCP:
    case COAP_URI_SCHEME_COAPS_WS:
#if COAP_OSCORE_SUPPORT
      if (server_use.oscore_conf) {
        if (server_use.dtls_pki) {
          server_use.dtls_pki->client_sni = client_sni;
          proxy_entry->ongoing =
              coap_new_client_session_oscore_pki_lkd(context, local_addr, &dst,
                                                     proto, server_use.dtls_pki, server_use.oscore_conf);
        } else if (server_use.dtls_cpsk) {
          server_use.dtls_cpsk->client_sni = client_sni;
          proxy_entry->ongoing =
              coap_new_client_session_oscore_psk_lkd(context, local_addr, &dst,
                                                     proto, server_use.dtls_cpsk, server_use.oscore_conf);
        } else {
          coap_log_warn("Proxy: (D)TLS not configured for secure session\n");
        }
      } else {
#endif /* COAP_OSCORE_SUPPORT */
        /* Not doing OSCORE */
        if (server_use.dtls_pki) {
          server_use.dtls_pki->client_sni = client_sni;
          proxy_entry->ongoing =
              coap_new_client_session_pki_lkd(context, local_addr, &dst,
                                              proto, server_use.dtls_pki);
        } else if (server_use.dtls_cpsk) {
          server_use.dtls_cpsk->client_sni = client_sni;
          proxy_entry->ongoing =
              coap_new_client_session_psk2_lkd(context, local_addr, &dst,
                                               proto, server_use.dtls_cpsk);
        } else {
          /* Using client anonymous PKI */
          proxy_entry->ongoing =
              coap_new_client_session_lkd(context, local_addr, &dst, proto);
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
    if (proxy_entry_created) {
      coap_log_debug("*  %s: proxy_entry %p created (tot count = %zd)\n",
                     coap_session_str(proxy_entry->ongoing),
                     (void *)proxy_entry,
                     session->context->proxy_list_count);
    }
  } else if (proxy_entry->ongoing->session_failed) {
    if (!coap_session_reconnect(proxy_entry->ongoing)) {
      /* Server is not yet back up */
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

static coap_proxy_req_t *
coap_proxy_get_req(coap_proxy_list_t *proxy_entry, coap_proxy_cache_t *proxy_cache,
                   coap_session_t *session) {
  coap_proxy_req_t *proxy_req;

  LL_FOREACH(proxy_entry->proxy_req, proxy_req) {
    if (proxy_req->incoming == session && proxy_req->proxy_cache == proxy_cache) {
      return proxy_req;
    }
  }
  return NULL;
}

static void
coap_proxy_free_response_data(coap_session_t *session COAP_UNUSED, void *app_ptr) {
  coap_delete_bin_const(app_ptr);
}

static coap_response_t
coap_proxy_call_response_handler(coap_session_t *session, const coap_pdu_t *sent,
                                 coap_pdu_t *rcvd, coap_bin_const_t *token,
                                 coap_proxy_req_t *proxy_req, int replace_mid,
                                 int remove_observe) {
  coap_response_t ret = COAP_RESPONSE_FAIL;
  coap_pdu_t *resp_pdu;
  coap_pdu_t *fwd_pdu = NULL;
  size_t size;
  size_t offset;
  size_t total;
  const uint8_t *data;
  coap_string_t *l_query = NULL;

  if (remove_observe) {
    coap_opt_filter_t drop_options;

    memset(&drop_options, 0, sizeof(coap_opt_filter_t));
    coap_option_filter_set(&drop_options, COAP_OPTION_OBSERVE);
    /* Correct the token */
    resp_pdu = coap_pdu_duplicate_lkd(rcvd, session, token->length, token->s,
                                      &drop_options);
  } else {
    /* Correct the token */
    resp_pdu = coap_pdu_duplicate_lkd(rcvd, session, token->length, token->s,
                                      NULL);
  }
  if (!resp_pdu)
    return COAP_RESPONSE_FAIL;

  if (COAP_PROTO_NOT_RELIABLE(session->proto))
    resp_pdu->max_size = coap_session_max_pdu_size_lkd(session);

  if (replace_mid)
    resp_pdu->mid = sent->mid;

  proxy_req->mid =  resp_pdu->mid;

  /* If sent early ACK, and this is an ACK, need to convert it to CON */
  if (COAP_PROTO_NOT_RELIABLE(session->proto) && resp_pdu->type == COAP_MESSAGE_ACK &&
      !(session->block_mode & COAP_BLOCK_CACHE_RESPONSE)) {
    resp_pdu->type = COAP_MESSAGE_CON;
  }

  if (coap_get_data_large(rcvd, &size, &data, &offset, &total)) {
    uint16_t media_type = 0;
    int maxage = -1;
    uint64_t etag = 0;
    coap_opt_t *option;
    coap_opt_iterator_t opt_iter;
    coap_bin_const_t *body;

    /* COAP_BLOCK_SINGLE_BODY is set, so single body should be given */
    assert(size == total);

    body = coap_new_bin_const(data, size);
    if (!body) {
      coap_log_debug("coap_proxy_call_response_handler: copy data error\n");
      goto failed;
    }
    option = coap_check_option(rcvd, COAP_OPTION_CONTENT_FORMAT, &opt_iter);
    if (option) {
      media_type = coap_decode_var_bytes(coap_opt_value(option),
                                         coap_opt_length(option));
    }
    option = coap_check_option(rcvd, COAP_OPTION_MAXAGE, &opt_iter);
    if (option) {
      maxage = coap_decode_var_bytes(coap_opt_value(option),
                                     coap_opt_length(option));
    }
    option = coap_check_option(rcvd, COAP_OPTION_ETAG, &opt_iter);
    if (option) {
      etag = coap_decode_var_bytes8(coap_opt_value(option),
                                    coap_opt_length(option));
    }
    if (sent)
      l_query = coap_get_query(sent);
    if (!coap_add_data_large_response_lkd(proxy_req->resource, session, sent,
                                          resp_pdu,
                                          l_query,
                                          media_type, maxage, etag, body->length,
                                          body->s,
                                          coap_proxy_free_response_data,
                                          body)) {
      coap_log_debug("coap_proxy_call_response_handler: add data error\n");
      goto failed;
    }
  }
  coap_lock_callback_ret_release(fwd_pdu,
                                 session->context->proxy_response_handler(session,
                                     sent,
                                     resp_pdu,
                                     proxy_req->cache_key),
                                 /* context is being freed off */
                                 goto failed);
  if (fwd_pdu) {
    ret = COAP_RESPONSE_OK;
    if (coap_send_lkd(session, fwd_pdu) == COAP_INVALID_MID) {
      ret = COAP_RESPONSE_FAIL;
    }
    if (fwd_pdu != resp_pdu) {
      /* Application created a new PDU */
      coap_delete_pdu_lkd(resp_pdu);
    }
  } else {
failed:
    ret = COAP_RESPONSE_FAIL;
    coap_delete_pdu_lkd(resp_pdu);
  }
  coap_delete_string(l_query);
  return ret;
}

int COAP_API
coap_proxy_forward_request(coap_session_t *session,
                           const coap_pdu_t *request,
                           coap_pdu_t *response,
                           coap_resource_t *resource,
                           coap_cache_key_t *cache_key,
                           coap_proxy_server_list_t *server_list) {
  int ret;

  coap_lock_lock(return 0);
  ret = coap_proxy_forward_request_lkd(session,
                                       request,
                                       response,
                                       resource,
                                       cache_key,
                                       server_list);
  coap_lock_unlock();
  return ret;
}

/* https://rfc-editor.org/rfc/rfc7641#section-3.6 */
static const uint16_t coap_proxy_ignore_options[] = { COAP_OPTION_ETAG,
                                                      COAP_OPTION_RTAG,
                                                      COAP_OPTION_BLOCK2,
                                                      COAP_OPTION_Q_BLOCK2,
                                                      COAP_OPTION_OSCORE
                                                    };

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
  coap_proxy_req_t *proxy_req = NULL;
  coap_optlist_t *optlist = NULL;
  coap_opt_t *option;
  coap_opt_iterator_t opt_iter;
  coap_uri_t uri;
  coap_opt_t *obs_opt = coap_check_option(request,
                                          COAP_OPTION_OBSERVE,
                                          &opt_iter);
  coap_proxy_cache_t *proxy_cache = NULL;

  /* Set up ongoing session (if not already done) */
  proxy_entry = coap_proxy_get_ongoing_session(session, request, response,
                                               server_list);
  if (!proxy_entry) {
    /* Error response code already set */
    return 0;
  }
  coap_proxy_log_entry(session, request, NULL, "req");

  /* Is this a observe cached request? */
  if (obs_opt && session->context->proxy_response_handler) {
    coap_cache_key_t *cache_key_l;

    cache_key_l = coap_cache_derive_key_w_ignore(session, request,
                                                 COAP_CACHE_NOT_SESSION_BASED,
                                                 coap_proxy_ignore_options,
                                                 sizeof(coap_proxy_ignore_options)/sizeof(coap_proxy_ignore_options[0]));
    if (!cache_key_l) {
      response->code = COAP_RESPONSE_CODE(505);
      return 0;
    }
    PROXY_CACHE_FIND(proxy_entry->rsp_cache, cache_key_l, proxy_cache);
    coap_delete_cache_key(cache_key_l);
  }

  if (proxy_cache) {
    proxy_req = coap_proxy_get_req(proxy_entry, proxy_cache, session);
    if (proxy_req) {
      coap_tick_t now;

      if (obs_opt) {
        int observe_action;

        observe_action = coap_decode_var_bytes(coap_opt_value(obs_opt),
                                               coap_opt_length(obs_opt));

        if (observe_action == COAP_OBSERVE_CANCEL) {
          if (proxy_req->doing_observe) {
            assert(proxy_req->incoming->ref_proxy_subs);
            proxy_req->incoming->ref_proxy_subs--;
            proxy_req->doing_observe = 0;
          }
          if (proxy_entry->proxy_req && !proxy_entry->proxy_req->next &&
              proxy_req->token_used) {
            coap_binary_t tmp;

            coap_log_debug("coap_proxy_forward_request: Using coap_cancel_observe() to do Proxy OBSERVE cancellation\n");
            /* Unfortunately need to change the ptr type to be r/w */
            memcpy(&tmp.s, &proxy_req->token_used->s, sizeof(tmp.s));
            tmp.length = proxy_req->token_used->length;
            coap_cancel_observe_lkd(proxy_entry->ongoing, &tmp, COAP_MESSAGE_CON);
            /* Let the upstream cancellation be the response */
            return 1;
          } else {
            obs_opt = 0;
            goto return_cached_info;
          }
        } else if (observe_action == COAP_OBSERVE_ESTABLISH) {
          /* Client must be re-registering */
          coap_ticks(&now);
          if (proxy_cache && (proxy_cache->expire + COAP_TICKS_PER_SECOND) < now) {
            /* Need to get an updated rsp_pdu */
            coap_proxy_del_req(proxy_entry, proxy_req);
            proxy_req = NULL;
            proxy_cache = NULL;
          } else {
            goto return_cached_info;
          }
        }
      } else {
        coap_ticks(&now);
        if (proxy_cache && (proxy_cache->expire + COAP_TICKS_PER_SECOND) < now) {
          /* Need to get an updated rsp_pdu */
          coap_proxy_del_req(proxy_entry, proxy_req);
          proxy_req = NULL;
          proxy_cache = NULL;
        } else {
          goto return_cached_info;
        }
      }
    }
  }

  if (!proxy_req) {
    proxy_req = coap_malloc_type(COAP_STRING, sizeof(coap_proxy_req_t));
    if (proxy_req == NULL) {
      goto failed;
    }
    memset(proxy_req, 0, sizeof(coap_proxy_req_t));
    LL_PREPEND(proxy_entry->proxy_req, proxy_req);

    proxy_req->pdu = coap_const_pdu_reference_lkd(request);
    proxy_req->resource = resource;
    proxy_req->incoming = session;
    proxy_req->cache_key = cache_key;
    proxy_req->proxy_cache = proxy_cache;

    coap_proxy_log_entry(proxy_req->incoming, proxy_req->pdu, proxy_req->token_used,  "add");
  }

  if (proxy_cache) {
    coap_bin_const_t j_token;

    if (obs_opt)
      proxy_cache->ref++;
    coap_delete_bin_const(proxy_req->token_used);
    j_token = coap_pdu_get_token(proxy_cache->rsp_pdu);
    proxy_req->token_used = coap_new_bin_const(j_token.s, j_token.length);
    if (proxy_req->token_used == NULL) {
      goto failed;
    }
    goto return_cached_info;
  }

  /* Get a new token for ongoing session */
  coap_session_new_token(proxy_entry->ongoing, &token_len, token);
  coap_delete_bin_const(proxy_req->token_used);
  proxy_req->token_used = coap_new_bin_const(token, token_len);
  if (proxy_req->token_used == NULL) {
    goto failed;
  }
  coap_pdu_release_lkd(proxy_req->pdu);
  proxy_req->pdu = coap_const_pdu_reference_lkd(request);

  /* Need to create the ongoing request pdu entry */
  switch (server_list->type) {
  case COAP_PROXY_REVERSE_STRIP:
  case COAP_PROXY_FORWARD_STATIC_STRIP:
  case COAP_PROXY_FORWARD_DYNAMIC_STRIP:
    /*
     * Need to replace Proxy-Uri with Uri-Host (and Uri-Port)
     * and strip out Proxy-Scheme.
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

    /* Copy the remaining options across */
    coap_option_iterator_init(request, &opt_iter, COAP_OPT_ALL);
    while ((option = coap_option_next(&opt_iter))) {
      switch (opt_iter.number) {
      case COAP_OPTION_PROXY_URI:
        if (coap_split_proxy_uri(coap_opt_value(option),
                                 coap_opt_length(option),
                                 &uri) < 0) {
          /* Need to return a 5.05 RFC7252 Section 5.7.2 */
          coap_log_warn("Proxy URI not decodable\n");
          coap_delete_pdu_lkd(pdu);
          return 0;
        }
        if (!coap_uri_into_optlist(&uri, NULL, &optlist, 0)) {
          coap_log_err("Failed to create options for URI\n");
          goto failed;
        }
        break;
      case COAP_OPTION_PROXY_SCHEME:
        break;
      case COAP_OPTION_BLOCK1:
      case COAP_OPTION_BLOCK2:
      case COAP_OPTION_Q_BLOCK1:
      case COAP_OPTION_Q_BLOCK2:
        /* These are not passed on */
        break;
      case COAP_OPTION_URI_HOST:
      case COAP_OPTION_URI_PORT:
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
  case COAP_PROXY_FORWARD_STATIC:
  case COAP_PROXY_FORWARD_DYNAMIC:
  default:
    /*
     * Duplicate request PDU for onward transmission (with new token).
     */
    pdu = coap_pdu_duplicate_lkd(request, proxy_entry->ongoing, token_len, token, NULL);
    if (!pdu) {
      coap_log_debug("proxy: PDU generation error\n");
      goto failed;
    }
    if (COAP_PROTO_NOT_RELIABLE(session->proto))
      pdu->max_size = coap_session_max_pdu_size_lkd(proxy_entry->ongoing);
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

  coap_proxy_log_entry(proxy_req->incoming, proxy_req->pdu, proxy_req->token_used,  "fwd");
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
  coap_delete_pdu_lkd(pdu);
  return 0;

return_cached_info:
  if (obs_opt && !proxy_req->doing_observe) {
    int observe_action;

    observe_action = coap_decode_var_bytes(coap_opt_value(obs_opt),
                                           coap_opt_length(obs_opt));

    if (observe_action == COAP_OBSERVE_ESTABLISH) {
      proxy_req->doing_observe = 1;
      proxy_req->incoming->ref_proxy_subs++;
    }
  }
  coap_log_debug("*  %s: Using Proxy Cache (Active %d)\n",
                 coap_session_str(session),
                 proxy_cache->ref);
  coap_proxy_log_entry(session, request, &proxy_cache->rsp_pdu->actual_token,  "rspc");
  coap_proxy_call_response_handler(session, request, proxy_cache->rsp_pdu,
                                   &r_token, proxy_req, 1, obs_opt ? 0 : 1);
  if (!obs_opt)
    coap_proxy_del_req(proxy_entry, proxy_req);
  return 1;
}

coap_proxy_req_t *
coap_proxy_map_outgoing_request(coap_session_t *ongoing,
                                const coap_pdu_t *received,
                                coap_proxy_list_t **u_proxy_entry) {
  coap_proxy_list_t *proxy_list = ongoing->context->proxy_list;
  size_t proxy_list_count = ongoing->context->proxy_list_count;
  size_t i;
  coap_bin_const_t rcv_token = coap_pdu_get_token(received);
  coap_proxy_list_t *proxy_entry = NULL;
  coap_proxy_req_t *proxy_req;

  for (i = 0; i < proxy_list_count; i++) {
    proxy_entry = &proxy_list[i];
    if (proxy_entry->ongoing == ongoing) {
      LL_FOREACH(proxy_entry->proxy_req, proxy_req) {
        if (coap_binary_equal(&rcv_token, proxy_req->token_used)) {
          coap_ticks(&proxy_entry->last_used);
          if (u_proxy_entry)
            *u_proxy_entry = proxy_entry;
          return proxy_req;
        }
      }
    }
  }
  if (coap_get_log_level() >= COAP_LOG_DEBUG) {
    char scratch[24];
    size_t size;

    scratch[0] = '\000';
    for (i = 0; i < rcv_token.length; i++) {
      size = strlen(scratch);
      snprintf(&scratch[size], sizeof(scratch)-size,
               "%02x", rcv_token.s[i]);
    }
    coap_log_debug("   proxy token to match {%s}\n", scratch);
    for (i = 0; i < proxy_list_count; i++) {
      proxy_entry = &proxy_list[i];
      LL_FOREACH(proxy_entry->proxy_req, proxy_req) {
        coap_proxy_log_entry(proxy_req->incoming, proxy_req->pdu,  proxy_req->token_used, "miss");
      }
    }
  }
  return NULL;
}

coap_response_t COAP_API
coap_proxy_forward_response(coap_session_t *session,
                            const coap_pdu_t *received,
                            coap_cache_key_t **cache_key) {
  int ret;

  coap_lock_lock(return 0);
  ret = coap_proxy_forward_response_lkd(session,
                                        received,
                                        cache_key);
  coap_lock_unlock();
  return ret;
}

coap_response_t
coap_proxy_forward_response_lkd(coap_session_t *session,
                                const coap_pdu_t *received,
                                coap_cache_key_t **cache_key) {
  coap_pdu_t *pdu = NULL;
  coap_session_t *incoming = NULL;
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
  coap_bin_const_t req_token;
  coap_binary_t *body_data = NULL;
  coap_pdu_t *req_pdu;
  coap_resource_t *resource;
  coap_proxy_req_t *proxy_req = NULL;

  proxy_req = coap_proxy_map_outgoing_request(session, received, &proxy_entry);
  if (!proxy_req || proxy_req->incoming->server_list) {
    coap_log_warn("Unknown proxy ongoing session response received - ignored\n");
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
  /* Need to remove matching token entry (apart from an Observe response) */
  if (option == NULL) {
    if (proxy_entry->proxy_req) {
      /* Do not delete cache key here - caller's responsibility */
      proxy_req->cache_key = NULL;
      coap_proxy_del_req(proxy_entry, proxy_req);
    }
  } else if (!proxy_req->doing_observe) {
    option = coap_check_option(proxy_req->pdu, COAP_OPTION_OBSERVE, &opt_iter);
    if (option &&
        coap_decode_var_bytes(coap_opt_value(option),
                              coap_opt_length(option)) == COAP_OBSERVE_ESTABLISH) {
      proxy_req->doing_observe = 1;
      proxy_req->incoming->ref_proxy_subs++;
    }
  }
  coap_delete_binary(body_data);
  return COAP_RESPONSE_OK;
}

void
coap_proxy_process_incoming(coap_session_t *session,
                            coap_pdu_t *rcvd,
                            void *body_data, coap_proxy_req_t *proxy_req,
                            coap_proxy_list_t *proxy_entry) {
  coap_opt_t *obs_opt;
  coap_opt_t *option;
  coap_opt_iterator_t opt_iter;
  coap_response_t ret = COAP_RESPONSE_FAIL;
  coap_bin_const_t token;

  obs_opt = coap_check_option(rcvd, COAP_OPTION_OBSERVE, &opt_iter);

  /* See if we are doing proxy caching */
  if (obs_opt) {
    coap_proxy_cache_t *proxy_cache;
    coap_cache_key_t *cache_key_l;
    coap_tick_t now;
    uint64_t expire;

    /* Need to cache the response */
    if (proxy_req->proxy_cache) {
      coap_delete_pdu_lkd(proxy_req->proxy_cache->rsp_pdu);
      proxy_cache = proxy_req->proxy_cache;
    } else {
      proxy_cache = coap_malloc_type(COAP_STRING, sizeof(coap_proxy_cache_t));
      if (proxy_cache == NULL) {
        goto cache_fail;
      }
      memset(proxy_cache, 0, sizeof(coap_proxy_cache_t));
      cache_key_l = coap_cache_derive_key_w_ignore(session, proxy_req->pdu,
                                                   COAP_CACHE_NOT_SESSION_BASED,
                                                   coap_proxy_ignore_options,
                                                   sizeof(coap_proxy_ignore_options)/sizeof(coap_proxy_ignore_options[0]));
      if (!cache_key_l) {
        coap_free_type(COAP_STRING, proxy_cache);
        goto cache_fail;
      }
      memcpy(&proxy_cache->cache_req, cache_key_l,
             sizeof(proxy_cache->cache_req));
      coap_delete_cache_key(cache_key_l);

      proxy_cache->req_pdu = coap_pdu_reference_lkd(proxy_req->pdu);
      proxy_req->proxy_cache = proxy_cache;

      PROXY_CACHE_ADD(proxy_entry->rsp_cache, proxy_cache);
      proxy_cache->ref++;
    }
    if (rcvd->body_data) {
      /* More data than that held in the PDU */
      const uint8_t *data;
      size_t data_len;

      proxy_cache->rsp_pdu = coap_pdu_duplicate_lkd(rcvd,
                                                    session,
                                                    rcvd->actual_token.length,
                                                    rcvd->actual_token.s,
                                                    NULL);
      if (proxy_cache->rsp_pdu) {
        if (coap_get_data(rcvd, &data_len, &data)) {
          coap_binary_t *copy;

          copy = coap_new_binary(data_len);
          if (copy) {
            memcpy(copy->s, data, data_len);
            proxy_cache->rsp_pdu->data_free = copy;
            proxy_cache->rsp_pdu->body_data = copy->s;
            proxy_cache->rsp_pdu->body_length = copy->length;
            proxy_cache->rsp_pdu->body_total = copy->length;
          } else {
            proxy_cache->rsp_pdu->body_data = NULL;
            proxy_cache->rsp_pdu->body_length = 0;
            proxy_cache->rsp_pdu->body_total = 0;
          }
        }
      }
    } else {
      /* The simple case */
      proxy_cache->rsp_pdu = coap_pdu_reference_lkd(rcvd);
    }
    option = coap_check_option(rcvd, COAP_OPTION_ETAG, &opt_iter);
    if (option) {
      proxy_cache->etag = coap_decode_var_bytes8(coap_opt_value(option),
                                                 coap_opt_length(option));
    } else {
      proxy_cache->etag = 0;
    }
    coap_ticks(&now);
    option = coap_check_option(rcvd, COAP_OPTION_MAXAGE, &opt_iter);
    if (option) {
      expire = coap_decode_var_bytes(coap_opt_value(option),
                                     coap_opt_length(option));
    } else {
      /* Default is 60 seconds */
      expire = 60;
    }
    proxy_cache->expire = now + expire * COAP_TICKS_PER_SECOND;

    /* Update all the cache listeners */
    LL_FOREACH(proxy_entry->proxy_req, proxy_req) {
      if (proxy_req->proxy_cache == proxy_cache) {
        if (!proxy_req->doing_observe) {
          coap_opt_t *req_obs;

          req_obs = coap_check_option(proxy_req->pdu, COAP_OPTION_OBSERVE, &opt_iter);
          if (req_obs &&
              coap_decode_var_bytes(coap_opt_value(req_obs),
                                    coap_opt_length(req_obs)) == COAP_OBSERVE_ESTABLISH) {
            proxy_req->doing_observe = 1;
            proxy_req->incoming->ref_proxy_subs++;
          }
        }
        coap_proxy_log_entry(proxy_req->incoming, proxy_req->pdu, proxy_req->token_used,  "rsp");
        token = coap_pdu_get_token(proxy_req->pdu);
        if (coap_proxy_call_response_handler(proxy_req->incoming, proxy_req->pdu,
                                             rcvd, &token,
                                             proxy_req, 0, 0) == COAP_RESPONSE_OK) {
          /* At least one success */
          ret = COAP_RESPONSE_OK;
        }
      }
    }
    goto finish;
  }
cache_fail:
  coap_proxy_log_entry(proxy_req->incoming, proxy_req->pdu, proxy_req->token_used,  "rspn");
  token = coap_pdu_get_token(proxy_req->pdu);
  ret = coap_proxy_call_response_handler(proxy_req->incoming, proxy_req->pdu,
                                         rcvd, &token, proxy_req, 0, 0);
  if (!obs_opt)
    coap_proxy_del_req(proxy_entry, proxy_req);

finish:
  if (ret == COAP_RESPONSE_FAIL && rcvd->type != COAP_MESSAGE_ACK) {
    coap_send_rst_lkd(session, rcvd);
    session->last_con_handler_res = COAP_RESPONSE_FAIL;
  } else {
    coap_send_ack_lkd(session, rcvd);
    session->last_con_handler_res = COAP_RESPONSE_OK;
  }
  coap_free_type(COAP_STRING, body_data);
}

/*
 */
coap_mid_t
coap_proxy_local_write(coap_session_t *session, coap_pdu_t *pdu) {
  coap_pdu_t *response = NULL;
  coap_resource_t *resource;
  coap_mid_t mid = COAP_INVALID_MID;

  resource = session->context->unknown_resource ?
             session->context->unknown_resource :
             session->context->proxy_uri_resource;
  if (!resource) {
    coap_log_err("coap_proxy_local_write: Unknown or Proxy resource not defined\n");
    goto fail;
  }

  response = coap_pdu_init(pdu->type == COAP_MESSAGE_CON ?
                           COAP_MESSAGE_ACK : COAP_MESSAGE_NON,
                           0, pdu->mid, coap_session_max_pdu_size_lkd(session));
  if (!response) {
    coap_log_err("coap_proxy_local_write: Could not create response PDU\n");
    goto fail;
  }
  response->session = session;

  if (!coap_add_token(response, pdu->actual_token.length,
                      pdu->actual_token.s)) {
    goto fail;
  }

  coap_log_debug("*  %s: internal: sent %4zd bytes\n",
                 coap_session_str(session),
                 pdu->used_size + coap_pdu_encode_header(pdu, session->proto));
  coap_show_pdu(COAP_LOG_DEBUG, pdu);

  mid = pdu->mid;
  if (!coap_proxy_forward_request_lkd(session, pdu, response, resource,
                                      NULL, session->server_list)) {
    coap_log_debug("coap_proxy_local_write: Failed to forward PDU\n");
    mid = COAP_INVALID_MID;
  }
fail:
  coap_delete_pdu_lkd(response);
  coap_delete_pdu_lkd(pdu);
  return mid;
}

COAP_API coap_session_t *
coap_new_client_session_proxy(coap_context_t *ctx,
                              coap_proxy_server_list_t *server_list) {
  coap_session_t *session;

  coap_lock_lock(return NULL);
  session = coap_new_client_session_proxy_lkd(ctx, server_list);
  coap_lock_unlock();
  return session;
}

coap_session_t *
coap_new_client_session_proxy_lkd(coap_context_t *ctx,
                                  coap_proxy_server_list_t *server_list) {
  coap_session_t *session;
  coap_addr_info_t *info_list = NULL;
  coap_str_const_t remote;

  coap_lock_check_locked();

#if COAP_IPV6_SUPPORT
  remote.s = (const uint8_t *)"::1";
#elif COAP_IPV4_SUPPORT
  remote.s = (const uint8_t *)"127.0.0.1";
#else /* !COAP_IPV6_SUPPORT && ! COAP_IPV4_SUPPORT */
  coap_log_warn("coap_new_client_session_proxy: No IPv4 or IPv6 support\n");
  return NULL;
#endif /* !COAP_IPV6_SUPPORT && ! COAP_IPV4_SUPPORT */
  remote.length = strlen((const char *)remote.s);
  /* resolve internal remote address where proxy session is 'connecting' to */
  info_list = coap_resolve_address_info(&remote, 0, 0, 0, 0,
                                        0,
                                        1 << COAP_URI_SCHEME_COAP,
                                        COAP_RESOLVE_TYPE_REMOTE);
  if (!info_list) {
    coap_log_warn("coap_new_client_session_proxy: Unable to resolve IP address\n");
    return NULL;
  }

  session = coap_new_client_session_lkd(ctx, NULL, &info_list->addr, COAP_PROTO_UDP);

  if (session) {
    session->server_list = server_list;
  }
  coap_free_address_info(info_list);
  return session;
}

void
coap_delete_proxy_subscriber(coap_session_t *session, coap_bin_const_t *token,
                             coap_mid_t mid, coap_proxy_subs_delete_t type) {
  /* Need to check is there is a proxy subscription active and delete it */
  coap_context_t *context = session->context;
  size_t i;

  for (i = 0; i < context->proxy_list_count; i++) {
    coap_proxy_list_t *proxy_entry = &context->proxy_list[i];
    coap_proxy_req_t *proxy_req, *treq;

    LL_FOREACH_SAFE(proxy_entry->proxy_req, proxy_req, treq) {
      if (proxy_req->incoming == session) {
        coap_bin_const_t req_token;
        int match = 0;

        req_token = coap_pdu_get_token(proxy_req->pdu);
        switch (type) {
        case COAP_PROXY_SUBS_ALL:
          match = 1;
          break;
        case COAP_PROXY_SUBS_TOKEN:
          if (token && coap_binary_equal(token, &req_token))
            match = 1;
          break;
        case COAP_PROXY_SUBS_MID:
          if (proxy_req->mid == mid)
            match = 1;
          break;
        default:
          break;
        }

        if (match && proxy_entry->proxy_req && ! proxy_entry->proxy_req->next &&
            proxy_req->token_used) {
          coap_binary_t tmp;

          coap_log_debug("coap_delete_proxy_subscriber: Using coap_cancel_observe() to do Proxy OBSERVE cancellation\n");
          /* Unfortunately need to change the ptr type to be r/w */
          memcpy(&tmp.s, &proxy_req->token_used->s, sizeof(tmp.s));
          tmp.length = proxy_req->token_used->length;
          coap_cancel_observe_lkd(proxy_entry->ongoing, &tmp, COAP_MESSAGE_CON);
        }
        coap_proxy_del_req(proxy_entry, proxy_req);
      }
    }
  }
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
