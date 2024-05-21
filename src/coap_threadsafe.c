/* coap_threadsafe.c -- Thread safe function locking wrappers
 *
 * Copyright (C) 2023-2024 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file coap_threadsafe.c
 * @brief CoAP multithreading safe functions
 */

/*
 * Public API functions are being migrated across to just ahead of where
 * the _locked() functions are for ease of maintenance, debugging and
 * documentation.
 *
 * The internal equivalent of the public API function will get _locked appended
 * to the function name, and all calls to this function within the libcoap
 * library have the function updated with the _locked suffix. Appropriate
 * entries for this function are removed from coap_threadsafe_internal.h.
 */
#include "coap_config.h"

#if COAP_THREAD_SAFE
#define COAP_THREAD_IGNORE_LOCKED_MAPPING

#include "coap3/coap_internal.h"

#if COAP_CLIENT_SUPPORT

/* Client only wrapper functions */

coap_session_t *
coap_new_client_session(coap_context_t *ctx,
                        const coap_address_t *local_if,
                        const coap_address_t *server,
                        coap_proto_t proto) {
  coap_session_t *session;

  coap_lock_lock(ctx, return NULL);
  session = coap_new_client_session_locked(ctx, local_if, server, proto);
  coap_lock_unlock(ctx);
  return session;
}


coap_session_t *
coap_new_client_session_oscore(coap_context_t *ctx,
                               const coap_address_t *local_if,
                               const coap_address_t *server,
                               coap_proto_t proto,
                               coap_oscore_conf_t *oscore_conf) {
  coap_session_t *session;

  coap_lock_lock(ctx, return NULL);
  session = coap_new_client_session_oscore_locked(ctx, local_if, server, proto, oscore_conf);
  coap_lock_unlock(ctx);
  return session;
}

coap_session_t *
coap_new_client_session_oscore_pki(coap_context_t *ctx,
                                   const coap_address_t *local_if,
                                   const coap_address_t *server,
                                   coap_proto_t proto,
                                   coap_dtls_pki_t *pki_data,
                                   coap_oscore_conf_t *oscore_conf) {
  coap_session_t *session;

  coap_lock_lock(ctx, return NULL);
  session = coap_new_client_session_oscore_pki_locked(ctx, local_if, server, proto, pki_data,
                                                      oscore_conf);
  coap_lock_unlock(ctx);
  return session;
}

coap_session_t *
coap_new_client_session_oscore_psk(coap_context_t *ctx,
                                   const coap_address_t *local_if,
                                   const coap_address_t *server,
                                   coap_proto_t proto,
                                   coap_dtls_cpsk_t *psk_data,
                                   coap_oscore_conf_t *oscore_conf) {
  coap_session_t *session;

  coap_lock_lock(ctx, return NULL);
  session = coap_new_client_session_oscore_psk_locked(ctx, local_if, server, proto, psk_data,
                                                      oscore_conf);
  coap_lock_unlock(ctx);
  return session;
}

coap_session_t *
coap_new_client_session_pki(coap_context_t *ctx,
                            const coap_address_t *local_if,
                            const coap_address_t *server,
                            coap_proto_t proto,
                            coap_dtls_pki_t *setup_data) {
  coap_session_t *session;

  coap_lock_lock(ctx, return NULL);
  session = coap_new_client_session_pki_locked(ctx, local_if, server, proto, setup_data);
  coap_lock_unlock(ctx);
  return session;
}

coap_session_t *
coap_new_client_session_psk(coap_context_t *ctx,
                            const coap_address_t *local_if,
                            const coap_address_t *server,
                            coap_proto_t proto, const char *identity,
                            const uint8_t *key, unsigned key_len) {
  coap_session_t *session;

  coap_lock_lock(ctx, return NULL);
  session = coap_new_client_session_psk_locked(ctx, local_if, server, proto, identity, key, key_len);
  coap_lock_unlock(ctx);
  return session;
}

coap_session_t *
coap_new_client_session_psk2(coap_context_t *ctx,
                             const coap_address_t *local_if,
                             const coap_address_t *server,
                             coap_proto_t proto,
                             coap_dtls_cpsk_t *setup_data) {
  coap_session_t *session;

  coap_lock_lock(ctx, return NULL);
  session = coap_new_client_session_psk2_locked(ctx, local_if, server, proto, setup_data);
  coap_lock_unlock(ctx);
  return session;
}
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT

/* Server only wrapper functions */

int
coap_context_oscore_server(coap_context_t *context,
                           coap_oscore_conf_t *oscore_conf) {
  int ret;

  coap_lock_lock(context, return 0);
  ret = coap_context_oscore_server_locked(context, oscore_conf);
  coap_lock_unlock(context);
  return ret;
}

int
coap_context_set_pki(coap_context_t *ctx,
                     const coap_dtls_pki_t *setup_data) {
  int ret;

  coap_lock_lock(ctx, return 0);
  ret = coap_context_set_pki_locked(ctx, setup_data);
  coap_lock_unlock(ctx);
  return ret;
}

int
coap_context_set_psk(coap_context_t *ctx,
                     const char *hint,
                     const uint8_t *key,
                     size_t key_len) {
  int ret;

  coap_lock_lock(ctx, return 0);
  ret = coap_context_set_psk_locked(ctx, hint, key, key_len);
  coap_lock_unlock(ctx);
  return ret;
}

int
coap_context_set_psk2(coap_context_t *ctx, coap_dtls_spsk_t *setup_data) {
  int ret;

  coap_lock_lock(ctx, return 0);
  ret = coap_context_set_psk2_locked(ctx, setup_data);
  coap_lock_unlock(ctx);
  return ret;
}

void
coap_free_endpoint(coap_endpoint_t *ep) {
  if (ep) {
    coap_context_t *context = ep->context;
    if (context)
      coap_lock_lock(context, return);
    coap_free_endpoint_locked(ep);
    if (context)
      coap_lock_unlock(context);
  }
}

int
coap_join_mcast_group_intf(coap_context_t *ctx, const char *group_name,
                           const char *ifname) {
  int ret;

  coap_lock_lock(ctx, return -1);
  ret = coap_join_mcast_group_intf_locked(ctx, group_name, ifname);
  coap_lock_unlock(ctx);
  return ret;
}

coap_endpoint_t *
coap_new_endpoint(coap_context_t *context, const coap_address_t *listen_addr, coap_proto_t proto) {
  coap_endpoint_t *endpoint;

  coap_lock_lock(context, return NULL);
  endpoint = coap_new_endpoint_locked(context, listen_addr, proto);
  coap_lock_unlock(context);
  return endpoint;
}

coap_subscription_t *
coap_persist_observe_add(coap_context_t *context,
                         coap_proto_t e_proto,
                         const coap_address_t *e_listen_addr,
                         const coap_addr_tuple_t *s_addr_info,
                         const coap_bin_const_t *raw_packet,
                         const coap_bin_const_t *oscore_info) {
  coap_subscription_t *subs;

  coap_lock_lock(context, return NULL);
  subs = coap_persist_observe_add_locked(context,
                                         e_proto,
                                         e_listen_addr,
                                         s_addr_info,
                                         raw_packet,
                                         oscore_info);
  coap_lock_unlock(context);
  return subs;
}

int
coap_persist_startup(coap_context_t *context,
                     const char *dyn_resource_save_file,
                     const char *observe_save_file,
                     const char *obs_cnt_save_file,
                     uint32_t save_freq) {
  int ret;

  coap_lock_lock(context, return 0);
  ret = coap_persist_startup_locked(context,
                                    dyn_resource_save_file,
                                    observe_save_file,
                                    obs_cnt_save_file,
                                    save_freq);
  coap_lock_unlock(context);
  return ret;
}

void
coap_persist_stop(coap_context_t *context) {
  if (!context)
    return;
  coap_lock_lock(context, return);
  coap_persist_stop_locked(context);
  coap_lock_unlock(context);
}

#endif /* COAP_SERVER_SUPPORT */

/* Both Client and Server wrapper functions */

void
coap_context_set_block_mode(coap_context_t *context,
                            uint32_t block_mode) {
  coap_lock_lock(context, return);
  coap_context_set_block_mode_locked(context, block_mode);
  coap_lock_unlock(context);
}

int
coap_context_set_max_block_size(coap_context_t *context,
                                size_t max_block_size) {
  int ret;

  coap_lock_lock(context, return 0);
  ret = coap_context_set_max_block_size_locked(context, max_block_size);
  coap_lock_unlock(context);
  return ret;
}

int
coap_context_set_pki_root_cas(coap_context_t *ctx,
                              const char *ca_file,
                              const char *ca_dir) {
  int ret;

  coap_lock_lock(ctx, return 0);
  ret = coap_context_set_pki_root_cas_locked(ctx, ca_file, ca_dir);
  coap_lock_unlock(ctx);
  return ret;
}

int
coap_delete_oscore_recipient(coap_context_t *context,
                             coap_bin_const_t *recipient_id) {
  int ret;

  if (!context || !recipient_id)
    return 0;
  coap_lock_lock(context, return 0);
  ret = coap_delete_oscore_recipient_locked(context, recipient_id);
  coap_lock_unlock(context);
  return ret;
}

uint16_t
coap_new_message_id(coap_session_t *session) {
  uint16_t mid;

  coap_lock_lock(session->context, return 0);
  mid = coap_new_message_id_locked(session);
  coap_lock_unlock(session->context);
  return mid;
}

int
coap_new_oscore_recipient(coap_context_t *context,
                          coap_bin_const_t *recipient_id) {
  int ret;

  coap_lock_lock(context, return 0);
  ret = coap_new_oscore_recipient_locked(context, recipient_id);
  coap_lock_unlock(context);
  return ret;
}

coap_pdu_t *
coap_new_pdu(coap_pdu_type_t type, coap_pdu_code_t code,
             coap_session_t *session) {
  coap_pdu_t *pdu;

  coap_lock_lock(session->context, return NULL);
  pdu = coap_new_pdu_locked(type, code, session);
  coap_lock_unlock(session->context);
  return pdu;
}

coap_pdu_t *
coap_pdu_duplicate(const coap_pdu_t *old_pdu,
                   coap_session_t *session,
                   size_t token_length,
                   const uint8_t *token,
                   coap_opt_filter_t *drop_options) {
  coap_pdu_t *new_pdu;

  coap_lock_lock(session->context, return NULL);
  new_pdu = coap_pdu_duplicate_locked(old_pdu,
                                      session,
                                      token_length,
                                      token,
                                      drop_options);
  coap_lock_unlock(session->context);
  return new_pdu;
}


void
coap_register_option(coap_context_t *ctx, uint16_t type) {
  coap_lock_lock(ctx, return);
  coap_register_option_locked(ctx, type);
  coap_lock_unlock(ctx);
}

coap_mid_t
coap_send(coap_session_t *session, coap_pdu_t *pdu) {
  coap_mid_t mid;

  coap_lock_lock(session->context, return COAP_INVALID_MID);
  mid = coap_send_locked(session, pdu);
  coap_lock_unlock(session->context);
  return mid;
}

coap_mid_t
coap_send_ack(coap_session_t *session, const coap_pdu_t *request) {
  coap_mid_t mid;

  coap_lock_lock(session->context, return COAP_INVALID_MID);
  mid = coap_send_ack_locked(session, request);
  coap_lock_unlock(session->context);
  return mid;
}

coap_mid_t
coap_send_error(coap_session_t *session,
                const coap_pdu_t *request,
                coap_pdu_code_t code,
                coap_opt_filter_t *opts) {
  coap_mid_t mid;

  coap_lock_lock(session->context, return COAP_INVALID_MID);
  mid = coap_send_error_locked(session, request, code, opts);
  coap_lock_unlock(session->context);
  return mid;
}


coap_mid_t
coap_send_message_type(coap_session_t *session, const coap_pdu_t *request,
                       coap_pdu_type_t type) {
  coap_mid_t mid;

  coap_lock_lock(session->context, return COAP_INVALID_MID);
  mid = coap_send_message_type_locked(session, request, type);
  coap_lock_unlock(session->context);
  return mid;
}

coap_mid_t
coap_send_rst(coap_session_t *session, const coap_pdu_t *request) {
  coap_mid_t mid;

  coap_lock_lock(session->context, return COAP_INVALID_MID);
  mid = coap_send_rst_locked(session, request);
  coap_lock_unlock(session->context);
  return mid;
}

void
coap_session_disconnected(coap_session_t *session, coap_nack_reason_t reason) {
  coap_lock_lock(session->context, return);
  coap_session_disconnected_locked(session, reason);
  coap_lock_unlock(session->context);
}

size_t
coap_session_max_pdu_size(const coap_session_t *session) {
  size_t size;
  coap_session_t *session_rw;

  /*
   * Need to do this to not get a compiler warning about const parameters
   * but need to maintain source code backward compatibility
   */
  memcpy(&session_rw, &session, sizeof(session_rw));
  coap_lock_lock(session_rw->context, return 0);
  size = coap_session_max_pdu_size_locked(session_rw);
  coap_lock_unlock(session_rw->context);
  return size;
}

coap_session_t *
coap_session_reference(coap_session_t *session) {
  coap_lock_lock(session->context, return NULL);
  coap_session_reference_locked(session);
  coap_lock_unlock(session->context);
  return session;
}

void
coap_session_release(coap_session_t *session) {
  if (session) {
    coap_context_t *context = session->context;

    coap_lock_lock(context, return);
    coap_session_release_locked(session);
    coap_lock_unlock(context);
  }
}

coap_mid_t
coap_session_send_ping(coap_session_t *session) {
  coap_mid_t mid;

  coap_lock_lock(session->context, return COAP_INVALID_MID);
  mid = coap_session_send_ping_locked(session);
  coap_lock_unlock(session->context);
  return mid;
}

#if COAP_THREAD_RECURSIVE_CHECK
void
coap_lock_unlock_func(coap_lock_t *lock, const char *file, int line) {
  assert(coap_thread_pid == lock->pid);
  if (lock->in_callback) {
    assert(lock->lock_count > 0);
    lock->lock_count--;
  } else {
    lock->pid = 0;
    lock->unlock_file = file;
    lock->unlock_line = line;
    coap_mutex_unlock(&lock->mutex);
  }
}

int
coap_lock_lock_func(coap_lock_t *lock, const char *file, int line) {
  if (coap_mutex_trylock(&lock->mutex)) {
    if (coap_thread_pid == lock->pid) {
      /* This thread locked the mutex */
      if (lock->in_callback) {
        /* This is called from within an app callback */
        lock->lock_count++;
        assert(lock->in_callback == lock->lock_count);
        goto being_freed_check;
      } else {
        coap_log_alert("Thread Deadlock: Last %s: %u, this %s: %u\n",
                       lock->lock_file, lock->lock_line, file, line);
        assert(0);
      }
    }
    /* Wait for the other thread to unlock */
    coap_mutex_lock(&lock->mutex);
  }
  lock->pid = coap_thread_pid;
  lock->lock_file = file;
  lock->lock_line = line;
  if (lock->in_callback) {
    /* This is when called from within an app callback and context is going away */
    lock->lock_count++;
    assert(lock->in_callback == lock->lock_count);
  }
being_freed_check:
  if (lock->being_freed) {
    /* context is in the process of being deleted */
    coap_lock_unlock_func(lock, file, line);
    return 0;
  }
  return 1;
}

#else /* ! COAP_THREAD_RECURSIVE_CHECK */

void
coap_lock_unlock_func(coap_lock_t *lock) {
  assert(coap_thread_pid == lock->pid);
  if (lock->in_callback) {
    assert(lock->lock_count > 0);
    lock->lock_count--;
  } else {
    lock->pid = 0;
    coap_mutex_unlock(&lock->mutex);
  }
}

int
coap_lock_lock_func(coap_lock_t *lock) {
  /*
   * Some OS do not have support for coap_mutex_trylock() so
   * cannot use that here and have to rely on lock-pid being stable
   */
  if (lock->in_callback && coap_thread_pid == lock->pid) {
    if (lock->being_freed) {
      return 0;
    }
    lock->lock_count++;
    assert(lock->in_callback == lock->lock_count);
  } else {
    coap_mutex_lock(&lock->mutex);
    lock->pid = coap_thread_pid;
    if (lock->in_callback) {
      /* This is when called from within an app callback and context is going away */
      lock->lock_count++;
      assert(lock->in_callback == lock->lock_count);
    }
    if (lock->being_freed) {
      coap_lock_unlock_func(lock);
      return 0;
    }
  }
  return 1;
}
#endif /* ! COAP_THREAD_RECURSIVE_CHECK */

#else /* ! COAP_THREAD_SAFE */

#ifdef __clang__
/* Make compilers happy that do not like empty modules. As this function is
 * never used, we ignore -Wunused-function at the end of compiling this file
 */
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
static inline void
dummy(void) {
}

#endif /* ! COAP_THREAD_SAFE */
