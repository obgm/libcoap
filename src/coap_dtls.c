/*
 * coap_dtls.c -- (D)TLS functions for libcoap
 *
 * Copyright (C) 2023-2024 Olaf Bergmann <bergmann@tzi.org>
 * Copyright (C) 2023-2024 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_dtls.c
 * @brief CoAP (D)TLS handling functions
 */

#include "coap3/coap_libcoap_build.h"

#ifdef _WIN32
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#endif

void
coap_dtls_map_key_type_to_define(const coap_dtls_pki_t *setup_data, coap_dtls_key_t *key) {
  *key = setup_data->pki_key;

  switch (key->key_type) {
  case COAP_PKI_KEY_PEM:
    key->key_type = COAP_PKI_KEY_DEFINE;
    key->key.define.ca.s_byte = setup_data->pki_key.key.pem.ca_file;
    key->key.define.public_cert.s_byte = setup_data->pki_key.key.pem.public_cert;
    key->key.define.private_key.s_byte = setup_data->pki_key.key.pem.private_key;

    key->key.define.public_cert_def = COAP_PKI_KEY_DEF_PEM;
    key->key.define.private_key_def = COAP_PKI_KEY_DEF_PEM;
    key->key.define.ca_def = COAP_PKI_KEY_DEF_PEM;
    break;
  case COAP_PKI_KEY_ASN1:
    key->key_type = COAP_PKI_KEY_DEFINE;
    key->key.define.ca.u_byte = setup_data->pki_key.key.asn1.ca_cert;
    key->key.define.public_cert.u_byte = setup_data->pki_key.key.asn1.public_cert;
    key->key.define.private_key.u_byte = setup_data->pki_key.key.asn1.private_key;

    key->key.define.ca_len = setup_data->pki_key.key.asn1.ca_cert_len;
    key->key.define.public_cert_len = setup_data->pki_key.key.asn1.public_cert_len;
    key->key.define.private_key_len = setup_data->pki_key.key.asn1.private_key_len;

    key->key.define.private_key_type = setup_data->pki_key.key.asn1.private_key_type;

    key->key.define.public_cert_def = COAP_PKI_KEY_DEF_DER_BUF;
    key->key.define.private_key_def = COAP_PKI_KEY_DEF_DER_BUF;
    key->key.define.ca_def = COAP_PKI_KEY_DEF_DER_BUF;
    break;
  case COAP_PKI_KEY_PEM_BUF:
    key->key_type = COAP_PKI_KEY_DEFINE;
    key->key.define.ca.u_byte = setup_data->pki_key.key.pem_buf.ca_cert;
    key->key.define.public_cert.u_byte = setup_data->pki_key.key.pem_buf.public_cert;
    key->key.define.private_key.u_byte = setup_data->pki_key.key.pem_buf.private_key;

    key->key.define.ca_len = setup_data->pki_key.key.pem_buf.ca_cert_len;
    key->key.define.public_cert_len = setup_data->pki_key.key.pem_buf.public_cert_len;
    key->key.define.private_key_len = setup_data->pki_key.key.pem_buf.private_key_len;

    if (setup_data->is_rpk_not_cert) {
      key->key.define.public_cert_def = COAP_PKI_KEY_DEF_RPK_BUF;
    } else {
      key->key.define.public_cert_def = COAP_PKI_KEY_DEF_PEM_BUF;
    }
    if (setup_data->is_rpk_not_cert) {
      key->key.define.private_key_def = COAP_PKI_KEY_DEF_RPK_BUF;
    } else {
      key->key.define.private_key_def = COAP_PKI_KEY_DEF_PEM_BUF;
    }
    if (setup_data->is_rpk_not_cert) {
      key->key.define.ca_def = COAP_PKI_KEY_DEF_RPK_BUF;
    } else {
      key->key.define.ca_def = COAP_PKI_KEY_DEF_PEM_BUF;
    }
    break;
  case COAP_PKI_KEY_PKCS11:
    key->key_type = COAP_PKI_KEY_DEFINE;
    key->key.define.ca.s_byte = setup_data->pki_key.key.pkcs11.ca;
    key->key.define.public_cert.s_byte = setup_data->pki_key.key.pkcs11.public_cert;
    key->key.define.private_key.s_byte = setup_data->pki_key.key.pkcs11.private_key;

    key->key.define.user_pin = setup_data->pki_key.key.pkcs11.user_pin;

    if (strncasecmp(key->key.pkcs11.ca, "pkcs11:", 7) == 0) {
      if (setup_data->is_rpk_not_cert) {
        key->key.define.ca_def = COAP_PKI_KEY_DEF_PKCS11_RPK;
      } else {
        key->key.define.ca_def = COAP_PKI_KEY_DEF_PKCS11;
      }
    } else {
      if (setup_data->is_rpk_not_cert) {
        key->key.define.ca_def = COAP_PKI_KEY_DEF_RPK_BUF;
      } else {
        key->key.define.ca_def = COAP_PKI_KEY_DEF_DER;
      }
    }
    if (strncasecmp(key->key.pkcs11.public_cert, "pkcs11:", 7) == 0) {
      if (setup_data->is_rpk_not_cert) {
        key->key.define.public_cert_def = COAP_PKI_KEY_DEF_PKCS11_RPK;
      } else {
        key->key.define.public_cert_def = COAP_PKI_KEY_DEF_PKCS11;
      }
    } else {
      if (setup_data->is_rpk_not_cert) {
        key->key.define.public_cert_def = COAP_PKI_KEY_DEF_RPK_BUF;
      } else {
        key->key.define.public_cert_def = COAP_PKI_KEY_DEF_DER;
      }
    }
    if (strncasecmp(key->key.pkcs11.private_key, "pkcs11:", 7) == 0) {
      if (setup_data->is_rpk_not_cert) {
        key->key.define.private_key_def = COAP_PKI_KEY_DEF_PKCS11_RPK;
      } else {
        key->key.define.private_key_def = COAP_PKI_KEY_DEF_PKCS11;
      }
    } else {
      if (setup_data->is_rpk_not_cert) {
        key->key.define.private_key_def = COAP_PKI_KEY_DEF_RPK_BUF;
      } else {
        key->key.define.private_key_def = COAP_PKI_KEY_DEF_DER;
      }
    }
    break;
  case COAP_PKI_KEY_DEFINE:
    /* Already configured */
    break;
  default:
    break;
  }
}

#if (COAP_MAX_LOGGING_LEVEL >= _COAP_LOG_ERR)
static const char *
coap_dtls_get_define_type(coap_pki_define_t def, coap_const_char_ptr_t name) {
  switch (def) {
  case COAP_PKI_KEY_DEF_PEM:
    return name.s_byte;
  case COAP_PKI_KEY_DEF_PEM_BUF:
    return "PEM_BUF";
  case COAP_PKI_KEY_DEF_RPK_BUF:
    return "RPK_BUF";
  case COAP_PKI_KEY_DEF_DER:
    return name.s_byte;
  case COAP_PKI_KEY_DEF_DER_BUF:
    return "DER_BUF";
  case COAP_PKI_KEY_DEF_PKCS11:
    return name.s_byte;
  case COAP_PKI_KEY_DEF_PKCS11_RPK:
    return name.s_byte;
  case COAP_PKI_KEY_DEF_ENGINE:
    return name.s_byte;
  default:
    return "???";
  }
}
#endif /* COAP_MAX_LOGGING_LEVEL >= _COAP_LOG_ERR */

int
coap_dtls_define_issue(coap_define_issue_key_t type, coap_define_issue_fail_t fail,
                       coap_dtls_key_t *key, const coap_dtls_role_t role, int ret) {
#if (COAP_MAX_LOGGING_LEVEL >= _COAP_LOG_ERR)
  coap_pki_key_define_t define = key->key.define;
  switch (type) {
  case COAP_DEFINE_KEY_CA:
    switch (fail) {
    case COAP_DEFINE_FAIL_BAD:
      coap_log_warn("*** setup_pki: (D)TLS: %s: %s CA configure failure\n",
                    coap_dtls_get_define_type(define.ca_def, define.ca),
                    role == COAP_DTLS_ROLE_SERVER ? "Server" : "Client");
      break;
    case COAP_DEFINE_FAIL_NOT_SUPPORTED:
      coap_log_err("*** setup_pki: (D)TLS: %s: %s CA type not supported\n",
                   coap_dtls_get_define_type(define.ca_def, define.ca),
                   role == COAP_DTLS_ROLE_SERVER ? "Server" : "Client");
      break;
    case COAP_DEFINE_FAIL_NONE:
      coap_log_err("*** setup_pki: (D)TLS: %s: %s CA not defined\n",
                   coap_dtls_get_define_type(define.ca_def, define.ca),
                   role == COAP_DTLS_ROLE_SERVER ? "Server" : "Client");
      break;
    default:
      break;
    }
    break;
  case COAP_DEFINE_KEY_ROOT_CA:
    switch (fail) {
    case COAP_DEFINE_FAIL_BAD:
      coap_log_warn("*** setup_pki: (D)TLS: %s: %s Root CA configure failure\n",
                    coap_dtls_get_define_type(define.ca_def, define.ca),
                    role == COAP_DTLS_ROLE_SERVER ? "Server" : "Client");
      break;
    case COAP_DEFINE_FAIL_NOT_SUPPORTED:
      coap_log_err("*** setup_pki: (D)TLS: %s: %s Root CA type not supported\n",
                   coap_dtls_get_define_type(define.ca_def, define.ca),
                   role == COAP_DTLS_ROLE_SERVER ? "Server" : "Client");
      break;
    case COAP_DEFINE_FAIL_NONE:
      coap_log_err("*** setup_pki: (D)TLS: %s: %s Root CA not defined\n",
                   coap_dtls_get_define_type(define.ca_def, define.ca),
                   role == COAP_DTLS_ROLE_SERVER ? "Server" : "Client");
      break;
    default:
      break;
    }
    break;
  case COAP_DEFINE_KEY_PUBLIC:
    switch (fail) {
    case COAP_DEFINE_FAIL_BAD:
      coap_log_warn("*** setup_pki: (D)TLS: %s: %s Certificate configure failure\n",
                    coap_dtls_get_define_type(define.public_cert_def, define.public_cert),
                    role == COAP_DTLS_ROLE_SERVER ? "Server" : "Client");
      break;
    case COAP_DEFINE_FAIL_NOT_SUPPORTED:
      coap_log_err("*** setup_pki: (D)TLS: %s: %s Certificate type not supported\n",
                   coap_dtls_get_define_type(define.public_cert_def, define.public_cert),
                   role == COAP_DTLS_ROLE_SERVER ? "Server" : "Client");
      break;
    case COAP_DEFINE_FAIL_NONE:
      coap_log_err("*** setup_pki: (D)TLS: %s: %s Certificate not defined\n",
                   coap_dtls_get_define_type(define.public_cert_def, define.public_cert),
                   role == COAP_DTLS_ROLE_SERVER ? "Server" : "Client");
      break;
    default:
      break;
    }
    break;
  case COAP_DEFINE_KEY_PRIVATE:
    switch (fail) {
    case COAP_DEFINE_FAIL_BAD:
      coap_log_warn("*** setup_pki: (D)TLS: %s: %s Private Key configure failure\n",
                    coap_dtls_get_define_type(define.private_key_def, define.private_key),
                    role == COAP_DTLS_ROLE_SERVER ? "Server" : "Client");
      break;
    case COAP_DEFINE_FAIL_NOT_SUPPORTED:
      coap_log_err("*** setup_pki: (D)TLS: %s: %s Private Key type not supported\n",
                   coap_dtls_get_define_type(define.private_key_def, define.private_key),
                   role == COAP_DTLS_ROLE_SERVER ? "Server" : "Client");
      break;
    case COAP_DEFINE_FAIL_NONE:
      coap_log_err("*** setup_pki: (D)TLS: %s: %s Private Key not defined\n",
                   coap_dtls_get_define_type(define.private_key_def, define.private_key),
                   role == COAP_DTLS_ROLE_SERVER ? "Server" : "Client");
      break;
    default:
      break;
    }
  default:
    break;
  }
#else /* COAP_MAX_LOGGING_LEVEL >= _COAP_LOG_ERR */
  (void)type;
  (void)fail;
  (void)key;
  (void)role;
#endif /* COAP_MAX_LOGGING_LEVEL < _COAP_LOG_ERR */
  return ret;
}

void
coap_dtls_establish(coap_session_t *session) {
  session->state = COAP_SESSION_STATE_HANDSHAKE;
#if COAP_CLIENT_SUPPORT
  if (session->type == COAP_SESSION_TYPE_CLIENT)
    session->tls = coap_dtls_new_client_session(session);
#endif /* COAP_CLIENT_SUPPORT */
#if COAP_SERVER_SUPPORT
  if (session->type != COAP_SESSION_TYPE_CLIENT)
    session->tls = coap_dtls_new_server_session(session);
#endif /* COAP_SERVER_SUPPORT */

  if (!session->tls) {
    coap_session_disconnected_lkd(session, COAP_NACK_TLS_LAYER_FAILED);
    return;
  }
  coap_ticks(&session->last_rx_tx);
}

void
coap_dtls_close(coap_session_t *session) {
  if (session->tls) {
    coap_dtls_free_session(session);
    session->tls = NULL;
  }
  session->sock.lfunc[COAP_LAYER_TLS].l_close(session);
}

#if !COAP_DISABLE_TCP
void
coap_tls_establish(coap_session_t *session) {
  session->state = COAP_SESSION_STATE_HANDSHAKE;
#if COAP_CLIENT_SUPPORT
  if (session->type == COAP_SESSION_TYPE_CLIENT)
    session->tls = coap_tls_new_client_session(session);
#endif /* COAP_CLIENT_SUPPORT */
#if COAP_SERVER_SUPPORT
  if (session->type != COAP_SESSION_TYPE_CLIENT)
    session->tls = coap_tls_new_server_session(session);
#endif /* COAP_SERVER_SUPPORT */

  if (!session->tls) {
    coap_session_disconnected_lkd(session, COAP_NACK_TLS_LAYER_FAILED);
    return;
  }
  coap_ticks(&session->last_rx_tx);
}

void
coap_tls_close(coap_session_t *session) {
  if (session->tls) {
    coap_tls_free_session(session);
    session->tls = NULL;
  }
  session->sock.lfunc[COAP_LAYER_TLS].l_close(session);
}
#endif /* !COAP_DISABLE_TCP */
