/*
 * coap_forward_decls.h -- Forward declarations of structures that are
 * opaque to application programming that use libcoap.
 *
 * Copyright (C) 2019 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_forward_decls.h
 * @brief COAP forward definitions
 */

#ifndef COAP_FORWARD_DECLS_H_
#define COAP_FORWARD_DECLS_H_

/*
 * Define the forward declations for the structures (even non-opaque)
 * so that applications (using coap.h) as well as libcoap builds
 * can reference them (and makes .h file dependencies a lot simpler).
 */
struct coap_cache_entry_t;
struct coap_cache_key_t;
struct coap_address_t;
struct coap_bin_const_t;
struct coap_context_t;
struct coap_dtls_pki_t;
struct coap_packet_t;
struct coap_pdu_t;
struct coap_queue_t;
struct coap_resource_t;
struct coap_session_t;
struct coap_str_const_t;
struct coap_string_t;

/*
 * typedef all the opaque structures that are defined in coap_*_internal.h
 */

/* ************* coap_cache_internal.h ***************** */

/** Cache Entry information */
typedef struct coap_cache_entry_t coap_cache_entry_t;
typedef struct coap_cache_key_t coap_cache_key_t;

/* ************* coap_session_internal.h ***************** */

/**
 * Abstraction of virtual endpoint that can be attached to coap_context_t.
 */
typedef struct coap_endpoint_t coap_endpoint_t;

/* ************* coap_subscribe_internal.h ***************** */

/**
 * Subscriber information
 */
typedef struct coap_subscription_t coap_subscription_t;

#endif /* COAP_FORWARD_DECLS_H_ */
