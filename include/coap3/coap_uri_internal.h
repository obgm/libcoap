/*
 * coap_uri_internal.h -- URI functions for libcoap
 *
 * Copyright (C) 2019--2026 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_uri_internal.h
 * @brief CoAP URI internal information
 */

#ifndef COAP_URI_INTERNAL_H_
#define COAP_URI_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup internal_api
 * @defgroup uri URI Support
 * Internal API for handling CoAP URIs
 * @{
 */

typedef struct {
  const char *name;         /**< scheme name */
  uint16_t port;            /**< default scheme port */
  uint16_t proxy_only;      /**< set if proxy support only */
  coap_uri_scheme_t scheme; /**< scheme */
} coap_uri_info_t;

typedef struct coap_upa_chain_t {
  struct coap_upa_chain_t *next; /**< Next entry in the chain */
  uint32_t upa_value;            /**< The Uri-Path-Abbrev option value */
  char *upa_path;                /**< The Uri-Path-Abbrev option path representation
                                     (withouot the leading '/') */
} coap_upa_chain_t;

extern coap_uri_info_t coap_uri_scheme[COAP_URI_SCHEME_LAST];
extern coap_upa_chain_t *coap_upa_client_fallback_chain;
extern coap_upa_chain_t *coap_upa_server_mapping_chain;

/**
 * Checks if path segment @p s consists of one or two dots.
 * Hex encoding %2e is also checked.
 *
 * @param s Start of data.
 * @param len length of data.
 *
 * @return @c 1 if single ., @c 2 if two .. else @c 0.
 */
int coap_check_dots(const uint8_t *s, size_t len);

/**
 * replace any % hex definitions with the actual character.
 *
 * @param optlist The optlist entry to modify if % hex definitions.
 *
 */
void coap_replace_percents(coap_optlist_t *optlist);

/**
 * Determine the expanded Uri-Path-Abbrev option value.
 *
 * @param chain Chain holding the information.
 * @param value The Uri-Path-Abbrev numeric value
 *
 * @return The expanded textual path or @c NULL if not found.
 */
const char *coap_map_abbrev_uri_path(coap_upa_chain_t *chain, uint32_t value);

/*
 * See if the specifiec path with length is on the UPA chain.
 *
 * @param chain The UPA chain to check against.
 * @param path  The URI path to match (without the leading /).
 * @param length The length of the URI path.
 * @param value The resoultant match value.
 *
 * @return 1 if a match, else 0.
 */
int coap_map_uri_path_abbrev(coap_upa_chain_t *chain, const char *path, size_t length,
                             uint32_t *value);

/**
 * Clean up a UPA chain.
 *
 * @param chain The chain to delete.
 */
void coap_delete_upa_chain(coap_upa_chain_t *chain);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* COAP_URI_INTERNAL_H_ */
