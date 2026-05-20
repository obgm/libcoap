/* Proxy fuzzer for libcoap.
 *
 * Drives coap_proxy_forward_request() with a fuzzer-controlled request PDU.
 * The proxy is configured forward-dynamic so the upstream target comes from
 * the request's Proxy-Uri or Proxy-Scheme+Uri-Host+Uri-Port options — the
 * attacker-controllable parsing surface inside coap_proxy.c.
 *
 * This harness drives:
 *   - coap_get_uri_proxy_scheme_info  (Proxy-Scheme + Uri-Host + Uri-Port)
 *   - coap_split_proxy_uri            (full URI string in Proxy-Uri)
 *   - coap_verify_proxy_scheme_supported
 *   - coap_proxy_get_session / coap_proxy_get_add_list_entry
 *   - coap_proxy_get_ongoing_session  (address resolution, session spawn)
 *   - coap_proxy_forward_request_lkd  (option mangling, PDU rewrite, send)
 *   - coap_proxy_log_entry
 *   - coap_proxy_release / coap_proxy_remove_association on cleanup
 *
 * Outbound UDP sockets to 127.0.0.1:0 quietly drop frames; no listener is
 * needed because the proxy doesn't block waiting for the upstream response.
 */

#include "coap3/coap_internal.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int
proxy_fuzz_event_handler(coap_session_t *session, const coap_event_t event) {
  (void)session;
  (void)event;
  return 0;
}

/* Required by coap_resource_proxy_uri_init2; we never forward a real response
 * back to a client so the handler body just sets a code and returns. */
static void
proxy_fuzz_handler(coap_resource_t *resource, coap_session_t *session,
                   const coap_pdu_t *request, const coap_string_t *query,
                   coap_pdu_t *response) {
  (void)resource;
  (void)session;
  (void)request;
  (void)query;
  response->code = COAP_RESPONSE_CODE(205);
}

/* Bounded cursor for slicing option values out of the fuzz buffer. */
typedef struct {
  const uint8_t *data;
  size_t size;
  size_t pos;
} proxy_cursor_t;

/* Take up to `max` bytes off the cursor. Returns the actual length written to
 * *out_len. May return zero. */
static const uint8_t *
proxy_take(proxy_cursor_t *c, size_t max, size_t *out_len) {
  size_t avail = c->size > c->pos ? c->size - c->pos : 0;
  size_t take = avail < max ? avail : max;
  const uint8_t *p = c->data + c->pos;
  c->pos += take;
  *out_len = take;
  return p;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* Need: mode byte + method byte + at least a few option-payload bytes. */
  if (size < 8)
    return 0;

  coap_context_t *ctx = NULL;
  coap_session_t *req_session = NULL;
  coap_resource_t *resource = NULL;
  coap_pdu_t *request = NULL;
  coap_pdu_t *response = NULL;
  coap_address_t addr;

  const uint8_t mode = data[0];
  const uint8_t method_byte = data[1];

  coap_startup();
  coap_set_log_level(COAP_LOG_EMERG);
  coap_dtls_set_log_level(COAP_LOG_EMERG);
  coap_debug_set_packet_loss("100%");
  coap_debug_set_packet_fail("100%");

  ctx = coap_new_context(NULL);
  if (!ctx)
    goto cleanup;
  coap_register_event_handler(ctx, proxy_fuzz_event_handler);

  /* Pick a proxy type from mode bits 2-4. Cover all three base types (static,
   * dynamic, reverse) crossed with the option-controlling bits that are
   * meaningful for each, per coap_proxy.h:
   *   0: FWD_STATIC                 — needs pre-populated server_list entry
   *   1: FWD_STATIC | STRIP         — static, strip proxy options on forward
   *   2: FWD_DYNAMIC               — pulls target from request's Proxy-* options
   *   3: FWD_DYNAMIC | STRIP        — same, strip proxy options (forces re-walk)
   *   4: FWD_DYNAMIC | MCAST        — allow multicast upstream resolution
   *   5: FWD_DYNAMIC | DYN_DEFINED  — no auto-added dynamic upstreams
   *   6: REV                        — reverse proxy, also uses server_list entry
   *   7: REV | STRIP                — reverse, strip proxy options
   * STRIP is the more interesting code path because it forces an option re-walk.
   */
  static const coap_proxy_t types[8] = {
    COAP_PROXY_FWD_STATIC,
    COAP_PROXY_FWD_STATIC | COAP_PROXY_BIT_STRIP,
    COAP_PROXY_FWD_DYNAMIC,
    COAP_PROXY_FWD_DYNAMIC | COAP_PROXY_BIT_STRIP,
    COAP_PROXY_FWD_DYNAMIC | COAP_PROXY_BIT_MCAST,
    COAP_PROXY_FWD_DYNAMIC | COAP_PROXY_DYN_DEFINED,
    COAP_PROXY_REV,
    COAP_PROXY_REV | COAP_PROXY_BIT_STRIP,
  };
  coap_proxy_t selected_type = types[(mode >> 2) & 0x07];

  /* Backing storage for a static server_list entry. coap_proxy_get_session
   * memcpys the entry into server_use, so stack storage is fine. */
  coap_proxy_server_t static_entry;
  memset(&static_entry, 0, sizeof(static_entry));
  static_entry.uri.scheme = COAP_URI_SCHEME_COAP;
  static_entry.uri.host.s = (const uint8_t *)"127.0.0.1";
  static_entry.uri.host.length = 9;
  static_entry.uri.port = 0; /* Picks something the OS will quietly drop. */

  coap_proxy_server_list_t server_list;
  memset(&server_list, 0, sizeof(server_list));
  server_list.type = selected_type;
  /* Match on the base type only (COAP_PROXY_NEW_MASK), so the STRIP/MCAST/
   * DYN_DEFINED option bits don't defeat the comparison — both FWD_STATIC and
   * REV (with or without those bits) need a pre-populated upstream entry. */
  coap_proxy_t base_type = selected_type & COAP_PROXY_NEW_MASK;
  if (base_type == COAP_PROXY_FWD_STATIC || base_type == COAP_PROXY_REV) {
    server_list.entry = &static_entry;
    server_list.entry_count = 1;
  }

  /* Build the "incoming client" session. We use UDP-to-loopback because UDP
   * doesn't connect — coap_new_client_session returns a fully-formed session
   * with no real network handshake. We won't actually transmit on it. */
  coap_address_init(&addr);
  addr.addr.sin.sin_family = AF_INET;
  addr.addr.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.addr.sin.sin_port = htons(5683);
  req_session = coap_new_client_session(ctx, NULL, &addr, COAP_PROTO_UDP);
  if (!req_session)
    goto cleanup;
  req_session->state = COAP_SESSION_STATE_ESTABLISHED;

  /* The proxy code uses `resource` to track which proxy URI resource the
   * request came in on. Use the official proxy-URI resource builder so flags
   * like `is_proxy_uri` are set, but with no host_name_list — we don't enforce
   * the host filter here. */
  resource = coap_resource_proxy_uri_init2(proxy_fuzz_handler, 0, NULL, 0);
  if (!resource)
    goto cleanup;
  coap_add_resource(ctx, resource);

  /* Build the request PDU. */
  const coap_pdu_code_t methods[8] = {
    COAP_REQUEST_CODE_GET,   COAP_REQUEST_CODE_POST,
    COAP_REQUEST_CODE_PUT,   COAP_REQUEST_CODE_DELETE,
    COAP_REQUEST_CODE_FETCH, COAP_REQUEST_CODE_PATCH,
    COAP_REQUEST_CODE_IPATCH, COAP_REQUEST_CODE_GET,
  };
  coap_pdu_type_t pdu_type = (mode & 0x01) ? COAP_MESSAGE_NON : COAP_MESSAGE_CON;
  size_t max_pdu = coap_session_max_pdu_size(req_session);
  request = coap_pdu_init(pdu_type, methods[method_byte & 0x07],
                          coap_new_message_id(req_session), max_pdu);
  if (!request)
    goto cleanup;

  /* Deterministic 4-byte token derived from the input keeps option-tracking
   * predictable across iterations without consuming the cursor's payload. */
  const uint8_t token[4] = { data[2], data[3], data[4], data[5] };
  coap_add_token(request, sizeof(token), token);

  /* Add options in monotonically increasing number order, since
   * coap_add_option doesn't reorder. Numbers below from coap_option.h:
   *   IF_MATCH=1  URI_HOST=3  URI_PORT=7  URI_PATH=11  PROXY_URI=35
   *   PROXY_SCHEME=39  SIZE1=60  ...
   */
  proxy_cursor_t c = { data + 6, size - 6, 0 };

  /* URI-Host (option 3). Pull a small slice — the proxy uses this together
   * with Proxy-Scheme to compute the upstream target. */
  {
    size_t n;
    const uint8_t *p = proxy_take(&c, 32, &n);
    if (n)
      coap_add_option(request, COAP_OPTION_URI_HOST, n, p);
  }

  /* URI-Port (option 7). 2 bytes max, encodes as a CoAP varint internally. */
  {
    size_t n;
    const uint8_t *p = proxy_take(&c, 2, &n);
    if (n)
      coap_add_option(request, COAP_OPTION_URI_PORT, n, p);
  }

  /* URI-Path (option 11) — a couple of segments to drive option-walk code. */
  for (int i = 0; i < 2; i++) {
    size_t n;
    const uint8_t *p = proxy_take(&c, 16, &n);
    if (n)
      coap_add_option(request, COAP_OPTION_URI_PATH, n, p);
  }

  /* Submode (bits 5-6 of mode) selects which proxy target option(s) we set:
   *   0: Proxy-Scheme only  — drives coap_get_uri_proxy_scheme_info
   *   1: Proxy-Uri only     — drives coap_split_proxy_uri
   *   2: both               — proxy code prefers Proxy-Uri but parses both
   *   3: neither            — exercises the "404 no proxy info" path
   */
  uint8_t submode = (mode >> 5) & 0x03;

  if (submode == 0 || submode == 2) {
    /* Proxy-Scheme value (option 39). The parser at coap_proxy.c:222-249
     * branches on opt_len 4/5/7/8/9 to identify "coap" / "coaps" / "coap+ws"
     * / "coap+tcp" / "coaps+tcp" — we want the fuzzer to discover those. */
    size_t n;
    const uint8_t *p = proxy_take(&c, 9, &n);
    if (n)
      coap_add_option(request, COAP_OPTION_PROXY_SCHEME, n, p);
  }
  if (submode == 1 || submode == 2) {
    /* Proxy-Uri value (option 35). Up to 1034 bytes per RFC 7252 — we cap at
     * 256 to leave room for payload. The parser is coap_split_proxy_uri. */
    size_t n;
    const uint8_t *p = proxy_take(&c, 256, &n);
    if (n)
      coap_add_option(request, COAP_OPTION_PROXY_URI, n, p);
  }

  /* Optional Observe option (bit 7 of mode, 4 bytes max). Triggers the proxy's
   * observe-cache logic if a proxy_response_cb were registered. */
  if ((mode >> 7) & 0x01) {
    size_t n;
    const uint8_t *p = proxy_take(&c, 4, &n);
    if (n)
      coap_add_option(request, COAP_OPTION_OBSERVE, n, p);
  }

  /* Remaining bytes become the request body. */
  {
    size_t n;
    const uint8_t *p = proxy_take(&c, c.size > c.pos ? c.size - c.pos : 0, &n);
    if (n)
      coap_add_data(request, n, p);
  }

  /* Response PDU the proxy fills in (with an error code on failure). */
  response = coap_pdu_init(COAP_MESSAGE_ACK, 0,
                           coap_new_message_id(req_session), max_pdu);
  if (!response)
    goto cleanup;

  /* The single API call we're here to fuzz. */
  coap_proxy_forward_request(req_session, request, response, resource, NULL,
                             &server_list);

cleanup:
  if (request)
    coap_delete_pdu(request);
  if (response)
    coap_delete_pdu(response);
  /* Don't release req_session manually — coap_free_context iterates
   * ctx->sessions and releases each (same idiom as the other harnesses). */
  if (ctx)
    coap_free_context(ctx);
  coap_cleanup();
  return 0;
}
