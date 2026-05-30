/* WebSocket layer fuzzer for libcoap.
 *
 * Targets coap_ws.c: the HTTP Upgrade handshake parser
 * (coap_ws_rd_http_header_server / _client) and the WebSocket frame parser
 * (coap_ws_read), plus the frame builder (coap_ws_write).
 *
 * The existing pdu_parse_ws_target only exercises coap_pdu_parse() with
 * COAP_PROTO_WS — it skips the entire WS framing layer above it. This
 * harness sits below that, feeding bytes directly into coap_ws_read via a
 * stubbed lower-layer read function so we exercise the masked / length-
 * encoded / opcode-dispatched parsing code.
 */

#include "coap3/coap_internal.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Bounded cursor that drip-feeds fuzz input into the WS layer. */
typedef struct {
  const uint8_t *data;
  size_t size;
  size_t pos;
} ws_fuzz_cursor_t;

static ws_fuzz_cursor_t g_cursor;

/* Stubbed COAP_LAYER_WS read: returns up to `datalen` bytes from the cursor.
 * Returning 0 when empty is the signal coap_ws_read uses for "no more data
 * available right now" — the caller loops naturally on that. */
static ssize_t
ws_fuzz_stub_read(coap_session_t *session, uint8_t *data, size_t datalen) {
  (void)session;
  size_t avail = g_cursor.size - g_cursor.pos;
  if (avail == 0)
    return 0;
  size_t n = avail < datalen ? avail : datalen;
  memcpy(data, g_cursor.data + g_cursor.pos, n);
  g_cursor.pos += n;
  return (ssize_t)n;
}

/* Stubbed COAP_LAYER_WS write: drop all output. coap_ws_read writes back the
 * HTTP/1.1 101 (or 400) response on the server path; coap_ws_close writes a
 * 2-byte close frame. None of that needs to leave the process. */
static ssize_t
ws_fuzz_stub_write(coap_session_t *session, const uint8_t *data,
                   size_t datalen) {
  (void)session;
  (void)data;
  return (ssize_t)datalen;
}

/* Stubbed establish: coap_ws_read calls this once the WS handshake
 * completes. The normal implementation is coap_session_establish; we just
 * mark the session as established to keep state consistent. */
static void
ws_fuzz_stub_establish(coap_session_t *session) {
  session->state = COAP_SESSION_STATE_ESTABLISHED;
}

static void
ws_fuzz_stub_close(coap_session_t *session) {
  (void)session;
}

static int
ws_fuzz_event_handler(coap_session_t *session, const coap_event_t event) {
  (void)session;
  (void)event;
  return 0;
}

/* Install the stub function pointers on a session for the WS layer. */
static void
ws_fuzz_install_stubs(coap_session_t *session) {
  session->sock.lfunc[COAP_LAYER_WS].l_read = ws_fuzz_stub_read;
  session->sock.lfunc[COAP_LAYER_WS].l_write = ws_fuzz_stub_write;
  session->sock.lfunc[COAP_LAYER_WS].l_establish = ws_fuzz_stub_establish;
  session->sock.lfunc[COAP_LAYER_WS].l_close = ws_fuzz_stub_close;
}

/* Drive coap_ws_read until the cursor is exhausted or the layer disconnects.
 * scratch must be at least 64 KiB to accept the largest representable WS
 * payload that survives the (size > datalen) sanity check. */
static void
ws_fuzz_drive_read(coap_session_t *session, uint8_t *scratch,
                   size_t scratch_len) {
  for (int i = 0; i < 64; i++) {
    if (g_cursor.pos >= g_cursor.size)
      return;
    size_t before = g_cursor.pos;
    coap_lock_lock(return);
    ssize_t r = coap_ws_read(session, scratch, scratch_len);
    coap_lock_unlock();
    if (r < 0)
      return;
    /* No forward progress and no bytes returned: avoid infinite spin. */
    if (r == 0 && g_cursor.pos == before)
      return;
  }
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* One control byte + at least a few bytes of payload. */
  if (size < 4)
    return 0;

  coap_context_t *ctx = NULL;
  coap_session_t *session = NULL;
  coap_address_t addr;
  uint8_t *scratch = NULL;

  const uint8_t mode = data[0];
  const uint8_t *fuzz_data = data + 1;
  size_t fuzz_size = size - 1;

  coap_startup();
  coap_set_log_level(COAP_LOG_EMERG);

  /* Allocate a 64 KiB scratch buffer: matches the 16-bit length field's
   * maximum so the size sanity check in coap_ws_read doesn't reject
   * legitimate frames produced by the fuzzer. */
  scratch = (uint8_t *)malloc(65536);
  if (!scratch)
    goto cleanup;

  ctx = coap_new_context(NULL);
  if (!ctx)
    goto cleanup;
  coap_register_event_handler(ctx, ws_fuzz_event_handler);

  /* Bring up a UDP client session for its initialised state — it's the only
   * way to get a fully-formed coap_session_t through public API without
   * spawning a real TCP connection. We don't touch its socket, only the WS
   * layer function pointers, so the UDP socket simply lingers until cleanup. */
  coap_address_init(&addr);
  addr.addr.sa.sa_family = AF_INET;
  addr.addr.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.addr.sin.sin_port = htons(5683);

  session = coap_new_client_session(ctx, NULL, &addr, COAP_PROTO_UDP);
  if (!session)
    goto cleanup;

  ws_fuzz_install_stubs(session);

  /* Stage the cursor for ws_fuzz_stub_read. */
  g_cursor.data = fuzz_data;
  g_cursor.size = fuzz_size;
  g_cursor.pos = 0;

  /* Pre-allocate session->ws so we can control ws->state — the field both
   * the HTTP-Upgrade parser (coap_ws_rd_http_header at coap_ws.c:526) and
   * the frame parser (coap_ws_read at coap_ws.c:641) branch on for
   * server-vs-client semantics. We deliberately do NOT mutate session->type,
   * because coap_session_release_lkd only frees a session whose type is
   * CLIENT; flipping type to SERVER causes a double-release assert when
   * coap_free_context later iterates ctx->sessions. */
  session->ws = (coap_ws_state_t *)coap_malloc_type(
                    COAP_STRING, sizeof(coap_ws_state_t));
  if (!session->ws)
    goto cleanup;
  memset(session->ws, 0, sizeof(coap_ws_state_t));
  session->ws->state = (mode & 0x01) ? COAP_SESSION_TYPE_SERVER
                       : COAP_SESSION_TYPE_CLIENT;

  /* Three sub-modes selected by mode bits 1-2:
   *   0: full handshake — drive HTTP Upgrade then any trailing frames
   *   1: post-handshake — pre-mark ws->up and drive frame parsing only
   *   2: write path     — also call coap_ws_write with fuzz bytes
   */
  uint8_t submode = (mode >> 1) & 0x03;
  if (submode == 1 || submode == 2)
    session->ws->up = 1; /* Skip the HTTP Upgrade exchange. */

  ws_fuzz_drive_read(session, scratch, 65536);

  /* Write path: fuzz coap_ws_write's frame builder with the remaining
   * input. Both client (masked) and server (unmasked) branches differ. */
  if (submode == 2 && g_cursor.pos < g_cursor.size) {
    size_t rem = g_cursor.size - g_cursor.pos;
    if (rem > 4096)
      rem = 4096;
    coap_ws_write(session, g_cursor.data + g_cursor.pos, rem);
  }

cleanup:
  if (session)
    coap_session_release(session);
  if (ctx)
    coap_free_context(ctx);
  free(scratch);
  coap_cleanup();
  return 0;
}
