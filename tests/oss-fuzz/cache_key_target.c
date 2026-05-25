/* Cache-key derivation fuzzer for libcoap.
 *
 * src/coap_cache.c is at ~21% line coverage. The cache layer derives a
 * stable key from a CoAP PDU by hashing a canonicalised view of the
 * options (with per-context "ignore" lists and the Block options handled
 * specially). The exposed entrypoints — coap_cache_derive_key /
 * coap_cache_derive_key_w_ignore / coap_cache_get_by_pdu — all consume an
 * attacker-influenced PDU.
 *
 * Strategy: parse a fuzz-supplied byte string as a CoAP UDP PDU, then
 * call every cache-key derivation entrypoint against it, varying the
 * "ignore options" set. coap_new_cache_entry is also driven on the
 * happy path so the cache-entry hash insertion (utlist macros over
 * attacker-controlled key bytes) is exercised.
 */

#include "coap3/coap_internal.h"
#include "coap3/coap_cache.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 5 || size > 4096)
    return 0;

  coap_context_t *ctx = NULL;
  coap_session_t *session = NULL;
  coap_pdu_t *pdu = NULL;
  coap_address_t addr;

  coap_startup();
  coap_set_log_level(COAP_LOG_EMERG);

  ctx = coap_new_context(NULL);
  if (!ctx)
    goto cleanup;

  coap_address_init(&addr);
  addr.addr.sa.sa_family = AF_INET;
  session = coap_new_client_session(ctx, NULL, &addr, COAP_PROTO_UDP);
  if (!session)
    goto cleanup;
  session->state = COAP_SESSION_STATE_ESTABLISHED;

  /* First byte selects ignore-set + session-based flag. Remaining bytes
   * are parsed as a UDP PDU. */
  uint8_t selector = data[0];
  const uint8_t *pdu_bytes = data + 1;
  size_t pdu_len = size - 1;

  pdu = coap_pdu_init(COAP_MESSAGE_CON, COAP_REQUEST_CODE_GET, 0,
                      coap_session_max_pdu_size(session));
  if (!pdu)
    goto cleanup;
  if (!coap_pdu_parse(COAP_PROTO_UDP, pdu_bytes, pdu_len, pdu))
    goto cleanup;

  coap_cache_session_based_t sb = (selector & 0x01)
                                  ? COAP_CACHE_IS_SESSION_BASED
                                  : COAP_CACHE_NOT_SESSION_BASED;

  /* Plain derive_key. */
  {
    coap_cache_key_t *k = coap_cache_derive_key(session, pdu, sb);
    coap_delete_cache_key(k);
  }

  /* derive_key_w_ignore with a small ignore list — exercises the
   * is_cache_key() option filter that walks the (option_num, ignore_count)
   * tuples. */
  {
    static const uint16_t ignore_set[] = {
      COAP_OPTION_ETAG, COAP_OPTION_OBSERVE, COAP_OPTION_BLOCK1,
      COAP_OPTION_BLOCK2, COAP_OPTION_URI_HOST,
    };
    size_t n = (selector >> 1) % (sizeof(ignore_set) / sizeof(ignore_set[0]) + 1);
    coap_cache_key_t *k = coap_cache_derive_key_w_ignore(session, pdu, sb,
                                                         ignore_set, n);
    coap_delete_cache_key(k);
  }

  /* Drive coap_cache_get_by_pdu (lookup) and coap_new_cache_entry
   * (insertion + hash chain walk). */
  {
    coap_cache_entry_t *entry =
        coap_new_cache_entry(session, pdu,
                             (selector & 0x10) ? COAP_CACHE_RECORD_PDU
                                               : COAP_CACHE_NOT_RECORD_PDU,
                             sb, 0);
    (void)coap_cache_get_by_pdu(session, pdu, sb);
    if (entry)
      coap_delete_cache_entry(ctx, entry);
  }

cleanup:
  if (pdu)
    coap_delete_pdu(pdu);
  if (session)
    coap_session_release(session);
  if (ctx)
    coap_free_context(ctx);
  coap_cleanup();
  return 0;
}
