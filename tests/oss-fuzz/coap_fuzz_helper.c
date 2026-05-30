#include "coap3/coap_internal.h"
#include "coap_fuzz_helper.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* Wrapping byte reader to ensure never goes out of bounds */
typedef struct {
  const uint8_t *data;
  size_t size;
  size_t pos;
} coap_fuzz_cursor_t;
static inline uint8_t
coap_fuzz_u8(coap_fuzz_cursor_t *c) {
  return c->size ? c->data[c->pos++ % c->size] : 0;
}

/* All 7 request codes */
static const coap_pdu_code_t coap_fuzz_req_codes[] = {
  COAP_REQUEST_CODE_GET,    COAP_REQUEST_CODE_POST,   COAP_REQUEST_CODE_PUT,
  COAP_REQUEST_CODE_DELETE, COAP_REQUEST_CODE_FETCH,
  COAP_REQUEST_CODE_IPATCH, COAP_REQUEST_CODE_PATCH,
};

/* Options reachable after a fixed path anchor */
static const uint16_t coap_fuzz_opt_nums[] = {
  COAP_OPTION_CONTENT_FORMAT, COAP_OPTION_MAXAGE,  COAP_OPTION_URI_QUERY,
  COAP_OPTION_ACCEPT,         COAP_OPTION_BLOCK2,  COAP_OPTION_BLOCK1,
  COAP_OPTION_SIZE1,          COAP_OPTION_ECHO,    COAP_OPTION_NORESPONSE,
};
#define COAP_FUZZ_OPT_N 9

void
coap_fuzz_dispatch(coap_context_t *ctx, coap_session_t *session,
                   const uint8_t *data, size_t size,
                   const uint8_t *fixed_path, size_t fixed_path_len) {
  if (!ctx || !session || !data || size < 4)
    return;

  /* Programmatic PDU with fixed URI-Path using coap_dispatch() */
  {
    coap_fuzz_cursor_t c = { data, size, 0 };
    coap_pdu_type_t type = coap_fuzz_u8(&c) & 1 ? COAP_MESSAGE_NON : COAP_MESSAGE_CON;
    coap_pdu_code_t code = coap_fuzz_req_codes[coap_fuzz_u8(&c) % 7];
    uint8_t tkl = coap_fuzz_u8(&c) % 9, token[8];
    for (uint8_t i = 0; i < tkl; i++)
      token[i] = coap_fuzz_u8(&c);

    coap_pdu_t *pdu = coap_pdu_init(type, code, coap_new_message_id(session),
                                    coap_session_max_pdu_size(session));
    if (pdu) {
      if (tkl)
        coap_add_token(pdu, tkl, token);

      uint16_t last = 0;
      if (fixed_path && fixed_path_len) {
        coap_add_option(pdu, COAP_OPTION_URI_PATH, fixed_path_len, fixed_path);
        last = COAP_OPTION_URI_PATH;
      }

      uint8_t n = coap_fuzz_u8(&c) % 4;
      for (uint8_t i = 0; i < n; i++) {
        uint16_t opt = coap_fuzz_opt_nums[coap_fuzz_u8(&c) % COAP_FUZZ_OPT_N];
        if (opt <= last)
          continue;
        uint8_t vlen = coap_fuzz_u8(&c) % 9, vbuf[8];
        for (uint8_t j = 0; j < vlen; j++)
          vbuf[j] = coap_fuzz_u8(&c);
        if (coap_add_option(pdu, opt, vlen, vbuf))
          last = opt;
      }

      size_t rem = c.pos < size ? size - c.pos : 0;
      if (rem) {
        size_t avail = coap_session_max_pdu_size(session) - pdu->used_size - 1;
        coap_add_data(pdu, rem < avail ? rem : avail, data + c.pos);
      }

      coap_lock_lock(return);
      coap_dispatch(ctx, session, pdu);
      coap_lock_unlock();
      coap_delete_pdu(pdu);
    }
  }

  /* Raw wire format using coap_handle_dgram() */
  {
    uint8_t *copy = malloc(size);
    if (copy) {
      memcpy(copy, data, size);
      coap_lock_lock(return);
      coap_handle_dgram(ctx, session, copy, size);
      coap_lock_unlock();
      free(copy);
    }
  }
}
