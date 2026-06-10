#ifndef COAP_FUZZ_HELPER_H
#define COAP_FUZZ_HELPER_H

#include "coap3/coap_internal.h"
#include <stdint.h>

void coap_fuzz_dispatch(coap_context_t *ctx, coap_session_t *session,
                        const uint8_t *data, size_t size,
                        const uint8_t *fixed_path, size_t fixed_path_len);

#endif
