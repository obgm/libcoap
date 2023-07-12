/* coap_layers.c -- Layer handling for libcoap
 *
 * Copyright (C) 2023 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file coap_layers.c
 * @brief Layer Handling
 */

#include "coap3/coap_internal.h"

/*
 * Layer index table.  A whole protocol chunk gets copied into coap_socket_t.
 * Each layer invokes the function defined at its layer to get the next layer
 * (which could be above or below) to complete.
 *
 * The stack layers are (* managed by libcoap)
 *   Application
 *   CoAP *
 *   CoAP-Session *
 *   DTLS *
 *   Netif *
 *   Sockets *
 *   Network Stack
 *
 * dgrm read currently handled separately.
 * strm read works down the layers.
 * write     works down the layers.
 * establish is done after netif accept/connect completes by invoking SESSION
 *           and then works up the layers.
 * close     works down the layers
 */
coap_layer_func_t coap_layers_coap[COAP_PROTO_LAST][COAP_LAYER_LAST] = {
  {
    /* COAP_PROTO_NONE */
    { NULL, NULL, NULL, NULL }, /* SESSION */
    { NULL, NULL, NULL, NULL }, /* WS */
    { NULL, NULL, NULL, NULL }  /* TLS */
  },
  {
    /* COAP_PROTO_UDP */
    { NULL,                 coap_netif_dgrm_write, coap_session_establish, coap_netif_close }, /* SESSION */
    { NULL,                 NULL,                  NULL,                   NULL             }, /* WS */
    { NULL,                 NULL,                  NULL,                   NULL             }  /* TLS */
  },
  {
    /* COAP_PROTO_DTLS */
    { NULL,                 coap_dtls_send,        coap_dtls_establish,    coap_dtls_close  }, /* SESSION */
    { NULL,                 NULL,                  NULL,                   NULL             }, /* WS */
    { NULL,                 coap_netif_dgrm_write, coap_session_establish, coap_netif_close }  /* TLS */
  },
#if !COAP_DISABLE_TCP
  {
    /* COAP_PROTO_TCP */
    { coap_netif_strm_read, coap_netif_strm_write, coap_session_establish, coap_netif_close }, /* SESSION */
    { NULL,                 NULL,                  NULL,                   NULL             }, /* WS */
    { NULL,                 NULL,                  NULL,                   NULL             }  /* TLS */
  },
  {
    /* COAP_PROTO_TLS */
    { coap_tls_read,        coap_tls_write,        coap_tls_establish,     coap_tls_close   }, /* SESSION */
    { NULL,                 NULL,                  NULL,                   NULL             }, /* WS */
    { coap_netif_strm_read, coap_netif_strm_write, coap_session_establish, coap_netif_close }  /* TLS */
  },
#if COAP_WS_SUPPORT
  {
    /* COAP_PROTO_WS */
    { coap_ws_read,         coap_ws_write,         coap_ws_establish,      coap_ws_close    }, /* SESSION */
    { coap_netif_strm_read, coap_netif_strm_write, coap_session_establish, coap_netif_close }, /* WS */
    { NULL,                 NULL,                  NULL,                   NULL             }  /* TLS */
  },
  {
    /* COAP_PROTO_WSS */
    { coap_ws_read,         coap_ws_write,         coap_tls_establish,     coap_ws_close    }, /* SESSION */
    { coap_tls_read,        coap_tls_write,        coap_session_establish, coap_tls_close   }, /* WS */
    { coap_netif_strm_read, coap_netif_strm_write, coap_ws_establish,      coap_netif_close }  /* TLS */
  }
#else /* !COAP_WS_SUPPORT */
  {
    /* COAP_PROTO_WS */
    { NULL, NULL, NULL, NULL }, /* SESSION */
    { NULL, NULL, NULL, NULL }, /* WS */
    { NULL, NULL, NULL, NULL }  /* TLS */
  },
  {
    /* COAP_PROTO_WSS */
    { NULL, NULL, NULL, NULL }, /* SESSION */
    { NULL, NULL, NULL, NULL }, /* WS */
    { NULL, NULL, NULL, NULL }  /* TLS */
  }
#endif /* !COAP_WS_SUPPORT */
#else /* COAP_DISABLE_TCP */
  {
    /* COAP_PROTO_TCP */
    { NULL, NULL, NULL, NULL }, /* SESSION */
    { NULL, NULL, NULL, NULL }, /* WS */
    { NULL, NULL, NULL, NULL }  /* TLS */
  },
  {
    /* COAP_PROTO_TLS */
    { NULL, NULL, NULL, NULL }, /* SESSION */
    { NULL, NULL, NULL, NULL }, /* WS */
    { NULL, NULL, NULL, NULL }  /* TLS */
  },
  {
    /* COAP_PROTO_WS */
    { NULL, NULL, NULL, NULL }, /* SESSION */
    { NULL, NULL, NULL, NULL }, /* WS */
    { NULL, NULL, NULL, NULL }  /* TLS */
  },
  {
    /* COAP_PROTO_WSS */
    { NULL, NULL, NULL, NULL }, /* SESSION */
    { NULL, NULL, NULL, NULL }, /* WS */
    { NULL, NULL, NULL, NULL }  /* TLS */
  }
#endif /* COAP_DISABLE_TCP */
};
