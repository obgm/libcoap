/*
 * coap_ws.c -- WebSockets functions for libcoap
 *
 * Copyright (C) 2023 Olaf Bergmann <bergmann@tzi.org>
 * Copyright (C) 2023 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_ws.c
 * @brief CoAP WebSocket handling functions
 */

#include "coap3/coap_internal.h"

#if COAP_WS_SUPPORT
#include <stdio.h>
#include <ctype.h>

#ifdef _WIN32
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#endif

#define COAP_WS_RESPONSE \
  "HTTP/1.1 101 Switching Protocols\r\n" \
  "Upgrade: websocket\r\n" \
  "Connection: Upgrade\r\n" \
  "Sec-WebSocket-Accept: %s\r\n" \
  "Sec-WebSocket-Protocol: coap\r\n" \
  "\r\n"

int
coap_ws_is_supported(void) {
#if defined(COAP_WITH_LIBOPENSSL) || defined(COAP_WITH_LIBGNUTLS) || defined(COAP_WITH_LIBMBEDTLS)
  /* Have SHA1 hash support */
  return coap_tcp_is_supported();
#else /* !COAP_WITH_LIBOPENSSL && !COAP_WITH_LIBGNUTLS && !COAP_WITH_LIBMBEDTLS */
  return 0;
#endif /* !COAP_WITH_LIBOPENSSL && !COAP_WITH_LIBGNUTLS && !COAP_WITH_LIBMBEDTLS */
}

int
coap_wss_is_supported(void) {
  return coap_tls_is_supported();
}

static const char
basis_64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int
coap_base64_encode_buffer(const uint8_t *string, size_t len, char *encoded,
                          const size_t max_encoded_len) {
  size_t i;
  char *p;

  if ((((len + 2) / 3 * 4) + 1) > max_encoded_len) {
    assert(0);
    return 0;
  }

  p = encoded;
  for (i = 0; i < len - 2; i += 3) {
    *p++ = basis_64[(string[i] >> 2) & 0x3F];
    *p++ = basis_64[((string[i] & 0x3) << 4) |
                                       ((int)(string[i + 1] & 0xF0) >> 4)];
    *p++ = basis_64[((string[i + 1] & 0xF) << 2) |
                                           ((int)(string[i + 2] & 0xC0) >> 6)];
    *p++ = basis_64[string[i + 2] & 0x3F];
  }
  if (i < len) {
    *p++ = basis_64[(string[i] >> 2) & 0x3F];
    if (i == (len - 1)) {
      *p++ = basis_64[((string[i] & 0x3) << 4)];
      *p++ = '=';
    } else {
      *p++ = basis_64[((string[i] & 0x3) << 4) |
                                         ((int)(string[i + 1] & 0xF0) >> 4)];
      *p++ = basis_64[((string[i + 1] & 0xF) << 2)];
    }
    *p++ = '=';
  }

  *p++ = '\0';
  return 1;
}

static int
coap_base64_decode_buffer(const char *bufcoded, size_t *len, uint8_t *bufplain,
                          const size_t max_decoded_len) {
  size_t nbytesdecoded;
  const uint8_t *bufin;
  uint8_t *bufout;
  size_t nprbytes;
  static const uint8_t pr2six[256] = {
    /* ASCII table */
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
  };

  bufin = (const uint8_t *)bufcoded;
  while (pr2six[*(bufin++)] <= 63);
  nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
  nbytesdecoded = ((nprbytes + 3) / 4) * 3;
  if ((nbytesdecoded - ((4 - nprbytes) & 3)) > max_decoded_len)
    return 0;

  bufout = bufplain;
  bufin = (const uint8_t *)bufcoded;

  while (nprbytes > 4) {
    *(bufout++) =
        (uint8_t)(pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
    *(bufout++) =
        (uint8_t)(pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
    *(bufout++) =
        (uint8_t)(pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
    bufin += 4;
    nprbytes -= 4;
  }

  /* Note: (nprbytes == 1) would be an error, so just ignore that case */
  if (nprbytes > 1) {
    *(bufout++) = (uint8_t)(pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
  }
  if (nprbytes > 2) {
    *(bufout++) = (uint8_t)(pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
  }
  if (nprbytes > 3) {
    *(bufout++) = (uint8_t)(pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
  }

  if (len)
    *len = nbytesdecoded - ((4 - nprbytes) & 3);
  return 1;
}

static void
coap_ws_log_header(const coap_session_t *session, const uint8_t *header) {
#if COAP_MAX_LOGGING_LEVEL < _COAP_LOG_DEBUG
  (void)session;
  (void)header;
#else /* COAP_MAX_LOGGING_LEVEL >= _COAP_LOG_DEBUG */
  char buf[3*COAP_MAX_FS + 1];
  int i;
  ssize_t bytes_size;
  int extra_hdr_len = 2;

  bytes_size = header[1] & WS_B1_LEN_MASK;
  if (bytes_size == 127) {
    extra_hdr_len += 8;
  } else if (bytes_size == 126) {
    extra_hdr_len += 2;
  }
  if (header[1] & WS_B1_MASK_BIT) {
    extra_hdr_len +=4;
  }
  for (i = 0; i < extra_hdr_len; i++) {
    snprintf(&buf[i*3], 4, " %02x", header[i]);
  }
  coap_log_debug("*  %s: WS header:%s\n", coap_session_str(session), buf);
#endif /* COAP_MAX_LOGGING_LEVEL >= _COAP_LOG_DEBUG */
}

static void
coap_ws_log_key(const coap_session_t *session) {
  char buf[3*16 + 1];
  size_t i;

  for (i = 0; i < sizeof(session->ws->key); i++) {
    snprintf(&buf[i*3], 4, " %02x", session->ws->key[i]);
  }
  coap_log_debug("WS: key:%s\n", buf);
}

static void
coap_ws_mask_data(coap_session_t *session, uint8_t *data, size_t data_len) {
  coap_ws_state_t *ws = session->ws;
  size_t i;

  for (i = 0; i < data_len; i++) {
    data[i] ^= ws->mask_key[i%4];
  }
}

ssize_t
coap_ws_write(coap_session_t *session, const uint8_t *data, size_t datalen) {
  uint8_t ws_header[COAP_MAX_FS];
  ssize_t hdr_len = 2;
  ssize_t ret;

  /* If lower layer not yet up, return error */
  if (!session->ws) {
    session->ws = coap_malloc_type(COAP_STRING, sizeof(coap_ws_state_t));
    if (!session->ws) {
      coap_session_disconnected(session, COAP_NACK_WS_LAYER_FAILED);
      return -1;
    }
    memset(session->ws, 0, sizeof(coap_ws_state_t));
  }

  if (!session->ws->up) {
    coap_log_debug("WS: Layer not up\n");
    return 0;
  }
  if (session->ws->sent_close)
    return 0;

  ws_header[0] = WS_B0_FIN_BIT | WS_OP_BINARY;
  if (datalen <= 125) {
    ws_header[1] = datalen & WS_B1_LEN_MASK;
  } else if (datalen <= 0xffff) {
    ws_header[1] = 126;
    ws_header[2] = (datalen >>  8) & 0xff;
    ws_header[3] = datalen & 0xff;
    hdr_len += 2;
  } else {
    ws_header[1] = 127;
    ws_header[2] = ((uint64_t)datalen >> 56) & 0xff;
    ws_header[3] = ((uint64_t)datalen >> 48) & 0xff;
    ws_header[4] = ((uint64_t)datalen >> 40) & 0xff;
    ws_header[5] = ((uint64_t)datalen >> 32) & 0xff;
    ws_header[6] = (datalen >> 24) & 0xff;
    ws_header[7] = (datalen >> 16) & 0xff;
    ws_header[8] = (datalen >>  8) & 0xff;
    ws_header[9] = datalen & 0xff;
    hdr_len += 8;
  }
  if (session->ws->state == COAP_SESSION_TYPE_CLIENT) {
    /* Need to set the Mask bit, and set the masking key */
    ws_header[1] |= WS_B1_MASK_BIT;
    /* TODO Masking Key and mask provided data */
    coap_prng(&ws_header[hdr_len], 4);
    memcpy(session->ws->mask_key, &ws_header[hdr_len], 4);
    hdr_len += 4;
  }
  coap_ws_log_header(session, ws_header);
  ret = session->sock.lfunc[COAP_LAYER_WS].l_write(session, ws_header, hdr_len);
  if (ret != hdr_len) {
    return -1;
  }
  if (session->ws->state == COAP_SESSION_TYPE_CLIENT) {
    /* Need to mask the data */
    uint8_t *wdata = coap_malloc_type(COAP_STRING, datalen);

    if (!wdata) {
      errno = ENOMEM;
      return -1;
    }
    session->ws->data_size = datalen;
    memcpy(wdata, data, datalen);
    coap_ws_mask_data(session, wdata, datalen);
    ret = session->sock.lfunc[COAP_LAYER_WS].l_write(session, wdata, datalen);
    coap_free_type(COAP_STRING, wdata);
  } else {
    ret = session->sock.lfunc[COAP_LAYER_WS].l_write(session, data, datalen);
  }
  if (ret <= 0) {
    return ret;
  }
  if (ret == (ssize_t)datalen)
    coap_log_debug("*  %s: ws:    sent %4zd bytes\n",
                   coap_session_str(session), ret);
  else
    coap_log_debug("*  %s: ws:    sent %4zd of %4zd bytes\n",
                   coap_session_str(session), ret, datalen);
  return datalen;
}

static char *
coap_ws_split_rd_header(coap_session_t *session) {
  char *cp = strchr((char *)session->ws->http_hdr, ' ');

  if (!cp)
    cp = strchr((char *)session->ws->http_hdr, '\t');

  if (!cp)
    return NULL;

  *cp = '\000';
  cp++;
  while (isblank(*cp))
    cp++;
  return cp;
}

static int
coap_ws_rd_http_header_server(coap_session_t *session) {
  coap_ws_state_t *ws = session->ws;
  char *value;

  if (!ws->seen_first) {
    if (strcasecmp((char *)ws->http_hdr,
                   "GET /.well-known/coap HTTP/1.1") != 0) {
      coap_log_info("WS: Invalid GET request %s\n", (char *)ws->http_hdr);
      return 0;
    }
    ws->seen_first = 1;
    return 1;
  }
  /* Process the individual header */
  value = coap_ws_split_rd_header(session);
  if (!value)
    return 0;

  if (strcasecmp((char *)ws->http_hdr, "Host:") == 0) {
    if (ws->seen_host) {
      coap_log_debug("WS: Duplicate Host: header\n");
      return 0;
    }
    ws->seen_host = 1;
  } else if (strcasecmp((char *)ws->http_hdr, "Upgrade:") == 0) {
    if (ws->seen_upg) {
      coap_log_debug("WS: Duplicate Upgrade: header\n");
      return 0;
    }
    if (strcasecmp(value, "websocket") != 0) {
      coap_log_debug("WS: Invalid Upgrade: header\n");
      return 0;
    }
    ws->seen_upg = 1;
  } else if (strcasecmp((char *)ws->http_hdr, "Connection:") == 0) {
    if (ws->seen_conn) {
      coap_log_debug("WS: Duplicate Connection: header\n");
      return 0;
    }
    if (strcasecmp(value, "Upgrade") != 0) {
      coap_log_debug("WS: Invalid Connection: header\n");
      return 0;
    }
    ws->seen_conn = 1;
  } else if (strcasecmp((char *)ws->http_hdr, "Sec-WebSocket-Key:") == 0) {
    size_t len;

    if (ws->seen_key) {
      coap_log_debug("WS: Duplicate Sec-WebSocket-Key: header\n");
      return 0;
    }
    if (!coap_base64_decode_buffer(value, &len, ws->key,
                                   sizeof(ws->key)) ||
        len != sizeof(ws->key)) {
      coap_log_info("WS: Invalid Sec-WebSocket-Key: %s\n", value);
      return 0;
    }
    coap_ws_log_key(session);
    ws->seen_key = 1;
  } else if (strcasecmp((char *)ws->http_hdr, "Sec-WebSocket-Protocol:") == 0) {
    if (ws->seen_proto) {
      coap_log_debug("WS: Duplicate Sec-WebSocket-Protocol: header\n");
      return 0;
    }
    if (strcasecmp(value, "coap") != 0) {
      coap_log_debug("WS: Invalid Sec-WebSocket-Protocol: header\n");
      return 0;
    }
    ws->seen_proto = 1;
  } else if (strcasecmp((char *)ws->http_hdr, "Sec-WebSocket-Version:") == 0) {
    if (ws->seen_ver) {
      coap_log_debug("WS: Duplicate Sec-WebSocket-Version: header\n");
      return 0;
    }
    if (strcasecmp(value, "13") != 0) {
      coap_log_debug("WS: Invalid Sec-WebSocket-Version: header\n");
      return 0;
    }
    ws->seen_ver = 1;
  }
  return 1;
}

#define COAP_WS_KEY_EXT "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

static int
coap_ws_build_key_hash(coap_session_t *session, char *hash, size_t max_hash_len) {
  char buf[28 + sizeof(COAP_WS_KEY_EXT)];
  coap_bin_const_t info;
  coap_bin_const_t *hashed = NULL;

  if (max_hash_len < 29)
    return 0;
  if (!coap_base64_encode_buffer(session->ws->key, sizeof(session->ws->key),
                                 buf, sizeof(buf)))
    return 0;
  if (strlen(buf) >= 28)
    return 0;
  strcat(buf, COAP_WS_KEY_EXT);
  info.s = (uint8_t *)buf;
  info.length = strlen(buf);
  if (!coap_crypto_hash(COSE_ALGORITHM_SHA_1, &info, &hashed))
    return 0;

  if (!coap_base64_encode_buffer(hashed->s, hashed->length,
                                 hash, max_hash_len)) {
    coap_delete_bin_const(hashed);
    return 0;
  }
  coap_delete_bin_const(hashed);
  return 1;
}

static int
coap_ws_rd_http_header_client(coap_session_t *session) {
  coap_ws_state_t *ws = session->ws;
  char *value;

  if (!ws->seen_first) {
    value = coap_ws_split_rd_header(session);

    if (strcmp((char *)ws->http_hdr, "HTTP/1.1") != 0 ||
        atoi(value) != 101) {
      coap_log_info("WS: Invalid GET response %s\n", (char *)ws->http_hdr);
      return 0;
    }
    ws->seen_first = 1;
    return 1;
  }
  /* Process the individual header */
  value = coap_ws_split_rd_header(session);
  if (!value)
    return 0;

  if (strcasecmp((char *)ws->http_hdr, "Upgrade:") == 0) {
    if (ws->seen_upg) {
      coap_log_debug("WS: Duplicate Upgrade: header\n");
      return 0;
    }
    if (strcasecmp(value, "websocket") != 0) {
      coap_log_debug("WS: Invalid Upgrade: header\n");
      return 0;
    }
    ws->seen_upg = 1;
  } else if (strcasecmp((char *)ws->http_hdr, "Connection:") == 0) {
    if (ws->seen_conn) {
      coap_log_debug("WS: Duplicate Connection: header\n");
      return 0;
    }
    if (strcasecmp(value, "Upgrade") != 0) {
      coap_log_debug("WS: Invalid Connection: header\n");
      return 0;
    }
    ws->seen_conn = 1;
  } else if (strcasecmp((char *)ws->http_hdr, "Sec-WebSocket-Accept:") == 0) {
    char hash[30];

    if (ws->seen_key) {
      coap_log_debug("WS: Duplicate Sec-WebSocket-Accept: header\n");
      return 0;
    }
    if (!coap_ws_build_key_hash(session, hash, sizeof(hash))) {
      return 0;
    }
    if (strcmp(hash, value) != 0) {
      return 0;
    }
    ws->seen_key = 1;
  } else if (strcasecmp((char *)ws->http_hdr, "Sec-WebSocket-Protocol:") == 0) {
    if (ws->seen_proto) {
      coap_log_debug("WS: Duplicate Sec-WebSocket-Protocol: header\n");
      return 0;
    }
    if (strcasecmp(value, "coap") != 0) {
      coap_log_debug("WS: Invalid Sec-WebSocket-Protocol: header\n");
      return 0;
    }
    ws->seen_proto = 1;
  }
  return 1;
}

/*
 * Read in and parse WebSockets setup HTTP headers
 *
 * return 0 failure
 *        1 success
 */
static int
coap_ws_rd_http_header(coap_session_t *session) {
  coap_ws_state_t *ws = session->ws;
  ssize_t bytes;
  ssize_t rem;
  char *cp;

  while (!ws->up) {
    /*
     * Can only read in up to COAP_MAX_FS at a time in case there is
     * some frame info that needs to be subsequently processed
     */
    rem = ws->http_ofs > (sizeof(ws->http_hdr) - 1 - COAP_MAX_FS) ?
          sizeof(ws->http_hdr) - ws->http_ofs : COAP_MAX_FS;
    bytes = session->sock.lfunc[COAP_LAYER_WS].l_read(session,
                                                      &ws->http_hdr[ws->http_ofs],
                                                      rem);
    if (bytes < 0)
      return 0;
    if (bytes == 0)
      return 1;

    ws->http_ofs += (uint32_t)bytes;
    ws->http_hdr[ws->http_ofs] = '\000';
    /* Force at least one check */
    cp = (char *)ws->http_hdr;
    while (cp) {
      cp = strchr((char *)ws->http_hdr, '\n');
      if (cp) {
        /* Whole header record in */
        *cp = '\000';
        if (cp != (char *)ws->http_hdr) {
          if (cp[-1] == '\r')
            cp[-1] = '\000';
        }

        coap_log_debug("WS: HTTP: %s\n", ws->http_hdr);
        if (ws->http_hdr[0] != '\000') {
          if (ws->state == COAP_SESSION_TYPE_SERVER) {
            if (!coap_ws_rd_http_header_server(session)) {
              return 0;
            }
          } else {
            if (!coap_ws_rd_http_header_client(session)) {
              return 0;
            }
          }
        }

        rem = ws->http_ofs - ((uint8_t *)cp + 1 - ws->http_hdr);
        if (ws->http_hdr[0] == '\000') {
          /* Found trailing empty header line */
          if (ws->state == COAP_SESSION_TYPE_SERVER) {
            if (!(ws->seen_first && ws->seen_host && ws->seen_upg &&
                  ws->seen_conn && ws->seen_key && ws->seen_proto &&
                  ws->seen_ver)) {
              coap_log_info("WS: Missing protocol header(s)\n");
              return 0;
            }
          } else {
            if (!(ws->seen_first && ws->seen_upg && ws->seen_conn &&
                  ws->seen_key && ws->seen_proto)) {
              coap_log_info("WS: Missing protocol header(s)\n");
              return 0;
            }
          }
          ws->up = 1;
          ws->hdr_ofs = (int)rem;
          if (rem > 0)
            memcpy(ws->rd_header, cp + 1, rem);
          return 1;
        }
        ws->http_ofs = (uint32_t)rem;
        memmove(ws->http_hdr, cp + 1, rem);
        ws->http_hdr[ws->http_ofs] = '\000';
      }
    }
  }
  return 1;
}

/*
 * return >=0 Number of bytes processed.
 *         -1 Error (error in errno).
 */
ssize_t
coap_ws_read(coap_session_t *session, uint8_t *data, size_t datalen) {
  ssize_t bytes_size = 0;
  ssize_t extra_hdr_len = 0;
  ssize_t ret;
  uint8_t op_code;

  if (!session->ws) {
    session->ws = coap_malloc_type(COAP_STRING, sizeof(coap_ws_state_t));
    if (!session->ws) {
      coap_session_disconnected(session, COAP_NACK_WS_LAYER_FAILED);
      return -1;
    }
    memset(session->ws, 0, sizeof(coap_ws_state_t));
  }

  if (!session->ws->up) {
    char buf[250];

    if (!coap_ws_rd_http_header(session)) {
      snprintf(buf, sizeof(buf), "HTTP/1.1 400 Invalid request\r\n\r\n");
      coap_log_debug("WS: Response (Fail)\n%s", buf);
      if (coap_netif_available(session)) {
        session->sock.lfunc[COAP_LAYER_WS].l_write(session, (uint8_t *)buf,
                                                   strlen(buf));
      }
      coap_session_disconnected(session, COAP_NACK_WS_LAYER_FAILED);
      return -1;
    }

    if (!session->ws->up)
      return 0;

    if (session->ws->state == COAP_SESSION_TYPE_SERVER) {
      char hash[30];

      if (!coap_ws_build_key_hash(session, hash, sizeof(hash))) {
        return 0;
      }
      snprintf(buf, sizeof(buf), COAP_WS_RESPONSE, hash);
      coap_log_debug("WS: Response\n%s", buf);
      session->sock.lfunc[COAP_LAYER_WS].l_write(session, (uint8_t *)buf,
                                                 strlen(buf));

      coap_handle_event(session->context, COAP_EVENT_WS_CONNECTED, session);
      coap_log_debug("WS: established\n");
    } else {
      /* TODO Process the GET response - error on failure */

      coap_handle_event(session->context, COAP_EVENT_WS_CONNECTED, session);
    }
    session->sock.lfunc[COAP_LAYER_WS].l_establish(session);
    if (session->ws->hdr_ofs == 0)
      return 0;
  }

  /* Get WebSockets frame if not already completely in */
  if (!session->ws->all_hdr_in) {
    ret = session->sock.lfunc[COAP_LAYER_WS].l_read(session,
                                                    &session->ws->rd_header[session->ws->hdr_ofs],
                                                    sizeof(session->ws->rd_header) - session->ws->hdr_ofs);
    if (ret < 0)
      return ret;
    session->ws->hdr_ofs += (int)ret;
    /* Enough of the header in ? */
    if (session->ws->hdr_ofs < 2)
      return 0;

    if (session->ws->state == COAP_SESSION_TYPE_SERVER &&
        !(session->ws->rd_header[1] & WS_B1_MASK_BIT)) {
      /* Client has failed to mask the data */
      session->ws->close_reason = 1002;
      coap_ws_close(session);
      return 0;
    }

    bytes_size = session->ws->rd_header[1] & WS_B1_LEN_MASK;
    if (bytes_size == 127) {
      extra_hdr_len += 8;
    } else if (bytes_size == 126) {
      extra_hdr_len += 2;
    }
    if (session->ws->rd_header[1] & WS_B1_MASK_BIT) {
      memcpy(session->ws->mask_key, &session->ws->rd_header[2 + extra_hdr_len], 4);
      extra_hdr_len +=4;
    }
    if (session->ws->hdr_ofs < 2 + extra_hdr_len)
      return 0;

    /* Header frame is fully in */
    coap_ws_log_header(session, session->ws->rd_header);

    op_code = session->ws->rd_header[0] & WS_B0_OP_MASK;
    if (op_code != WS_OP_BINARY && op_code != WS_OP_CLOSE) {
      /* Remote has failed to use correct opcode */
      session->ws->close_reason = 1003;
      coap_ws_close(session);
      return 0;
    }
    if (op_code == WS_OP_CLOSE) {
      coap_log_debug("WS: Close received\n");
      session->ws->recv_close = 1;
      coap_ws_close(session);
      return 0;
    }

    session->ws->all_hdr_in = 1;

    /* Get WebSockets frame size */
    if (bytes_size == 127) {
      bytes_size = ((uint64_t)session->ws->rd_header[2] << 56) +
                   ((uint64_t)session->ws->rd_header[3] << 48) +
                   ((uint64_t)session->ws->rd_header[4] << 40) +
                   ((uint64_t)session->ws->rd_header[5] << 32) +
                   ((uint64_t)session->ws->rd_header[6] << 24) +
                   ((uint64_t)session->ws->rd_header[7] << 16) +
                   ((uint64_t)session->ws->rd_header[8] <<  8) +
                   session->ws->rd_header[9];
    } else if (bytes_size == 126) {
      bytes_size = ((uint16_t)session->ws->rd_header[2] << 8) +
                   session->ws->rd_header[3];
    }
    session->ws->data_size = bytes_size;
    if ((size_t)bytes_size > datalen) {
      coap_log_err("coap_ws_read: packet size bigger than provided data space"
                   " (%zu > %zu)\n", bytes_size, datalen);
      coap_handle_event(session->context, COAP_EVENT_WS_PACKET_SIZE, session);
      session->ws->close_reason = 1009;
      coap_ws_close(session);
      return 0;
    }
    coap_log_debug("*  %s: Packet size %zu\n", coap_session_str(session),
                   bytes_size);

    /* Handle any data read in as a part of the header */
    ret = session->ws->hdr_ofs - 2 - extra_hdr_len;
    if (ret > 0) {
      assert(2 + extra_hdr_len < (ssize_t)sizeof(session->ws->rd_header));
      /* data in latter part of header */
      if (ret <= bytes_size) {
        /* copy across all the available data */
        memcpy(data, &session->ws->rd_header[2 + extra_hdr_len], ret);
        session->ws->data_ofs = ret;
        if (ret == bytes_size) {
          if (session->ws->state == COAP_SESSION_TYPE_SERVER) {
            /* Need to unmask the data */
            coap_ws_mask_data(session, data, bytes_size);
          }
          session->ws->all_hdr_in = 0;
          session->ws->hdr_ofs = 0;
          op_code = session->ws->rd_header[0] & WS_B0_OP_MASK;
          if (op_code == WS_OP_CLOSE) {
            session->ws->close_reason = (data[0] << 8) + data[1];
            coap_log_debug("*  %s: WS: Close received (%u)\n",
                           coap_session_str(session),
                           session->ws->close_reason);
            session->ws->recv_close = 1;
            if (!session->ws->sent_close)
              coap_ws_close(session);
            return 0;
          }
          return bytes_size;
        }
      } else {
        /* more information in header than given data size */
        memcpy(data, &session->ws->rd_header[2 + extra_hdr_len], bytes_size);
        session->ws->data_ofs = bytes_size;
        if (session->ws->state == COAP_SESSION_TYPE_SERVER) {
          /* Need to unmask the data */
          coap_ws_mask_data(session, data, bytes_size);
        }
        /* set up partial header for the next read */
        memmove(session->ws->rd_header,
                &session->ws->rd_header[2 + extra_hdr_len + bytes_size],
                ret - bytes_size);
        session->ws->all_hdr_in = 0;
        session->ws->hdr_ofs = (int)(ret - bytes_size);
        return bytes_size;
      }
    } else {
      session->ws->data_ofs = 0;
    }
  }

  /* Get in (remaining) data */
  ret = session->sock.lfunc[COAP_LAYER_WS].l_read(session,
                                                  &data[session->ws->data_ofs],
                                                  session->ws->data_size - session->ws->data_ofs);
  if (ret <= 0)
    return ret;
  session->ws->data_ofs += ret;
  if (session->ws->data_ofs == session->ws->data_size) {
    if (session->ws->state == COAP_SESSION_TYPE_SERVER) {
      /* Need to unmask the data */
      coap_ws_mask_data(session, data, session->ws->data_size);
    }
    session->ws->all_hdr_in = 0;
    session->ws->hdr_ofs = 0;
    session->ws->data_ofs = 0;
    coap_log_debug("*  %s: ws:    recv %4zd bytes\n",
                   coap_session_str(session), session->ws->data_size);
    return session->ws->data_size;
  }
  /* Need to get in all of the data */
  coap_log_debug("*  %s: Waiting Packet size %zu (got %zu)\n", coap_session_str(session),
                 session->ws->data_size, session->ws->data_ofs);
  return 0;
}

#define COAP_WS_REQUEST \
  "GET /.well-known/coap HTTP/1.1\r\n" \
  "Host: %s\r\n" \
  "Upgrade: websocket\r\n" \
  "Connection: Upgrade\r\n" \
  "Sec-WebSocket-Key: %s\r\n" \
  "Sec-WebSocket-Protocol: coap\r\n" \
  "Sec-WebSocket-Version: 13\r\n" \
  "\r\n"

void
coap_ws_establish(coap_session_t *session) {
  if (!session->ws) {
    session->ws = coap_malloc_type(COAP_STRING, sizeof(coap_ws_state_t));
    if (!session->ws) {
      coap_session_disconnected(session, COAP_NACK_WS_LAYER_FAILED);
      return;
    }
    memset(session->ws, 0, sizeof(coap_ws_state_t));
  }
  if (session->type == COAP_SESSION_TYPE_CLIENT) {
    char buf[270];
    char base64[28];
    char host[80];
    int port = 0;

    session->ws->state = COAP_SESSION_TYPE_CLIENT;
    if (!session->ws_host) {
      coap_log_err("WS Host not defined\n");
      coap_session_disconnected(session, COAP_NACK_WS_LAYER_FAILED);
      return;
    }
    coap_prng(session->ws->key, sizeof(session->ws->key));
    coap_ws_log_key(session);
    if (!coap_base64_encode_buffer(session->ws->key, sizeof(session->ws->key),
                                   base64, sizeof(base64)))
      return;
    if (session->proto == COAP_PROTO_WS &&
        coap_address_get_port(&session->addr_info.remote) != 80) {
      port = coap_address_get_port(&session->addr_info.remote);
    } else if (session->proto == COAP_PROTO_WSS &&
               coap_address_get_port(&session->addr_info.remote) != 443) {
      port = coap_address_get_port(&session->addr_info.remote);
    }
    if (strchr((const char *)session->ws_host->s, ':')) {
      if (port) {
        snprintf(host, sizeof(host), "[%s]:%d", session->ws_host->s, port);
      } else {
        snprintf(host, sizeof(host), "[%s]", session->ws_host->s);
      }
    } else {
      if (port) {
        snprintf(host, sizeof(host), "%s:%d", session->ws_host->s, port);
      } else {
        snprintf(host, sizeof(host), "%s", session->ws_host->s);
      }
    }
    snprintf(buf, sizeof(buf), COAP_WS_REQUEST, host, base64);
    coap_log_debug("WS Request\n%s", buf);
    session->sock.lfunc[COAP_LAYER_WS].l_write(session, (uint8_t *)buf,
                                               strlen(buf));
  } else {
    session->ws->state = COAP_SESSION_TYPE_SERVER;
  }
}

void
coap_ws_close(coap_session_t *session) {
  if (!coap_netif_available(session) ||
      session->state == COAP_SESSION_STATE_NONE) {
    session->sock.lfunc[COAP_LAYER_WS].l_close(session);
    return;
  }
  if (session->ws && session->ws->up) {
    int count;

    if (!session->ws->sent_close) {
      size_t hdr_len = 2;
      uint8_t ws_header[COAP_MAX_FS];
      size_t ret;

      ws_header[0] = WS_B0_FIN_BIT | WS_OP_CLOSE;
      ws_header[1] = 2;
      if (session->ws->state == COAP_SESSION_TYPE_CLIENT) {
        /* Need to set the Mask bit, and set the masking key */
        ws_header[1] |= WS_B1_MASK_BIT;
        coap_prng(&ws_header[hdr_len], 4);
        memcpy(session->ws->mask_key, &ws_header[hdr_len], 4);
        hdr_len += 4;
      }
      coap_ws_log_header(session, ws_header);
      if (session->ws->close_reason == 0)
        session->ws->close_reason = 1000;

      ws_header[hdr_len] =  session->ws->close_reason >> 8;
      ws_header[hdr_len+1] =  session->ws->close_reason & 0xff;
      if (session->ws->state == COAP_SESSION_TYPE_CLIENT) {
        coap_ws_mask_data(session, &ws_header[hdr_len], 2);
      }
      session->ws->sent_close = 1;
      coap_log_debug("*  %s: WS: Close sent (%u)\n",
                     coap_session_str(session),
                     session->ws->close_reason);
      ret = session->sock.lfunc[COAP_LAYER_WS].l_write(session, ws_header, hdr_len+2);
      if (ret != hdr_len+2) {
        return;
      }
    }
    count = 5;
    while (!session->ws->recv_close && count > 0 && coap_netif_available(session)) {
      uint8_t buf[100];
      fd_set readfds;
      int result;
      struct timeval tv;

      FD_ZERO(&readfds);
      FD_SET(session->sock.fd, &readfds);
      tv.tv_sec = 0;
      tv.tv_usec = 1000;
      result = select((int)(session->sock.fd+1), &readfds, NULL, NULL, &tv);

      if (result < 0) {
        break;
      } else if (result > 0) {
        coap_ws_read(session, buf, sizeof(buf));
      }
      count --;
    }
    coap_handle_event(session->context, COAP_EVENT_WS_CLOSED, session);
  }
  session->sock.lfunc[COAP_LAYER_WS].l_close(session);
}

int
coap_ws_set_host_request(coap_session_t *session, coap_str_const_t *ws_host) {
  if (!session | !ws_host)
    return 0;

  session->ws_host = coap_new_str_const(ws_host->s, ws_host->length);
  if (!session->ws_host)
    return 0;
  return 1;
}

#else /* !COAP_WS_SUPPORT */

int
coap_ws_is_supported(void) {
  return 0;
}

int
coap_wss_is_supported(void) {
  return 0;
}

int
coap_ws_set_host_request(coap_session_t *session, coap_str_const_t *ws_host) {
  (void)session;
  (void)ws_host;
  return 0;
}

#endif /* !COAP_WS_SUPPORT */
