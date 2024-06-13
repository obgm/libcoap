/* libcoap unit tests
 *
 * Copyright (C) 2012,2015,2022-2024 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#include "test_common.h"
#include "test_uri.h"

#include <stdio.h>

static void
t_parse_uri1(void) {
  char teststr[] = "coap://[::1]/.well-known/core";

  int result;
  coap_uri_t uri;

  result = coap_split_uri((unsigned char *)teststr, strlen(teststr), &uri);
  if (result == 0) {
    CU_ASSERT(uri.host.length == 3);
    CU_ASSERT_NSTRING_EQUAL(uri.host.s, "::1", 3);

    CU_ASSERT(uri.port == COAP_DEFAULT_PORT);

    CU_ASSERT(uri.path.length == 16);
    CU_ASSERT_NSTRING_EQUAL(uri.path.s, ".well-known/core", 16);

    CU_ASSERT(uri.query.length == 0);
    CU_ASSERT(uri.query.s == NULL);
  } else {
    CU_FAIL("uri parser error");
  }
}

static void
t_parse_uri2(void) {
  char teststr[] = "coap://[::1]:8000/.well-known/core";
  int result;
  coap_uri_t uri;

  result = coap_split_uri((unsigned char *)teststr, strlen(teststr), &uri);
  if (result == 0) {
    CU_ASSERT(uri.host.length == 3);
    CU_ASSERT_NSTRING_EQUAL(uri.host.s, "::1", 3);

    CU_ASSERT(uri.port == 8000);

    CU_ASSERT(uri.path.length == 16);
    CU_ASSERT_NSTRING_EQUAL(uri.path.s, ".well-known/core", 16);

    CU_ASSERT(uri.query.length == 0);
    CU_ASSERT(uri.query.s == NULL);
  } else {
    CU_FAIL("uri parser error");
  }
}

static void
t_parse_uri3(void) {
  char teststr[] = "coap://localhost/?foo&bla=fasel";
  int result;
  coap_uri_t uri;

  result = coap_split_uri((unsigned char *)teststr, strlen(teststr), &uri);
  if (result == 0) {
    CU_ASSERT(uri.host.length == 9);
    CU_ASSERT_NSTRING_EQUAL(uri.host.s, "localhost", 9);

    CU_ASSERT(uri.port == COAP_DEFAULT_PORT);

    CU_ASSERT(uri.path.length == 0);

    CU_ASSERT(uri.query.length == 13);
    CU_ASSERT_NSTRING_EQUAL(uri.query.s, "foo&bla=fasel", 13);
  } else {
    CU_FAIL("uri parser error");
  }
}

static void
t_parse_uri4(void) {
  char teststr[] = "coap://:100000";
  int result;
  coap_uri_t uri;

  result = coap_split_uri((unsigned char *)teststr, strlen(teststr), &uri);
  CU_ASSERT(result < 0);
}

static void
t_parse_uri5(void) {
  char teststr[] = "coap://foo:100000";
  int result;
  coap_uri_t uri;

  result = coap_split_uri((unsigned char *)teststr, strlen(teststr), &uri);
  if (result == 0) {
    CU_ASSERT(uri.host.length == 3);
    CU_ASSERT_NSTRING_EQUAL(uri.host.s, "foo", 3);

    CU_ASSERT(uri.path.length == 0);
    CU_ASSERT(uri.path.s == NULL);

    CU_ASSERT(uri.query.length == 0);
    CU_ASSERT(uri.query.s == NULL);

    CU_FAIL("invalid port not detected");
  } else {
    CU_PASS("detected invalid port");
  }
}

static void
t_parse_uri6(void) {
  char teststr[] = "coap://134.102.218.2/.well-known/core";
  int result;
  coap_uri_t uri;

  result = coap_split_uri((unsigned char *)teststr, strlen(teststr), &uri);
  if (result == 0) {
    CU_ASSERT(uri.host.length == 13);
    CU_ASSERT_NSTRING_EQUAL(uri.host.s, "134.102.218.2", 13);

    CU_ASSERT(uri.port == COAP_DEFAULT_PORT);

    CU_ASSERT(uri.path.length == 16);
    CU_ASSERT_NSTRING_EQUAL(uri.path.s, ".well-known/core", 16);

    CU_ASSERT(uri.query.length == 0);
    CU_ASSERT(uri.query.s == NULL);
  } else {
    CU_FAIL("uri parser error");
  }
}

static void
t_parse_uri7(void) {
  char teststr[] = "coap://foo.bar:5683/some_resource/with/multiple/segments";
  int result;
  coap_uri_t uri;
  unsigned char buf[40];
  size_t buflen = sizeof(buf);
  coap_optlist_t *optlist_chain = NULL;
  coap_pdu_t *pdu = NULL;

  /* The list of path segments to check against. Each segment is
     preceded by a dummy option indicating that holds the (dummy)
     delta value 0 and the actual segment length. */
  const uint8_t checkbuf[] = {
    0x0d, 0x00, 's', 'o', 'm', 'e', '_', 'r', 'e', 's', 'o', 'u', 'r', 'c', 'e',
    0x04, 'w', 'i', 't', 'h',
    0x08, 'm', 'u', 'l', 't', 'i', 'p', 'l', 'e',
    0x08, 's', 'e', 'g', 'm', 'e', 'n', 't', 's'
  };

  result = coap_split_uri((unsigned char *)teststr, strlen(teststr), &uri);
  if (result == 0) {
    CU_ASSERT(uri.host.length == 7);
    CU_ASSERT_NSTRING_EQUAL(uri.host.s, "foo.bar", 7);

    CU_ASSERT(uri.port == 5683);

    CU_ASSERT(uri.path.length == 36);
    CU_ASSERT_NSTRING_EQUAL(uri.path.s, "some_resource/with/multiple/segments", 36);

    CU_ASSERT(uri.query.length == 0);
    CU_ASSERT(uri.query.s == NULL);

    /* check path segments */
    result = coap_split_path(uri.path.s, uri.path.length, buf, &buflen);
    CU_ASSERT(result == 4);
    CU_ASSERT(buflen == sizeof(checkbuf));
    CU_ASSERT_NSTRING_EQUAL(buf, checkbuf, buflen);

    result = coap_path_into_optlist(uri.path.s, uri.path.length, 0, &optlist_chain);
    CU_ASSERT(result == 1);
    pdu = coap_pdu_init(0, 0, 0, 128);
    CU_ASSERT(pdu != NULL);
    assert(pdu != NULL);
    result = coap_add_optlist_pdu(pdu, &optlist_chain);
    CU_ASSERT(result == 1);
    coap_delete_optlist(optlist_chain);
    CU_ASSERT(pdu->used_size == sizeof(checkbuf));
    CU_ASSERT_NSTRING_EQUAL(pdu->token, checkbuf, pdu->used_size);
    coap_delete_pdu(pdu);
  } else {
    CU_FAIL("uri parser error");
  }
}

static void
t_parse_uri8(void) {
  coap_log_t level = coap_get_log_level();
  char teststr[] = "http://example.com/%7E%AB%13";
  int result;
  coap_uri_t uri;

  coap_set_log_level(COAP_LOG_CRIT);
  result = coap_split_uri((unsigned char *)teststr, strlen(teststr), &uri);
  coap_set_log_level(level);
  if (result < 0) {
    CU_PASS("detected non-coap URI");
  } else {
    CU_FAIL("non-coap URI not recognized");
  }
}

static void
t_parse_uri9(void) {
  coap_log_t level = coap_get_log_level();
  char teststr[] = "http://example.com/%x";
  int result;
  coap_uri_t uri;

  coap_set_log_level(COAP_LOG_CRIT);
  result = coap_split_uri((unsigned char *)teststr, strlen(teststr), &uri);
  coap_set_log_level(level);
  if (result < 0) {
    CU_PASS("detected non-coap URI");
  } else {
    CU_FAIL("non-coap URI not recognized");
  }
}

static void
t_parse_uri10(void) {
  char teststr[] = "/absolute/path";
  int result;
  coap_uri_t uri;

  result = coap_split_uri((unsigned char *)teststr, strlen(teststr), &uri);
  if (result == 0) {
    CU_ASSERT(uri.host.length == 0);
    CU_ASSERT(uri.host.s == NULL);

    CU_ASSERT(uri.port == COAP_DEFAULT_PORT);

    CU_ASSERT(uri.path.length == 13);
    CU_ASSERT_NSTRING_EQUAL(uri.path.s, "absolute/path", 13);

    CU_ASSERT(uri.query.length == 0);
    CU_ASSERT(uri.query.s == NULL);
  } else {
    CU_FAIL("uri parser error");
  }
}

static void
t_parse_uri11(void) {
  char teststr[] =
      "coap://xn--18j4d.example/%E3%81%93%E3%82%93%E3%81%AB%E3%81%A1%E3%81%AF";
  int result;
  coap_uri_t uri;
  unsigned char buf[40];
  size_t buflen = sizeof(buf);
  coap_optlist_t *optlist_chain = NULL;
  coap_pdu_t *pdu = NULL;

  /* The list of path segments to check against. Each segment is
     preceded by a dummy option indicating that holds the (dummy)
     delta value 0 and the actual segment length. */
  const uint8_t checkbuf[] = {
    0x0d, 0x02, 0xE3, 0x81, 0x93, 0xE3, 0x82, 0x93,
    0xE3, 0x81, 0xAB, 0xE3, 0x81, 0xA1, 0xE3, 0x81,
    0xAF
  };

  result = coap_split_uri((unsigned char *)teststr, strlen(teststr), &uri);
  if (result == 0) {
    CU_ASSERT(uri.host.length == 17);
    CU_ASSERT_NSTRING_EQUAL(uri.host.s, "xn--18j4d.example", 17);

    CU_ASSERT(uri.port == COAP_DEFAULT_PORT);

    CU_ASSERT(uri.path.length == 45);
    CU_ASSERT_NSTRING_EQUAL(uri.path.s,
                            "%E3%81%93%E3%82%93%E3%81%AB%E3%81%A1%E3%81%AF", 45);

    CU_ASSERT(uri.query.length == 0);
    CU_ASSERT(uri.query.s == NULL);

    /* check path segments */
    result = coap_split_path(uri.path.s, uri.path.length, buf, &buflen);
    CU_ASSERT(result == 1);
    CU_ASSERT(buflen == sizeof(checkbuf));
    CU_ASSERT_NSTRING_EQUAL(buf, checkbuf, buflen);

    result = coap_path_into_optlist(uri.path.s, uri.path.length, 0, &optlist_chain);
    CU_ASSERT(result == 1);
    pdu = coap_pdu_init(0, 0, 0, 128);
    CU_ASSERT(pdu != NULL);
    assert(pdu != NULL);
    result = coap_add_optlist_pdu(pdu, &optlist_chain);
    CU_ASSERT(result == 1);
    coap_delete_optlist(optlist_chain);
    CU_ASSERT(pdu->used_size == sizeof(checkbuf));
    CU_ASSERT_NSTRING_EQUAL(pdu->token, checkbuf, pdu->used_size);
    coap_delete_pdu(pdu);
  } else {
    CU_FAIL("uri parser error");
  }
}

static void
t_parse_uri12(void) {
  char teststr[] = "coap://198.51.100.1:61616//%2F//?%2F%2F&?%26";
  int result;
  coap_uri_t uri;
  unsigned char buf[40];
  size_t buflen = sizeof(buf);
  coap_optlist_t *optlist_chain = NULL;
  coap_pdu_t *pdu = NULL;

  /* The list of path segments to check against. Each segment is
     preceded by a dummy option indicating that holds the (dummy)
     delta value 0 and the actual segment length. */
  const uint8_t uricheckbuf[] = { 0x00, 0x01, 0x2f, 0x00, 0x00 };
  const uint8_t querycheckbuf[] = { 0x02, 0x2f, 0x2f, 0x02, 0x3f, 0x26 };

  result = coap_split_uri((unsigned char *)teststr, strlen(teststr), &uri);
  if (result == 0) {
    CU_ASSERT(uri.host.length == 12);
    CU_ASSERT_NSTRING_EQUAL(uri.host.s, "198.51.100.1", 12);

    CU_ASSERT(uri.port == 61616);

    CU_ASSERT(uri.path.length == 6);
    CU_ASSERT_NSTRING_EQUAL(uri.path.s, "/%2F//", 6);

    CU_ASSERT(uri.query.length == 11);
    CU_ASSERT_NSTRING_EQUAL(uri.query.s, "%2F%2F&?%26", 11);

    /* check path segments */
    result = coap_split_path(uri.path.s, uri.path.length, buf, &buflen);
    CU_ASSERT(result == 4);
    CU_ASSERT(buflen == sizeof(uricheckbuf));
    CU_ASSERT_NSTRING_EQUAL(buf, uricheckbuf, buflen);

    result = coap_path_into_optlist(uri.path.s, uri.path.length, 0, &optlist_chain);
    CU_ASSERT(result == 1);
    pdu = coap_pdu_init(0, 0, 0, 128);
    CU_ASSERT(pdu != NULL);
    assert(pdu != NULL);
    result = coap_add_optlist_pdu(pdu, &optlist_chain);
    CU_ASSERT(result == 1);
    coap_delete_optlist(optlist_chain);
    CU_ASSERT(pdu->used_size == sizeof(uricheckbuf));
    CU_ASSERT_NSTRING_EQUAL(pdu->token, uricheckbuf, pdu->used_size);
    coap_delete_pdu(pdu);

    /* check query segments */
    buflen = sizeof(buf);
    result = coap_split_query(uri.query.s, uri.query.length, buf, &buflen);
    CU_ASSERT(result == 2);
    CU_ASSERT(buflen == sizeof(querycheckbuf));
    CU_ASSERT_NSTRING_EQUAL(buf, querycheckbuf, buflen);
    optlist_chain = NULL;
    result = coap_query_into_optlist(uri.query.s, uri.query.length, 0, &optlist_chain);
    CU_ASSERT(result == 1);
    pdu = coap_pdu_init(0, 0, 0, 128);
    CU_ASSERT(pdu != NULL);
    assert(pdu != NULL);
    result = coap_add_optlist_pdu(pdu, &optlist_chain);
    CU_ASSERT(result == 1);
    coap_delete_optlist(optlist_chain);
    CU_ASSERT(pdu->used_size == sizeof(querycheckbuf));
    CU_ASSERT_NSTRING_EQUAL(pdu->token, querycheckbuf, pdu->used_size);
    coap_delete_pdu(pdu);
  } else {
    CU_FAIL("uri parser error");
  }
}

#ifdef _MSC_VER
#  define ALIGNED(x)
#else
#  define ALIGNED(x) __attribute__ ((aligned (x)))
#endif

static void
t_parse_uri13(void) {
  uint8_t teststr[] ALIGNED(8) = {
    0x80, 0x03, 'f',  'o',
    'o',  0x3b, '.',  'w',  'e',  'l',  'l',  '-',
    'k',  'n',  'o',  'w',  'n',  0x04,  'c', 'o',
    'r',  'e'
  };

  coap_pdu_t pdu = {
    .max_size = sizeof(teststr),
    .e_token_length = 0,
    .token = teststr,
    .used_size = sizeof(teststr)
  };

  coap_string_t *uri_path = coap_get_uri_path(&pdu);

  CU_ASSERT(uri_path->length == sizeof(COAP_DEFAULT_URI_WELLKNOWN)-1);
  CU_ASSERT_NSTRING_EQUAL(uri_path->s, COAP_DEFAULT_URI_WELLKNOWN,
                          sizeof(COAP_DEFAULT_URI_WELLKNOWN)-1);
  coap_delete_string(uri_path);
}

static void
t_parse_uri14(void) {
  char teststr[] =
      "longerthan13lessthan270=0123456789012345678901234567890123456789";
  int result;
  coap_optlist_t *optlist_chain = NULL;
  coap_pdu_t *pdu = NULL;

  /* buf is large enough to hold sizeof(teststr) - 1 bytes content and
   * 2 bytes for the option header. */
  unsigned char buf[sizeof(teststr) + 1];
  size_t buflen = sizeof(buf);

  result = coap_split_query((unsigned char *)teststr, strlen(teststr),
                            buf, &buflen);
  if (result >= 0) {
    CU_ASSERT(buf[0] == 0x0d);
    CU_ASSERT(buf[1] == strlen(teststr) - 13);

    CU_ASSERT_NSTRING_EQUAL(buf+2, teststr, strlen(teststr));

    result = coap_query_into_optlist((unsigned char *)teststr,
                                     strlen(teststr), 0, &optlist_chain);
    CU_ASSERT(result == 1);
    pdu = coap_pdu_init(0, 0, 0, 128);
    CU_ASSERT(pdu != NULL);
    assert(pdu != NULL);
    result = coap_add_optlist_pdu(pdu, &optlist_chain);
    CU_ASSERT(result == 1);
    coap_delete_optlist(optlist_chain);
    CU_ASSERT(pdu->token[0] == 0x0d);
    CU_ASSERT(pdu->token[1] == strlen(teststr) - 13);
    coap_delete_pdu(pdu);
  } else {
    CU_FAIL("uri parser error");
  }
}

static void
t_parse_uri15(void) {
  char teststr[] =
      "longerthan13lessthan270=0123456789012345678901234567890123456789";
  int result;

  /* buf is too small to hold sizeof(teststr) - 1 bytes content and 2
   * bytes for the option header. */
  unsigned char buf[sizeof(teststr) - 1];
  size_t buflen = sizeof(buf);

  result = coap_split_query((unsigned char *)teststr, strlen(teststr),
                            buf, &buflen);
  CU_ASSERT(result == 0);
}

static void
t_parse_uri16(void) {
  char teststr[] =
      "longerthan13lessthan270=0123456789012345678901234567890123456789";
  int result;

  /* buf is too small to hold the option header. */
  unsigned char buf[1];
  size_t buflen = sizeof(buf);

  result = coap_split_query((unsigned char *)teststr, strlen(teststr),
                            buf, &buflen);
  CU_ASSERT(result == 0);
}

static void
t_parse_uri17(void) {
  char teststr[] =
      "thisislongerthan269="
      "01234567890123456789012345678901234567890123456789"
      "01234567890123456789012345678901234567890123456789"
      "01234567890123456789012345678901234567890123456789"
      "01234567890123456789012345678901234567890123456789"
      "01234567890123456789012345678901234567890123456789";
  int result;
  coap_optlist_t *optlist_chain = NULL;
  coap_pdu_t *pdu = NULL;

  /* buf is large enough to hold sizeof(teststr) - 1 bytes content and
   * 3 bytes for the option header. */
  unsigned char buf[sizeof(teststr) + 2];
  size_t buflen = sizeof(buf);

  result = coap_split_query((unsigned char *)teststr, strlen(teststr),
                            buf, &buflen);
  if (result >= 0) {
    CU_ASSERT(buf[0] == 0x0e);
    CU_ASSERT(buf[1] == (((strlen(teststr) - 269) >> 8) & 0xff));
    CU_ASSERT(buf[2] == ((strlen(teststr) - 269) & 0xff));

    CU_ASSERT_NSTRING_EQUAL(buf+3, teststr, strlen(teststr));
    result = coap_query_into_optlist((unsigned char *)teststr, strlen(teststr),
                                     0, &optlist_chain);
    CU_ASSERT(result == 1);
    pdu = coap_pdu_init(0, 0, 0, 300);
    CU_ASSERT(pdu != NULL);
    assert(pdu != NULL);
    result = coap_add_optlist_pdu(pdu, &optlist_chain);
    CU_ASSERT(result == 1);
    coap_delete_optlist(optlist_chain);
    CU_ASSERT(pdu->token[0] == 0x0e);
    CU_ASSERT(pdu->token[1] == (((strlen(teststr) - 269) >> 8) & 0xff));
    CU_ASSERT(pdu->token[2] == ((strlen(teststr) - 269) & 0xff));
    coap_delete_pdu(pdu);
  } else {
    CU_FAIL("uri parser error");
  }
}

static void
t_parse_uri18(void) {
  uint8_t token[1] = "";
  coap_pdu_t pdu = {
    .max_size = 0,
    .e_token_length = 0,
    .token = token,
    .used_size = 0
  };

  coap_string_t *uri_path = coap_get_uri_path(&pdu);

  CU_ASSERT(uri_path->length == 0);
#if 0
  /* Currently this is not the case - Issue #167 */
  /* strings are stored with terminating zero */
  CU_ASSERT_NSTRING_EQUAL(uri_path->s, "", 1);
#endif
  coap_delete_string(uri_path);
}

static void
t_parse_uri19(void) {
  uint8_t teststr[] ALIGNED(8) = {
    0xb3, 'f', 'o', 'o',
    0x00                  /* "foo/" as Uri-Path options */
  };

  coap_pdu_t pdu = {
    .max_size = sizeof(teststr),
    .e_token_length = 0,
    .token = teststr,
    .used_size = sizeof(teststr)
  };

  coap_string_t *uri_path = coap_get_uri_path(&pdu);

  CU_ASSERT(uri_path->length == 4);
  CU_ASSERT_NSTRING_EQUAL(uri_path->s, "foo/", 4);
  coap_delete_string(uri_path);
}

static void
t_parse_uri20(void) {
  uint8_t teststr[] ALIGNED(8) = {
    0xb0, 0x00                  /* "//" as Uri-Path options */
  };

  coap_pdu_t pdu = {
    .max_size = sizeof(teststr),
    .e_token_length = 0,
    .token = teststr,
    .used_size = sizeof(teststr)
  };

  coap_string_t *uri_path = coap_get_uri_path(&pdu);

  /* The leading '/' is stripped hence only one '/' remains. */
  CU_ASSERT(uri_path->length == 1);
  CU_ASSERT_NSTRING_EQUAL(uri_path->s, "/", 1);
  coap_delete_string(uri_path);
}

static void
t_parse_uri21(void) {
  uint8_t teststr[] ALIGNED(8) = {
    0xb0, 0x03, 'f', 'o', 'o'   /* "//foo" as Uri-Path options */
  };

  coap_pdu_t pdu = {
    .max_size = sizeof(teststr),
    .e_token_length = 0,
    .token = teststr,
    .used_size = sizeof(teststr)
  };

  coap_string_t *uri_path = coap_get_uri_path(&pdu);

  /* The leading '/' is stripped hence only one '/' remains. */
  CU_ASSERT(uri_path->length == 4);
  CU_ASSERT_NSTRING_EQUAL(uri_path->s, "/foo", 4);
  coap_delete_string(uri_path);
}

static void
t_parse_uri22(void) {
  uint8_t teststr[] ALIGNED(8) = {
    /* characters that are not percent-encoded in a path segment */
    0xba, '-', '.', '_', '~', '!', '$', '&', '\'', '(', ')',
    0x05, '*', '+', ',', ';', '='
  };

  coap_pdu_t pdu = {
    .max_size = sizeof(teststr),
    .e_token_length = 0,
    .token = teststr,
    .used_size = sizeof(teststr)
  };

  coap_string_t *uri_path = coap_get_uri_path(&pdu);

  CU_ASSERT(uri_path->length == 16);
  CU_ASSERT_NSTRING_EQUAL(uri_path->s, "-._~!$&'()/*+,;=", 16);
  coap_delete_string(uri_path);
}

static void
t_parse_uri23(void) {
  uint8_t teststr[] ALIGNED(8) = {
    /* characters that must be percent-encoded in a path segment */
    0xb5, '%', ' ', '#', '[', ']'
  };

  coap_pdu_t pdu = {
    .max_size = sizeof(teststr),
    .e_token_length = 0,
    .token = teststr,
    .used_size = sizeof(teststr)
  };

  coap_string_t *uri_path = coap_get_uri_path(&pdu);

  CU_ASSERT(uri_path->length == 15);
  CU_ASSERT_NSTRING_EQUAL(uri_path->s, "%25%20%23%5B%5D", 15);
  coap_delete_string(uri_path);
}

/*
 * To test Issue #212 which reads off the end of the input buffer when looking
 * for . or .. in the path.
 * Credit to OSS-Fuzz for finding this, work done by Bhargava Shastry
 */
static void
t_parse_uri24(void) {
  /* coap://\206coap:// */
  uint8_t teststr[] = { 0x63, 0x6f, 0x61, 0x70, 0x3a, 0x2f, 0x2f, 0x86, 0x63, 0x6f, 0x61, 0x70, 0x3a, 0x2f, 0x2f };
  int result;
  unsigned char buf[40];
  size_t buflen = sizeof(buf);
  coap_optlist_t *optlist_chain = NULL;
  coap_pdu_t *pdu = NULL;

  result = coap_split_path(teststr, sizeof(teststr), buf, &buflen);
  CU_ASSERT(result == 5);
  CU_ASSERT(buflen == 16);

  result = coap_path_into_optlist(teststr, sizeof(teststr), 0, &optlist_chain);
  CU_ASSERT(result == 1);
  pdu = coap_pdu_init(0, 0, 0, 128);
  CU_ASSERT(pdu != NULL);
  assert(pdu != NULL);
  result = coap_add_optlist_pdu(pdu, &optlist_chain);
  CU_ASSERT(result == 1);
  coap_delete_optlist(optlist_chain);
  CU_ASSERT(pdu->used_size == 16);
  coap_delete_pdu(pdu);
}

static void
t_parse_uri25(void) {
  char teststr[] = "coap://198.51.100.1:61616//%2E//%2E%2E/./../a?%2e%2F&?%26";
  int result;
  coap_uri_t uri;
  unsigned char buf[40];
  size_t buflen = sizeof(buf);
  coap_optlist_t *optlist_chain = NULL;
  coap_pdu_t *pdu = NULL;

  /* The list of path segments to check against. Each segment is
     preceded by a dummy option indicating that holds the (dummy)
     delta value 0 and the actual segment length. */
  const uint8_t uricheckbuf[] = { 0x01, 0x61 };
  const uint8_t querycheckbuf[] = { 0x02, 0x2e, 0x2f, 0x02, 0x3f, 0x26 };

  result = coap_split_uri((unsigned char *)teststr, strlen(teststr), &uri);
  if (result == 0) {
    CU_ASSERT(uri.host.length == 12);
    CU_ASSERT_NSTRING_EQUAL(uri.host.s, "198.51.100.1", 12);

    CU_ASSERT(uri.port == 61616);

    CU_ASSERT(uri.path.length == 19);
    CU_ASSERT_NSTRING_EQUAL(uri.path.s, "/%2E//%2E%2E/./../a", 19);

    CU_ASSERT(uri.query.length == 11);
    CU_ASSERT_NSTRING_EQUAL(uri.query.s, "%2e%2F&?%26", 11);

    /* check path segments */
    result = coap_split_path(uri.path.s, uri.path.length, buf, &buflen);
    CU_ASSERT(result == 1);
    CU_ASSERT(buflen == sizeof(uricheckbuf));
    CU_ASSERT_NSTRING_EQUAL(buf, uricheckbuf, buflen);

    result = coap_path_into_optlist(uri.path.s, uri.path.length, 0, &optlist_chain);
    CU_ASSERT(result == 1);
    pdu = coap_pdu_init(0, 0, 0, 128);
    CU_ASSERT(pdu != NULL);
    assert(pdu != NULL);
    result = coap_add_optlist_pdu(pdu, &optlist_chain);
    CU_ASSERT(result == 1);
    coap_delete_optlist(optlist_chain);
    CU_ASSERT(pdu->used_size == sizeof(uricheckbuf));
    CU_ASSERT_NSTRING_EQUAL(pdu->token, uricheckbuf, pdu->used_size);
    coap_delete_pdu(pdu);

    /* check query segments */
    buflen = sizeof(buf);
    result = coap_split_query(uri.query.s, uri.query.length, buf, &buflen);
    CU_ASSERT(result == 2);
    CU_ASSERT(buflen == sizeof(querycheckbuf));
    CU_ASSERT_NSTRING_EQUAL(buf, querycheckbuf, buflen);
    optlist_chain = NULL;

    result = coap_query_into_optlist(uri.query.s, uri.query.length, 0, &optlist_chain);
    CU_ASSERT(result == 1);
    pdu = coap_pdu_init(0, 0, 0, 128);
    CU_ASSERT(pdu != NULL);
    assert(pdu != NULL);
    result = coap_add_optlist_pdu(pdu, &optlist_chain);
    CU_ASSERT(result == 1);
    coap_delete_optlist(optlist_chain);
    CU_ASSERT(pdu->used_size == sizeof(querycheckbuf));
    CU_ASSERT_NSTRING_EQUAL(pdu->token, querycheckbuf, pdu->used_size);
    coap_delete_pdu(pdu);
  } else {
    CU_FAIL("uri parser error");
  }
}

static void
t_parse_uri26(void) {
  char teststr[] = "coap://198.51.100.1:61616//a/?a=b";
  int result;
  coap_uri_t uri;
  unsigned char buf[40];
  size_t buflen = sizeof(buf);
  coap_optlist_t *optlist_chain = NULL;
  coap_pdu_t *pdu = NULL;

  /* The list of path segments to check against. Each segment is
     preceded by a dummy option indicating that holds the (dummy)
     delta value 0 and the actual segment length. */
  const uint8_t uricheckbuf[] = { 0x00, 0x01, 0x61, 0x00 };
  const uint8_t querycheckbuf[] = { 0x03, 0x61, 0x3d, 0x62 };

  result = coap_split_uri((unsigned char *)teststr, strlen(teststr), &uri);
  if (result == 0) {
    CU_ASSERT(uri.host.length == 12);
    CU_ASSERT_NSTRING_EQUAL(uri.host.s, "198.51.100.1", 12);

    CU_ASSERT(uri.port == 61616);

    CU_ASSERT(uri.path.length == 3);
    CU_ASSERT_NSTRING_EQUAL(uri.path.s, "/a/", 3);

    CU_ASSERT(uri.query.length == 3);
    CU_ASSERT_NSTRING_EQUAL(uri.query.s, "a=b", 3);

    /* check path segments */
    result = coap_split_path(uri.path.s, uri.path.length, buf, &buflen);
    CU_ASSERT(result == 3);
    CU_ASSERT(buflen == sizeof(uricheckbuf));
    CU_ASSERT_NSTRING_EQUAL(buf, uricheckbuf, buflen);

    result = coap_path_into_optlist(uri.path.s, uri.path.length, 0, &optlist_chain);
    CU_ASSERT(result == 1);
    pdu = coap_pdu_init(0, 0, 0, 128);
    CU_ASSERT(pdu != NULL);
    assert(pdu != NULL);
    result = coap_add_optlist_pdu(pdu, &optlist_chain);
    CU_ASSERT(result == 1);
    coap_delete_optlist(optlist_chain);
    CU_ASSERT(pdu->used_size == sizeof(uricheckbuf));
    CU_ASSERT_NSTRING_EQUAL(pdu->token, uricheckbuf, pdu->used_size);
    coap_delete_pdu(pdu);

    /* check query segments */
    buflen = sizeof(buf);
    result = coap_split_query(uri.query.s, uri.query.length, buf, &buflen);
    CU_ASSERT(result == 1);
    CU_ASSERT(buflen == sizeof(querycheckbuf));
    CU_ASSERT_NSTRING_EQUAL(buf, querycheckbuf, buflen);
    optlist_chain = NULL;

    result = coap_query_into_optlist(uri.query.s, uri.query.length, 0, &optlist_chain);
    CU_ASSERT(result == 1);
    pdu = coap_pdu_init(0, 0, 0, 128);
    CU_ASSERT(pdu != NULL);
    assert(pdu != NULL);
    result = coap_add_optlist_pdu(pdu, &optlist_chain);
    CU_ASSERT(result == 1);
    coap_delete_optlist(optlist_chain);
    CU_ASSERT(pdu->used_size == sizeof(querycheckbuf));
    CU_ASSERT_NSTRING_EQUAL(pdu->token, querycheckbuf, pdu->used_size);
    coap_delete_pdu(pdu);
  } else {
    CU_FAIL("uri parser error");
  }
}

static void
t_parse_uri27(void) {
  char testpath[] = "../a";
  int result;
  coap_optlist_t *optlist_chain = NULL;
  coap_pdu_t *pdu = NULL;
  unsigned char buf[40];
  size_t buflen = sizeof(buf);

  const uint8_t pathcheckbuf_1[] = { 0x01, 0x61 };
  const uint8_t pathcheckbuf_2[] = { 0x34, 0x68, 0x6f, 0x73, 0x74, 0x81, 0x61 };

  result = coap_split_path((uint8_t *)testpath, strlen(testpath), buf, &buflen);
  CU_ASSERT(result == 1);
  CU_ASSERT(buflen == sizeof(pathcheckbuf_1));
  CU_ASSERT_NSTRING_EQUAL(buf, pathcheckbuf_1, buflen);

  result = coap_path_into_optlist((uint8_t *)testpath, strlen(testpath),
                                  0, &optlist_chain);
  CU_ASSERT(result == 1);
  pdu = coap_pdu_init(0, 0, 0, 128);
  CU_ASSERT(pdu != NULL);
  assert(pdu != NULL);
  result = coap_add_optlist_pdu(pdu, &optlist_chain);
  CU_ASSERT(result == 1);
  coap_delete_optlist(optlist_chain);
  CU_ASSERT(pdu->used_size == sizeof(pathcheckbuf_1));
  CU_ASSERT_NSTRING_EQUAL(pdu->token, pathcheckbuf_1, pdu->used_size);
  coap_delete_pdu(pdu);

  optlist_chain = NULL;
  /* Add in a Uri-Host: option to check .. backup */
  coap_insert_optlist(&optlist_chain,
                      coap_new_optlist(COAP_OPTION_URI_HOST,
                                       4,
                                       (const uint8_t *)"host"));
  result = coap_path_into_optlist((uint8_t *)testpath, strlen(testpath),
                                  COAP_OPTION_URI_PATH, &optlist_chain);
  CU_ASSERT(result == 1);
  pdu = coap_pdu_init(0, 0, 0, 128);
  CU_ASSERT(pdu != NULL);
  assert(pdu != NULL);
  result = coap_add_optlist_pdu(pdu, &optlist_chain);
  CU_ASSERT(result == 1);
  coap_delete_optlist(optlist_chain);
  CU_ASSERT(pdu->used_size == sizeof(pathcheckbuf_2));
  CU_ASSERT_NSTRING_EQUAL(pdu->token, pathcheckbuf_2, pdu->used_size);
  coap_delete_pdu(pdu);
}

static void
t_parse_uri28(void) {
  char testpath[] = "a/";
  int result;
  coap_optlist_t *optlist_chain = NULL;
  coap_pdu_t *pdu = NULL;
  unsigned char buf[40];
  size_t buflen = sizeof(buf);

  const uint8_t pathcheckbuf_1[] = { 0x01, 0x61, 0x00 };

  result = coap_split_path((uint8_t *)testpath, strlen(testpath), buf, &buflen);
  CU_ASSERT(result == 2);
  CU_ASSERT(buflen == sizeof(pathcheckbuf_1));
  CU_ASSERT_NSTRING_EQUAL(buf, pathcheckbuf_1, buflen);

  result = coap_path_into_optlist((uint8_t *)testpath, strlen(testpath),
                                  0, &optlist_chain);
  CU_ASSERT(result == 1);
  pdu = coap_pdu_init(0, 0, 0, 128);
  CU_ASSERT(pdu != NULL);
  assert(pdu != NULL);
  result = coap_add_optlist_pdu(pdu, &optlist_chain);
  CU_ASSERT(result == 1);
  coap_delete_optlist(optlist_chain);
  CU_ASSERT(pdu->used_size == sizeof(pathcheckbuf_1));
  CU_ASSERT_NSTRING_EQUAL(pdu->token, pathcheckbuf_1, pdu->used_size);
  coap_delete_pdu(pdu);
}

static void
t_parse_uri29(void) {
  char testpath[] = "a/.";
  int result;
  coap_optlist_t *optlist_chain = NULL;
  coap_pdu_t *pdu = NULL;
  unsigned char buf[40];
  size_t buflen = sizeof(buf);

  const uint8_t pathcheckbuf_1[] = { 0x01, 0x61 };

  result = coap_split_path((uint8_t *)testpath, strlen(testpath), buf, &buflen);
  CU_ASSERT(result == 1);
  CU_ASSERT(buflen == sizeof(pathcheckbuf_1));
  CU_ASSERT_NSTRING_EQUAL(buf, pathcheckbuf_1, buflen);

  result = coap_path_into_optlist((uint8_t *)testpath, strlen(testpath),
                                  0, &optlist_chain);
  CU_ASSERT(result == 1);
  pdu = coap_pdu_init(0, 0, 0, 128);
  CU_ASSERT(pdu != NULL);
  assert(pdu != NULL);
  result = coap_add_optlist_pdu(pdu, &optlist_chain);
  CU_ASSERT(result == 1);
  coap_delete_optlist(optlist_chain);
  CU_ASSERT(pdu->used_size == sizeof(pathcheckbuf_1));
  CU_ASSERT_NSTRING_EQUAL(pdu->token, pathcheckbuf_1, pdu->used_size);
  coap_delete_pdu(pdu);
}

static void
t_parse_uri30(void) {
  char testpath[] = "a/..";
  int result;
  coap_optlist_t *optlist_chain = NULL;
  coap_pdu_t *pdu = NULL;
  unsigned char buf[40];
  size_t buflen = sizeof(buf);

  result = coap_split_path((uint8_t *)testpath, strlen(testpath), buf, &buflen);
  CU_ASSERT(result == 0);
  CU_ASSERT(buflen == 0);

  result = coap_path_into_optlist((uint8_t *)testpath, strlen(testpath),
                                  0, &optlist_chain);
  CU_ASSERT(result == 1);
  pdu = coap_pdu_init(0, 0, 0, 128);
  CU_ASSERT(pdu != NULL);
  assert(pdu != NULL);
  result = coap_add_optlist_pdu(pdu, &optlist_chain);
  CU_ASSERT(result == 1);
  coap_delete_optlist(optlist_chain);
  CU_ASSERT(pdu->used_size == 0);
  coap_delete_pdu(pdu);
}

static void
t_parse_uri31(void) {
  char testpath[] = "a/../";
  int result;
  coap_optlist_t *optlist_chain = NULL;
  coap_pdu_t *pdu = NULL;
  unsigned char buf[40];
  size_t buflen = sizeof(buf);

  const uint8_t pathcheckbuf_1[] = { 0x00 };

  result = coap_split_path((uint8_t *)testpath, strlen(testpath), buf, &buflen);
  CU_ASSERT(result == 1);
  CU_ASSERT(buflen == sizeof(pathcheckbuf_1));
  CU_ASSERT_NSTRING_EQUAL(buf, pathcheckbuf_1, buflen);

  result = coap_path_into_optlist((uint8_t *)testpath, strlen(testpath),
                                  0, &optlist_chain);
  CU_ASSERT(result == 1);
  pdu = coap_pdu_init(0, 0, 0, 128);
  CU_ASSERT(pdu != NULL);
  assert(pdu != NULL);
  result = coap_add_optlist_pdu(pdu, &optlist_chain);
  CU_ASSERT(result == 1);
  coap_delete_optlist(optlist_chain);
  CU_ASSERT(pdu->used_size == sizeof(pathcheckbuf_1));
  CU_ASSERT_NSTRING_EQUAL(pdu->token, pathcheckbuf_1, pdu->used_size);
  coap_delete_pdu(pdu);
}

static void
t_parse_uri32(void) {
  char testpath[] = "a/.b";
  int result;
  coap_optlist_t *optlist_chain = NULL;
  coap_pdu_t *pdu = NULL;
  unsigned char buf[40];
  size_t buflen = sizeof(buf);

  const uint8_t pathcheckbuf_1[] = { 0x01, 0x61, 0x2, 0x2e, 0x62 };

  result = coap_split_path((uint8_t *)testpath, strlen(testpath), buf, &buflen);
  CU_ASSERT(result == 2);
  CU_ASSERT(buflen == sizeof(pathcheckbuf_1));
  CU_ASSERT_NSTRING_EQUAL(buf, pathcheckbuf_1, buflen);

  result = coap_path_into_optlist((uint8_t *)testpath, strlen(testpath),
                                  0, &optlist_chain);
  CU_ASSERT(result == 1);
  pdu = coap_pdu_init(0, 0, 0, 128);
  CU_ASSERT(pdu != NULL);
  assert(pdu != NULL);
  result = coap_add_optlist_pdu(pdu, &optlist_chain);
  CU_ASSERT(result == 1);
  coap_delete_optlist(optlist_chain);
  CU_ASSERT(pdu->used_size == sizeof(pathcheckbuf_1));
  CU_ASSERT_NSTRING_EQUAL(pdu->token, pathcheckbuf_1, pdu->used_size);
  coap_delete_pdu(pdu);
}

static void
t_parse_uri33(void) {
  char testpath[] = "a/..b";
  int result;
  coap_optlist_t *optlist_chain = NULL;
  coap_pdu_t *pdu = NULL;
  unsigned char buf[40];
  size_t buflen = sizeof(buf);

  const uint8_t pathcheckbuf_1[] = { 0x01, 0x61, 0x3, 0x2e, 0x2e, 0x62 };

  result = coap_split_path((uint8_t *)testpath, strlen(testpath), buf, &buflen);
  CU_ASSERT(result == 2);
  CU_ASSERT(buflen == sizeof(pathcheckbuf_1));
  CU_ASSERT_NSTRING_EQUAL(buf, pathcheckbuf_1, buflen);

  result = coap_path_into_optlist((uint8_t *)testpath, strlen(testpath),
                                  0, &optlist_chain);
  CU_ASSERT(result == 1);
  pdu = coap_pdu_init(0, 0, 0, 128);
  CU_ASSERT(pdu != NULL);
  assert(pdu != NULL);
  result = coap_add_optlist_pdu(pdu, &optlist_chain);
  CU_ASSERT(result == 1);
  coap_delete_optlist(optlist_chain);
  CU_ASSERT(pdu->used_size == sizeof(pathcheckbuf_1));
  CU_ASSERT_NSTRING_EQUAL(pdu->token, pathcheckbuf_1, pdu->used_size);
  coap_delete_pdu(pdu);
}

CU_pSuite
t_init_uri_tests(void) {
  CU_pSuite suite;

  suite = CU_add_suite("uri parser", NULL, NULL);
  if (!suite) {                        /* signal error */
    fprintf(stderr, "W: cannot add uri parser test suite (%s)\n",
            CU_get_error_msg());

    return NULL;
  }

#define URI_TEST(s,t)                                                      \
  if (!CU_ADD_TEST(s,t)) {                                              \
    fprintf(stderr, "W: cannot add uri parser test (%s)\n",              \
            CU_get_error_msg());                                      \
  }

  URI_TEST(suite, t_parse_uri1);
  URI_TEST(suite, t_parse_uri2);
  URI_TEST(suite, t_parse_uri3);
  URI_TEST(suite, t_parse_uri4);
  URI_TEST(suite, t_parse_uri5);
  URI_TEST(suite, t_parse_uri6);
  URI_TEST(suite, t_parse_uri7);
  URI_TEST(suite, t_parse_uri8);
  URI_TEST(suite, t_parse_uri9);
  URI_TEST(suite, t_parse_uri10);
  URI_TEST(suite, t_parse_uri11);
  URI_TEST(suite, t_parse_uri12);
  URI_TEST(suite, t_parse_uri13);
  URI_TEST(suite, t_parse_uri14);
  URI_TEST(suite, t_parse_uri15);
  URI_TEST(suite, t_parse_uri16);
  URI_TEST(suite, t_parse_uri17);
  URI_TEST(suite, t_parse_uri18);
  URI_TEST(suite, t_parse_uri19);
  URI_TEST(suite, t_parse_uri20);
  URI_TEST(suite, t_parse_uri21);
  URI_TEST(suite, t_parse_uri22);
  URI_TEST(suite, t_parse_uri23);
  URI_TEST(suite, t_parse_uri24);
  URI_TEST(suite, t_parse_uri25);
  URI_TEST(suite, t_parse_uri26);
  URI_TEST(suite, t_parse_uri27);
  URI_TEST(suite, t_parse_uri28);
  URI_TEST(suite, t_parse_uri29);
  URI_TEST(suite, t_parse_uri30);
  URI_TEST(suite, t_parse_uri31);
  URI_TEST(suite, t_parse_uri32);
  URI_TEST(suite, t_parse_uri33);

  return suite;
}
