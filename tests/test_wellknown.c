/* libcoap unit tests
 *
 * Copyright (C) 2013--2014 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <coap.h>
#include <netinet/in.h>
#include "test_wellknown.h"

#define TEST_PDU_SIZE 120
#define TEST_URI_LEN    4

coap_context_t *ctx;	   /* Holds the coap context for most tests */
coap_pdu_t *pdu;	   /* Holds the parsed PDU for most tests */

extern coap_pdu_t *wellknown_response(coap_context_t *, coap_pdu_t *);
extern int print_wellknown(coap_context_t *context, unsigned char *buf, 
			   size_t *buflen, size_t offset, 
			   coap_opt_t *query_filter);

void
t_wellknown1(void) {
  int result;
  coap_resource_t *r;
  unsigned char buf[40];
  size_t buflen, offset, ofs;

  char teststr[] = {  /* </>;title="some attribute";ct=0 (31 chars) */
    '<', '/', '>', ';', 't', 'i', 't', 'l',
    'e', '=', '"', 's', 'o', 'm', 'e', ' ',
    'a', 't', 't', 'r', 'i', 'b', 'u', 't',
    'e', '"', ';', 'c', 't', '=', '0'
  };

  r = coap_resource_init(NULL, 0, 0);

  coap_add_attr(r, (unsigned char *)"ct", 2, (unsigned char *)"0", 1, 0);
  coap_add_attr(r, (unsigned char *)"title", 5, (unsigned char *)"\"some attribute\"", 16, 0);

  coap_add_resource(ctx, r);

  for (offset = 0; offset < sizeof(teststr); offset++) {
    ofs = offset;
    buflen = sizeof(buf);

    result = coap_print_link(r, buf, &buflen, &ofs);
  
    CU_ASSERT(result == 0);
    CU_ASSERT(buflen == sizeof(teststr) - offset);
    CU_ASSERT(memcmp(buf, teststr + offset, sizeof(teststr) - offset) == 0);
  }
  
  /* offset points behind teststr */
  ofs = offset;
  buflen = sizeof(buf);
  result = coap_print_link(r, buf, &buflen, &ofs);
  
  CU_ASSERT(result == 0);

  /* offset exceeds buffer */
  buflen = sizeof(buf);
  ofs = buflen;
  result = coap_print_link(r, buf, &buflen, &ofs);

  CU_ASSERT(result == 0);
}

void
t_wellknown2(void) {
  int result;
  coap_resource_t *r;
  unsigned char buf[10];	/* smaller than teststr */
  size_t buflen, offset, ofs;

  char teststr[] = {  /* ,</abcd>;if="one";obs (21 chars) */
    '<', '/', 'a', 'b', 'c', 'd', '>', ';',
    'i', 'f', '=', '"', 'o', 'n', 'e', '"',
    ';', 'o', 'b', 's'
  };
  
  r = coap_resource_init((unsigned char *)"abcd", 4, 0);
  r->observable = 1;
  coap_add_attr(r, (unsigned char *)"if", 2, (unsigned char *)"\"one\"", 5, 0);

  coap_add_resource(ctx, r);

  for (offset = 0; offset < sizeof(teststr) - sizeof(buf); offset++) {
    ofs = offset;
    buflen = sizeof(buf);

    result = coap_print_link(r, buf, &buflen, &ofs);
  
    CU_ASSERT(result == 1);
    CU_ASSERT(buflen == sizeof(buf));
    CU_ASSERT(memcmp(buf, teststr + offset, sizeof(buf)) == 0);
  }

  /* from here on, the resource description fits into buf */
  for (; offset < sizeof(teststr); offset++) {
    ofs = offset;
    buflen = sizeof(buf);
    result = coap_print_link(r, buf, &buflen, &ofs);
  
    CU_ASSERT(result == 0);
    CU_ASSERT(buflen == sizeof(teststr) - offset);
    CU_ASSERT(memcmp(buf, teststr + offset, buflen) == 0);
  }

  /* offset exceeds buffer */
  buflen = sizeof(buf);
  ofs = offset;
  result = coap_print_link(r, buf, &buflen, &ofs);
  CU_ASSERT(result == 0);
}

void
t_wellknown3(void) {
  int result, j;
  coap_resource_t *r;
  static char uris[2 * COAP_MAX_PDU_SIZE];
  unsigned char *uribuf = (unsigned char *)uris;
  unsigned char buf[40];
  size_t buflen = sizeof(buf);
  size_t offset;
  const unsigned short num_resources = (sizeof(uris) / TEST_URI_LEN) - 1;

  /* ,</0000> (TEST_URI_LEN + 4 chars) */
  for (j = 0; j < num_resources; j++) {
    int len = snprintf((char *)uribuf, TEST_URI_LEN + 1,
		       "%0*d", TEST_URI_LEN, j);
    r = coap_resource_init(uribuf, len, 0);
    coap_add_resource(ctx, r);
    uribuf += TEST_URI_LEN;
  }

  /* the following test assumes that the first two resources from
   * t_wellknown1() and t_wellknown2() need more than buflen
   * characters. Otherwise, CU_ASSERT(result > 0) will fail.
   */
  offset = num_resources * (TEST_URI_LEN + 4);
  result = print_wellknown(ctx, buf, &buflen, offset, NULL);
  CU_ASSERT(result > 0);
}

void
t_wellknown4(void) {
  coap_pdu_t *response;

  response = wellknown_response(ctx, pdu);

  CU_ASSERT_PTR_NOT_NULL(response);

  /* printf("%.*s", (int)(((unsigned char *)response->hdr + response->length) - response->data), response->data); */

  coap_delete_pdu(response);
}

int 
t_wkc_tests_create(void) {
  coap_address_t addr;

  coap_address_init(&addr);

  addr.size = sizeof(struct sockaddr_in6);
  addr.addr.sin6.sin6_family = AF_INET6;
  addr.addr.sin6.sin6_addr = in6addr_any;
  addr.addr.sin6.sin6_port = htons(COAP_DEFAULT_PORT);

  ctx = coap_new_context(&addr);

  pdu = coap_pdu_init(0, 0, 0, TEST_PDU_SIZE);
#if 0
  /* add resources to coap context */
  if (ctx && pdu) {
    coap_resource_t *r;
    static char _buf[2 * COAP_MAX_PDU_SIZE];
    unsigned char *buf = (unsigned char *)_buf;
    int i;

    /* </>;title="some attribute";ct=0 (31 chars) */
    r = coap_resource_init(NULL, 0, 0);

    coap_add_attr(r, (unsigned char *)"ct", 2, (unsigned char *)"0", 1, 0);
    coap_add_attr(r, (unsigned char *)"title", 5, (unsigned char *)"\"some attribute\"", 16, 0);
    coap_add_resource(ctx, r);

    /* ,</abcd>;if="one";obs (21 chars) */
    r = coap_resource_init((unsigned char *)"abcd", 4, 0);
    r->observable = 1;
    coap_add_attr(r, (unsigned char *)"if", 2, (unsigned char *)"\"one\"", 5, 0);

    coap_add_resource(ctx, r);

    /* ,</0000> (TEST_URI_LEN + 4 chars) */
    for (i = 0; i < sizeof(_buf) / (TEST_URI_LEN + 4); i++) {
      int len = snprintf((char *)buf, TEST_URI_LEN + 1,
			 "%0*d", TEST_URI_LEN, i);
      r = coap_resource_init(buf, len, 0);
      coap_add_resource(ctx, r);
      buf += TEST_URI_LEN + 1;
    }

  }
#endif  
  return ctx == NULL || pdu == NULL;
}

int 
t_wkc_tests_remove(void) {
  coap_delete_pdu(pdu);
  coap_free_context(ctx);
  return 0;
}

CU_pSuite
t_init_wellknown_tests(void) {
  CU_pSuite suite;

  suite = CU_add_suite(".well-known/core", t_wkc_tests_create, t_wkc_tests_remove);
  if (!suite) {			/* signal error */
    fprintf(stderr, "W: cannot add .well-known/core test suite (%s)\n", 
	    CU_get_error_msg());

    return NULL;
  }

#define WKC_TEST(s,t)						      \
  if (!CU_ADD_TEST(s,t)) {					      \
    fprintf(stderr, "W: cannot add .well-known/core test (%s)\n",	      \
	    CU_get_error_msg());				      \
  }

  WKC_TEST(suite, t_wellknown1);
  WKC_TEST(suite, t_wellknown2);
  WKC_TEST(suite, t_wellknown3);
  WKC_TEST(suite, t_wellknown4);

  return suite;
}

