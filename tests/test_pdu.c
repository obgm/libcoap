/* libcoap unit tests
 *
 * Copyright (C) 2012 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <coap.h>
#include "test_pdu.h"

extern size_t
coap_pdu_parse(unsigned char *data, size_t length, coap_pdu_t *result);

void
t_parse_pdu1(void) {
}

void
t_parse_pdu2(void) {
}

CU_pSuite
t_init_pdu_tests(void) {
  CU_pSuite suite;

  suite = CU_add_suite("pdu parser", NULL, NULL);
  if (!suite) {			/* signal error */
    fprintf(stderr, "W: cannot add pdu parser test suite (%s)\n", 
	    CU_get_error_msg());

    return NULL;
  }

#define PDU_TEST(s,t)						      \
  if (!CU_ADD_TEST(s,t)) {					      \
    fprintf(stderr, "W: cannot add pdu parser test (%s)\n",	      \
	    CU_get_error_msg());				      \
  }

  PDU_TEST(suite, t_parse_pdu1);
  PDU_TEST(suite, t_parse_pdu2);

  return suite;
}

