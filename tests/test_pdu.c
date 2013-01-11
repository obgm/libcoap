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

coap_pdu_t *pdu;	      /* Holds the parsed PDU for most tests */

/************************************************************************
 ** PDU decoder
 ************************************************************************/

void
t_parse_pdu1(void) {
  char teststr[] = {  0x40, 0x01, 0x93, 0x34 };
  int result;

  result = coap_pdu_parse((unsigned char *)teststr, sizeof(teststr), pdu);
  CU_ASSERT(result > 0);
  
  CU_ASSERT(pdu->length == sizeof(teststr));
  CU_ASSERT(pdu->hdr->version == 1);
  CU_ASSERT(pdu->hdr->type == COAP_MESSAGE_CON);
  CU_ASSERT(pdu->hdr->token_length == 0);
  CU_ASSERT(pdu->hdr->code == COAP_REQUEST_GET);
  CU_ASSERT(memcmp(&pdu->hdr->id, teststr + 2, 2) == 0);
  CU_ASSERT_PTR_NULL(pdu->data);
}

void
t_parse_pdu2(void) {
  char teststr[] = {  0x55, 0x69, 0x12, 0x34, 't', 'o', 'k', 'e', 'n' };
  int result;

  result = coap_pdu_parse((unsigned char *)teststr, sizeof(teststr), pdu);
  CU_ASSERT(result > 0);
  
  CU_ASSERT(pdu->length == sizeof(teststr));
  CU_ASSERT(pdu->hdr->version == 1);
  CU_ASSERT(pdu->hdr->type == COAP_MESSAGE_NON);
  CU_ASSERT(pdu->hdr->token_length == 5);
  CU_ASSERT(pdu->hdr->code == 0x69);
  CU_ASSERT(memcmp(&pdu->hdr->id, teststr + 2, 2) == 0);
  CU_ASSERT(memcmp(pdu->hdr->token, teststr + 4, 5) == 0);
  CU_ASSERT_PTR_NULL(pdu->data);
}

void
t_parse_pdu3(void) {
  char teststr[] = {  0x53, 0x69, 0x12, 0x34, 't', 'o', 'k', 'e', 'n' };
  int result;

  result = coap_pdu_parse((unsigned char *)teststr, sizeof(teststr), pdu);
  CU_ASSERT(result == 0);
}

void
t_parse_pdu4(void) {
  /* illegal token length */
  char teststr[] = {  0x59, 0x69, 0x12, 0x34, 
		      't', 'o', 'k', 'e', 'n', '1', '2', '3', '4' };
  int result;

  result = coap_pdu_parse((unsigned char *)teststr, sizeof(teststr), pdu);
  CU_ASSERT(result == 0);

  teststr[0] = 0x5f;

  result = coap_pdu_parse((unsigned char *)teststr, sizeof(teststr), pdu);
  CU_ASSERT(result == 0);
}

void
t_parse_pdu5(void) {
  /* PDU with options */
  char teststr[] = {  0x55, 0x73, 0x12, 0x34, 't', 'o', 'k', 'e', 
		      'n',  0x00, 0xc1, 0x00
  };
  int result;

  result = coap_pdu_parse((unsigned char *)teststr, sizeof(teststr), pdu);
  CU_ASSERT(result > 0);
  
  CU_ASSERT(pdu->length == sizeof(teststr));
  CU_ASSERT(pdu->hdr->version == 1);
  CU_ASSERT(pdu->hdr->type == COAP_MESSAGE_NON);
  CU_ASSERT(pdu->hdr->token_length == 5);
  CU_ASSERT(pdu->hdr->code == 0x73);
  CU_ASSERT(memcmp(&pdu->hdr->id, teststr + 2, 2) == 0);
  CU_ASSERT(memcmp(pdu->hdr->token, teststr + 4, 5) == 0);
  CU_ASSERT_PTR_NULL(pdu->data);

  /* FIXME: check options */
}

void
t_parse_pdu6(void) {
  /* PDU with options that exceed the PDU */
  char teststr[] = {  0x55, 0x73, 0x12, 0x34, 't', 'o', 'k', 'e', 
		      'n',  0x00, 0xc1, 0x00, 0xae, 0xf0, 0x03 
  };
  int result;

  result = coap_pdu_parse((unsigned char *)teststr, sizeof(teststr), pdu);
  CU_ASSERT(result == 0);
}

void
t_parse_pdu7(void) {
  /* PDU with options and payload */
  char teststr[] = {  0x55, 0x73, 0x12, 0x34, 't', 'o', 'k', 'e', 
		      'n',  0x00, 0xc1, 0x00, 0xff, 'p', 'a', 'y',
		      'l', 'o', 'a', 'd'
  };
  int result;

  result = coap_pdu_parse((unsigned char *)teststr, sizeof(teststr), pdu);
  CU_ASSERT(result > 0);
  
  CU_ASSERT(pdu->length == sizeof(teststr));
  CU_ASSERT(pdu->hdr->version == 1);
  CU_ASSERT(pdu->hdr->type == COAP_MESSAGE_NON);
  CU_ASSERT(pdu->hdr->token_length == 5);
  CU_ASSERT(pdu->hdr->code == 0x73);
  CU_ASSERT(memcmp(&pdu->hdr->id, teststr + 2, 2) == 0);
  CU_ASSERT(memcmp(pdu->hdr->token, teststr + 4, 5) == 0);

  /* FIXME: check options */

  CU_ASSERT(pdu->data == (unsigned char *)pdu->hdr + 13);
  CU_ASSERT(memcmp(pdu->data, teststr + 13, 7) == 0);
}

void
t_parse_pdu8(void) {
  /* PDU without options but with payload */
  char teststr[] = {  0x50, 0x73, 0x12, 0x34, 
		      0xff, 'p', 'a', 'y', 'l', 'o', 'a', 
		      'd'
  };
  int result;

  result = coap_pdu_parse((unsigned char *)teststr, sizeof(teststr), pdu);
  CU_ASSERT(result > 0);
  
  CU_ASSERT(pdu->length == sizeof(teststr));
  CU_ASSERT(pdu->hdr->version == 1);
  CU_ASSERT(pdu->hdr->type == COAP_MESSAGE_NON);
  CU_ASSERT(pdu->hdr->token_length == 0);
  CU_ASSERT(pdu->hdr->code == 0x73);
  CU_ASSERT(memcmp(&pdu->hdr->id, teststr + 2, 2) == 0);

  /* FIXME: check options */

  CU_ASSERT(pdu->data == (unsigned char *)pdu->hdr + 5);
  CU_ASSERT(memcmp(pdu->data, teststr + 5, 7) == 0);
}

void
t_parse_pdu9(void) {
  /* PDU without options and payload but with payload start marker */
  char teststr[] = {  0x70, 0x00, 0x12, 0x34, 0xff };
  int result;

  result = coap_pdu_parse((unsigned char *)teststr, sizeof(teststr), pdu);
  CU_ASSERT(result == 0);
}

void
t_parse_pdu10(void) {
  /* PDU without payload but with options and payload start marker */
  char teststr[] = {  0x53, 0x73, 0x12, 0x34, 't', 'o', 'k', 
		      0x30, 0xc1, 0x00, 0xff 
  };
  int result;

  result = coap_pdu_parse((unsigned char *)teststr, sizeof(teststr), pdu);
  CU_ASSERT(result == 0);
}

void
t_parse_pdu11(void) {
  char teststr[] = {  0x60, 0x00, 0x12, 0x34 };
  int result;

  result = coap_pdu_parse((unsigned char *)teststr, sizeof(teststr), pdu);
  CU_ASSERT(result > 0);
  
  CU_ASSERT(pdu->length == sizeof(teststr));
  CU_ASSERT(pdu->hdr->version == 1);
  CU_ASSERT(pdu->hdr->type == COAP_MESSAGE_ACK);
  CU_ASSERT(pdu->hdr->token_length == 0);
  CU_ASSERT(pdu->hdr->code == 0);
  CU_ASSERT(memcmp(&pdu->hdr->id, teststr + 2, 2) == 0);
}

void
t_parse_pdu12(void) {
  /* RST */
  char teststr[] = {  0x70, 0x00, 0x12, 0x34 };
  int result;

  result = coap_pdu_parse((unsigned char *)teststr, sizeof(teststr), pdu);
  CU_ASSERT(result > 0);
  
  CU_ASSERT(pdu->length == sizeof(teststr));
  CU_ASSERT(pdu->hdr->version == 1);
  CU_ASSERT(pdu->hdr->type == COAP_MESSAGE_RST);
  CU_ASSERT(pdu->hdr->token_length == 0);
  CU_ASSERT(pdu->hdr->code == 0);
  CU_ASSERT(memcmp(&pdu->hdr->id, teststr + 2, 2) == 0);
}

void
t_parse_pdu13(void) {
  /* RST with content */
  char teststr[] = {  0x70, 0x00, 0x12, 0x34, 
		      0xff, 'c', 'o', 'n', 't', 'e', 'n', 't' 
  };
  int result;

  result = coap_pdu_parse((unsigned char *)teststr, sizeof(teststr), pdu);
  CU_ASSERT(result == 0);
}

void
t_parse_pdu14(void) {
  /* ACK with content */
  char teststr[] = {  0x60, 0x00, 0x12, 0x34, 
		      0xff, 'c', 'o', 'n', 't', 'e', 'n', 't' 
  };
  int result;

  result = coap_pdu_parse((unsigned char *)teststr, sizeof(teststr), pdu);
  CU_ASSERT(result == 0);
}

/************************************************************************
 ** PDU encoder
 ************************************************************************/

void
t_encode_pdu1(void) {
  char teststr[] = { 0x45, 0x01, 0x12, 0x34, 't', 'o', 'k',
                     'e', 'n' 
  };
  int result;

  coap_pdu_clear(pdu, pdu->max_size);
  pdu->hdr->type = COAP_MESSAGE_CON;
  pdu->hdr->code = COAP_REQUEST_GET;
  pdu->hdr->id = htons(0x1234);

  result = coap_add_token(pdu, 5, (unsigned char *)"token");

  CU_ASSERT(result == 1);
  CU_ASSERT(pdu->length = sizeof(teststr));
  CU_ASSERT_PTR_NULL(pdu->data);
  CU_ASSERT(memcmp(pdu->hdr, teststr, sizeof(teststr)) == 0);
}

void
t_encode_pdu2(void) {
  size_t old_max = pdu->max_size;
  int result;

  coap_pdu_clear(pdu, 7);	/* set very small PDU size */

  pdu->hdr->type = COAP_MESSAGE_CON;
  pdu->hdr->code = COAP_REQUEST_GET;
  pdu->hdr->id = htons(0x1234);

  result = coap_add_token(pdu, 5, (unsigned char *)"token");

  CU_ASSERT(result == 0);

  coap_pdu_clear(pdu, old_max);	/* restore PDU size */
}

void
t_encode_pdu3(void) {
  int result;

  result = coap_add_token(pdu, 9, (unsigned char *)"123456789");

  CU_ASSERT(result == 0);
}

void
t_encode_pdu4(void) {
  /* PDU with options */
  char teststr[] = { 0x60, 0x99, 0x12, 0x34, 0x3d, 0x05, 0x66, 0x61,
		     0x6e, 0x63, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79,
		     0x2e, 0x63, 0x6f, 0x61, 0x70, 0x2e, 0x6d, 0x65,
		     0x84, 0x70, 0x61, 0x74, 0x68, 0x00, 0xe8, 0x1e,
		     0x28, 0x66, 0x61, 0x6e, 0x63, 0x79, 0x6f, 0x70,
		     0x74
  };
  int result;

  coap_pdu_clear(pdu, pdu->max_size);	/* clear PDU */

  pdu->hdr->type = COAP_MESSAGE_ACK;
  pdu->hdr->code = 0x99;
  pdu->hdr->id = htons(0x1234);

  CU_ASSERT(pdu->length == 4);

  result = coap_add_option(pdu, COAP_OPTION_URI_HOST, 
       18, (unsigned char *)"fancyproxy.coap.me");

  CU_ASSERT(result == 20);
  CU_ASSERT(pdu->max_delta == 3);
  CU_ASSERT(pdu->length == 24);
  CU_ASSERT_PTR_NULL(pdu->data);

  result = coap_add_option(pdu, COAP_OPTION_URI_PATH, 
			   4, (unsigned char *)"path");

  CU_ASSERT(result == 5);
  CU_ASSERT(pdu->max_delta == 11);
  CU_ASSERT(pdu->length == 29);
  CU_ASSERT_PTR_NULL(pdu->data);

  result = coap_add_option(pdu, COAP_OPTION_URI_PATH, 0, NULL);

  CU_ASSERT(result == 1);
  CU_ASSERT(pdu->max_delta == 11);
  CU_ASSERT(pdu->length == 30);
  CU_ASSERT_PTR_NULL(pdu->data);

  result = coap_add_option(pdu, 8000, 8, (unsigned char *)"fancyopt");

  CU_ASSERT(result == 11);
  CU_ASSERT(pdu->max_delta == 8000);
  CU_ASSERT(pdu->length == 41);
  CU_ASSERT_PTR_NULL(pdu->data);

  CU_ASSERT(pdu->length == sizeof(teststr));
  CU_ASSERT(memcmp(pdu->hdr, teststr, sizeof(teststr)) == 0);
}

void
t_encode_pdu5(void) {
  /* PDU with token and options */
  coap_pdu_clear(pdu, pdu->max_size);
}

int 
t_pdu_tests_create(void) {
  pdu = coap_pdu_init(0, 0, 0, COAP_MAX_PDU_SIZE);

  return pdu == NULL;
}

int 
t_pdu_tests_remove(void) {
  coap_delete_pdu(pdu);
  return 0;
}

CU_pSuite
t_init_pdu_tests(void) {
  CU_pSuite suite[2];

  suite[0] = CU_add_suite("pdu parser", t_pdu_tests_create, t_pdu_tests_remove);
  if (!suite[0]) {			/* signal error */
    fprintf(stderr, "W: cannot add pdu parser test suite (%s)\n", 
	    CU_get_error_msg());

    return NULL;
  }

#define PDU_TEST(s,t)						      \
  if (!CU_ADD_TEST(s,t)) {					      \
    fprintf(stderr, "W: cannot add pdu parser test (%s)\n",	      \
	    CU_get_error_msg());				      \
  }

  PDU_TEST(suite[0], t_parse_pdu1);
  PDU_TEST(suite[0], t_parse_pdu2);
  PDU_TEST(suite[0], t_parse_pdu3);
  PDU_TEST(suite[0], t_parse_pdu4);
  PDU_TEST(suite[0], t_parse_pdu5);
  PDU_TEST(suite[0], t_parse_pdu6);
  PDU_TEST(suite[0], t_parse_pdu7);
  PDU_TEST(suite[0], t_parse_pdu8);
  PDU_TEST(suite[0], t_parse_pdu9);
  PDU_TEST(suite[0], t_parse_pdu10);
  PDU_TEST(suite[0], t_parse_pdu11);
  PDU_TEST(suite[0], t_parse_pdu12);
  PDU_TEST(suite[0], t_parse_pdu13);
  PDU_TEST(suite[0], t_parse_pdu14);

  suite[1] = CU_add_suite("pdu encoder", NULL, NULL);
  if (suite[1]) {
#define PDU_ENCODER_TEST(s,t)						      \
  if (!CU_ADD_TEST(s,t)) {					      \
    fprintf(stderr, "W: cannot add pdu encoder test (%s)\n",	      \
	    CU_get_error_msg());				      \
  }
    PDU_ENCODER_TEST(suite[1], t_encode_pdu1);
    PDU_ENCODER_TEST(suite[1], t_encode_pdu2);
    PDU_ENCODER_TEST(suite[1], t_encode_pdu3);
    PDU_ENCODER_TEST(suite[1], t_encode_pdu4);
    PDU_ENCODER_TEST(suite[1], t_encode_pdu5);

  } else 			/* signal error */
    fprintf(stderr, "W: cannot add pdu parser test suite (%s)\n", 
	    CU_get_error_msg());


  return suite[0];
}

