/* libcoap unit tests
 *
 * Copyright (C) 2012 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <coap.h>
#include "test_options.h"

void
t_parse_option1(void) {
  /* delta == 0, length == 0, value == 0 */
  str teststr = {  1, (unsigned char *)"" };

  size_t result;
  coap_option_t option;

  /* result = coap_opt_parse(teststr.s, teststr.s + teststr.length, &option); */
  result = coap_opt_parse(teststr.s, teststr.length, &option);
  CU_ASSERT(result == 1);
  CU_ASSERT(option.delta == 0);
  CU_ASSERT(option.length == 0);
  /* FIXME: value? */
}

void
t_parse_option2(void) {
  /* delta == 12, length == 1, value == 0 */
  str teststr = {  2, (unsigned char *)"\xc1" };

  size_t result;
  coap_option_t option;

  result = coap_opt_parse(teststr.s, teststr.length, &option);
  CU_ASSERT(result == 2);
  CU_ASSERT(option.delta == 12);
  CU_ASSERT(option.length == 1);
  CU_ASSERT(option.value == teststr.s + 1);
}

void
t_parse_option3(void) {
  /* delta == 3, length == 12, value == 0 */
  str teststr = { 13, (unsigned char *)"\x3c\x00\x01\x02\x03\x04"
		                       "\x05\x06\x07\x08\x09\x0a\x0b" };

  size_t result;
  coap_option_t option;

  result = coap_opt_parse(teststr.s, teststr.length, &option);
  CU_ASSERT(result == 13);
  CU_ASSERT(option.delta == 3);
  CU_ASSERT(option.length == 12);
  CU_ASSERT(option.value == teststr.s + 1);
  /* CU_ASSERT(memcmp(option.value, teststr.s + 1, 12) == 0); */
}

void
t_parse_option4(void) {
  /* delta == 15, length == 3, value == 0 */
  str teststr = {  2, (unsigned char *)"\xf3" };

  size_t result;
  coap_option_t option;

  result = coap_opt_parse(teststr.s, teststr.length, &option);
  CU_ASSERT(result == 0);
}

void
t_parse_option5(void) {
  /* delta == 3, length == 15, value == 0 */
  str teststr = {  2, (unsigned char *)"\x3f" };

  size_t result;
  coap_option_t option;

  result = coap_opt_parse(teststr.s, teststr.length, &option);
  CU_ASSERT(result == 0);
}

void
t_parse_option6(void) {
  /* delta == 15, length == 15 */
  str teststr = {  1, (unsigned char *)"\xff" };

  size_t result;
  coap_option_t option;

  result = coap_opt_parse(teststr.s, teststr.length, &option);
  CU_ASSERT(result == 0);
}

void
t_parse_option7(void) {
  /* delta == 20, length == 0 */
  str teststr = {  2, (unsigned char *)"\xd0\x07" };

  size_t result;
  coap_option_t option;

  result = coap_opt_parse(teststr.s, teststr.length, &option);
  CU_ASSERT(result == 2);
  CU_ASSERT(option.delta == 20);
  CU_ASSERT(option.length == 0);
}

void
t_parse_option8(void) {
  /* delta == 780, length == 0 */
  str teststr = {  3, (unsigned char *)"\xe0\x01\xff" };

  size_t result;
  coap_option_t option;

  result = coap_opt_parse(teststr.s, teststr.length, &option);
  CU_ASSERT(result == 3);
  CU_ASSERT(option.delta == 780);
  CU_ASSERT(option.length == 0);
}

void
t_parse_option9(void) {
  /* delta == 65535, length == 0 */
  str teststr = {  3, (unsigned char *)"\xe0\xfe\xf2" };

  size_t result;
  coap_option_t option;

  result = coap_opt_parse(teststr.s, teststr.length, &option);
  CU_ASSERT(result == 3);
  CU_ASSERT(option.delta == 65535);
}

void
t_parse_option10(void) {
  /* delta > 65535 (illegal), length == 0 */
  str teststr = {  3, (unsigned char *)"\xe0\xff\xff" };

  size_t result;
  coap_option_t option;

  result = coap_opt_parse(teststr.s, teststr.length, &option);
  CU_ASSERT(result == 0);
}

void
t_parse_option11(void) {
  /* illegal delta value (option too short) */
  str teststr = {  1, (unsigned char *)"\xd0" };

  size_t result;
  coap_option_t option;

  result = coap_opt_parse(teststr.s, teststr.length, &option);
  CU_ASSERT(result == 0);
}

void
t_parse_option12(void) {
  /* delta == 280, length == 500 */
  str teststr = {  3, (unsigned char *)"\xee\xff\x0b" };

  size_t result;
  coap_option_t option;

  result = coap_opt_parse(teststr.s, teststr.length, &option);
  CU_ASSERT(result == 0);
}

void
t_parse_option13(void) {
  /* delta == 280, length == 500 */
  unsigned char _data[505];
  str teststr = {  sizeof(_data), _data };
  teststr.s[0] = 0xee;
  teststr.s[1] = 0x00;
  teststr.s[2] = 0x0b;
  teststr.s[3] = 0x00;
  teststr.s[4] = 0xe7;
  
  size_t result;
  coap_option_t option;

  result = coap_opt_parse(teststr.s, teststr.length, &option);
  CU_ASSERT(result == sizeof(_data));
  CU_ASSERT(option.delta == 280);
  CU_ASSERT(option.length == 500);
  CU_ASSERT(option.value == &_data[5]);
}

void
t_parse_option14(void) {
  /* delta == 268, length == 65535 */
  unsigned char *data;
  unsigned int length = 4 + 65535;

  data = (unsigned char *)malloc(length);
  if (!data) {
    CU_FAIL("internal error in test framework -- insufficient memory\n");
    return;
  }

  data[0] = 0xde;
  data[1] = 0xff;
  data[2] = 0xfe;
  data[3] = 0xf2;
  
  size_t result;
  coap_option_t option;

  result = coap_opt_parse(data, length, &option);
  CU_ASSERT(result == length);
  CU_ASSERT(option.delta == 268);
  CU_ASSERT(option.length == 65535);
  CU_ASSERT(option.value == &data[4]);
}

CU_pSuite
t_init_option_tests(void) {
  CU_pSuite suite;

  suite = CU_add_suite("option parser", NULL, NULL);
  if (!suite) {			/* signal error */
    fprintf(stderr, "W: cannot add option parser test suite (%s)\n", 
	    CU_get_error_msg());

    return NULL;
  }

#define OPTION_TEST(n,s)						      \
  if (!CU_add_test(suite, s, t_parse_option##n)) {	      \
    fprintf(stderr, "W: cannot add option parser test (%s)\n",	      \
	    CU_get_error_msg());				      \
  }

  OPTION_TEST(1, "parse option #1");
  OPTION_TEST(2, "parse option #2");
  OPTION_TEST(3, "parse option #3");
  OPTION_TEST(4, "parse option #4");
  OPTION_TEST(5, "parse option #5");
  OPTION_TEST(6, "parse option #6");
  OPTION_TEST(7, "parse option #7");
  OPTION_TEST(8, "parse option #8");
  OPTION_TEST(9, "parse option #9");
  OPTION_TEST(10, "parse option #10");
  OPTION_TEST(11, "parse option #11");
  OPTION_TEST(12, "parse option #12");
  OPTION_TEST(13, "parse option #13");
  OPTION_TEST(14, "parse option #14");

#if 0
  if (!CU_add_test(suite, "parse delta", t_parse_delta)) {
    fprintf(stderr, "W: cannot add option delta test (%s)\n",
	    CU_get_error_msg());
  }
  
  if (!CU_add_test(suite, "parse option length", t_parse_length)) {
    fprintf(stderr, "W: cannot add option length test (%s)\n",
	    CU_get_error_msg());
  }
#endif  
  return suite;
}

