#include <stdio.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

/* #include <coap.h> */

#include "test_uri.h"
#include "test_options.h"
#include "test_pdu.h"
#include "test_error_response.h"
#include "test_sendqueue.h"
#include "test_wellknown.h"

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__ ((unused))
#else /* not a GCC */
#define UNUSED_PARAM
#endif /* GCC */

int
main(int argc UNUSED_PARAM, char **argv UNUSED_PARAM) {
  CU_ErrorCode result;
  CU_BasicRunMode run_mode = CU_BRM_VERBOSE;

  if (CU_initialize_registry() != CUE_SUCCESS) {
    fprintf(stderr, "E: test framework initialization failed\n");
    return -2;
  }

  t_init_uri_tests();
  t_init_option_tests();
  t_init_pdu_tests();
  t_init_error_response_tests();
  t_init_sendqueue_tests();
  t_init_wellknown_tests();

  CU_basic_set_mode(run_mode);
  result = CU_basic_run_tests();

  CU_cleanup_registry();

  printf("\n\nknown bugs:\n");
  printf("\t- Test: t_error_response8 ... FAILED\n"
	 "\t    1. test_error_response.c:310  - response->length == sizeof(teststr)\n"
	 "\t    2. test_error_response.c:316  - memcmp(response->hdr, teststr, sizeof(teststr)) == 0\n");

  return result;
}
