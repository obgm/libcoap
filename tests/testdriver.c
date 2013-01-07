#include <stdio.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

/* #include <coap.h> */

#include "test_uri.h"
#include "test_options.h"

int
main(int argc, char **argv) {
  CU_ErrorCode result;
  CU_BasicRunMode run_mode = CU_BRM_VERBOSE;

  if (CU_initialize_registry() != CUE_SUCCESS) {
    fprintf(stderr, "E: test framework initialization failed\n");
    return -2;
  }

  t_init_uri_tests();
  t_init_option_tests();

  CU_basic_set_mode(run_mode);
  result = CU_basic_run_tests();

  CU_cleanup_registry();
  return result;
}
