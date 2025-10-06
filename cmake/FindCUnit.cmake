# FindCUnit
# ---------
#
# Find the CUnit library.
#
# Imported Targets
# ^^^^^^^^^^^^^^^^
#
# This module defines the following :prop_tgt:`IMPORTED` targets:
#
# ``CUnit::cunit``
#   The CUnit library, if found.
#
# Result Variables
# ^^^^^^^^^^^^^^^^
#
# This module will set the following variables in your project:
#
# ``CUnit_FOUND``
#   System has the CUnit library.
# ``CUnit_VERSION``
#   The version of CUnit found.
# ``CUnit_INCLUDE_DIR``
#   The CUnit include directory.
# ``CUnit_LIBRARIES``
#   All CUnit libraries.
#
# Hints
# ^^^^^
#
# Set ``CUnit_ROOT_DIR`` to the root directory of a CUnit installation.

if(CUnit_INCLUDE_DIR AND CUnit_LIBRARIES)
  # in cache already
  set(CUnit_FIND_QUIETLY TRUE)
endif()

if(CUnit_ROOT_DIR)
  set(_CUnit_EXTRA_FIND_ARGS "NO_CMAKE_FIND_ROOT_PATH")
endif()

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
  pkg_check_modules(PC_CUNIT QUIET cunit)
endif()

find_path(
  CUnit_INCLUDE_DIR
  NAMES CUnit/CUnit.h
  PATH_SUFFIXES include
  HINTS ${PROJECT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
        ${CUnit_ROOT_DIR}
		${PC_CUNIT_INCLUDE_DIRS}
        ${_CUnit_EXTRA_FIND_ARGS})

find_library(
  CUnit_LIBRARIES
  NAMES cunit
  PATH_SUFFIXES lib
  HINTS ${PROJECT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
        ${CUnit_ROOT_DIR}
		${PC_CUNIT_LIBRARY_DIRS}
        ${_CUnit_EXTRA_FIND_ARGS})

if(CUnit_INCLUDE_DIR AND EXISTS "${CUnit_INCLUDE_DIR}/CUnit/CUnit.h")
  file(STRINGS "${CUnit_INCLUDE_DIR}/CUnit/CUnit.h" CUnit_VERSION_STR
    REGEX "#[\t ]*define[\t ]+CU_VERSION[\t ]+\"[^\"]+\"")
  string(REGEX REPLACE "^.*CU_VERSION[\t ]+\"([^\"]+)\""
    "\\1" CUnit_VERSION_STR "${CUnit_VERSION_STR}")
  set(CUnit_VERSION "${CUnit_VERSION_STR}")
  unset(CUnit_VERSION_STR)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
  CUnit
  FAIL_MESSAGE "Could NOT find CUnit, try to set the path to CUnit root folder in the system variable CUnit_ROOT_DIR"
  REQUIRED_VARS CUnit_INCLUDE_DIR
                CUnit_LIBRARIES
  VERSION_VAR CUnit_VERSION)

if(NOT
   TARGET
   CUnit::cunit)
  add_library(
    CUnit::cunit
    UNKNOWN
    IMPORTED)
  set_target_properties(
    CUnit::cunit
    PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${CUnit_INCLUDE_DIR}"
               VERSION "${CUnit_VERSION}"
               IMPORTED_LINK_INTERFACE_LANGUAGES "C"
               IMPORTED_LOCATION "${CUnit_LIBRARIES}")
endif()

mark_as_advanced(
  CUnit_INCLUDE_DIR
  CUnit_LIBRARIES)
