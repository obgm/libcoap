# Findwolfssl
# -----------
#
# Find the wolfSSL library.
#
# Imported Targets
# ^^^^^^^^^^^^^^^^
#
# This module defines the following :prop_tgt:`IMPORTED` targets:
#
# ``wolfssl::wolfssl``
#   The wolfSSL library, if found.
#
# Result Variables
# ^^^^^^^^^^^^^^^^
#
# This module will set the following variables in your project:
#
# ``wolfssl_FOUND``
#   System has the wolfSSL library.
# ``wolfssl_VERSION``
#   The version of wolfSSL found.
# ``WOLFSSL_INCLUDE_DIR``
#   The wolfSSL include directory.
# ``WOLFSSL_LIBRARIES``
#   All wolfSSL libraries.
#
# Hints
# ^^^^^
#
# Set ``WOLFSSL_ROOT_DIR`` to the root directory of a wolfSSL installation.

if(WOLFSSL_INCLUDE_DIR AND WOLFSSL_LIBRARIES)
  # in cache already
  set(wolfssl_FIND_QUIETLY TRUE)
endif()

if(WOLFSSL_ROOT_DIR)
  set(_WOLFSSL_EXTRA_FIND_ARGS "NO_CMAKE_FIND_ROOT_PATH")
endif()

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
  pkg_check_modules(PC_WOLFSSL QUIET wolfssl)
endif()

find_path(
  WOLFSSL_INCLUDE_DIR
  NAMES wolfssl/ssl.h
  PATH_SUFFIXES include
  HINTS ${PROJECT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
        ${WOLFSSL_ROOT_DIR}
		${PC_WOLFSSL_INCLUDE_DIRS}
        ${_WOLFSSL_EXTRA_FIND_ARGS})

find_library(
  WOLFSSL_LIBRARIES
  NAMES wolfssl
  PATH_SUFFIXES lib
  HINTS ${PROJECT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
        ${WOLFSSL_ROOT_DIR}
		${PC_WOLFSSL_LIBRARY_DIRS}
        ${_WOLFSSL_EXTRA_FIND_ARGS})

if(WOLFSSL_INCLUDE_DIR AND EXISTS "${WOLFSSL_INCLUDE_DIR}/wolfssl/version.h")
  file(STRINGS "${WOLFSSL_INCLUDE_DIR}/wolfssl/version.h" WOLFSSL_VERSION_STR
    REGEX "#[\t ]*define[\t ]+LIBWOLFSSL_VERSION_STRING[\t ]+\"[^\"]+\"")
  string(REGEX REPLACE "^.*LIBWOLFSSL_VERSION_STRING[\t ]+\"([^\"]+)\""
    "\\1" WOLFSSL_VERSION_STR "${WOLFSSL_VERSION_STR}")
  set(wolfssl_VERSION "${WOLFSSL_VERSION_STR}")
  unset(WOLFSSL_VERSION_STR)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
  wolfssl
  FAIL_MESSAGE "Could NOT find WolfSSL, try to set the path to WolfSSL root folder in the system variable WOLFSSL_ROOT_DIR"
  REQUIRED_VARS WOLFSSL_INCLUDE_DIR
                WOLFSSL_LIBRARIES
  VERSION_VAR wolfssl_VERSION)

if(NOT
   TARGET
   wolfssl::wolfssl)
  add_library(
    wolfssl::wolfssl
    UNKNOWN
    IMPORTED)
  set_target_properties(
    wolfssl::wolfssl
    PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${WOLFSSL_INCLUDE_DIR}"
               VERSION "${wolfssl_VERSION}"
               IMPORTED_LINK_INTERFACE_LANGUAGES "C"
               IMPORTED_LOCATION "${WOLFSSL_LIBRARIES}")
endif()

mark_as_advanced(
  WOLFSSL_INCLUDE_DIR
  WOLFSSL_LIBRARIES)
