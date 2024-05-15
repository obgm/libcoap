# FindWolfSSL.cmake
# -----------------
#
# Find the wolfSSL library.
#
# Imported Targets
# ^^^^^^^^^^^^^^^^
#
# This module defines the following :prop_tgt:`IMPORTED` targets:
#
# ``wolfssl``
#   The wolfSSL library, if found.
#
# Result Variables
# ^^^^^^^^^^^^^^^^
#
# This module will set the following variables in your project:
#
# ``wolfSSL_FOUND``
#   System has the wolfSSL library.
# ``WOLFSSL_INCLUDE_DIR``
#   The wolfSSL include directory.
# ``WOLFSSL_LIBRARIES``
#   All wolfSSL libraries.
#
# Hints
# ^^^^^
#
# Set ``WOLFSSL_ROOT_DIR`` to the root directory of a wolfSSL installation.

if(WOLFSSL_ROOT_DIR)
  set(_WOLFSSL_EXTRA_FIND_ARGS "NO_CMAKE_FIND_ROOT_PATH")
endif()

find_path(
  WOLFSSL_INCLUDE_DIR
  NAMES wolfssl/ssl.h
  PATH_SUFFIXES include
  HINTS ${PROJECT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
        ${WOLFSSL_ROOT_DIR}
        ${_WOLFSSL_EXTRA_FIND_ARGS})

find_library(
  WOLFSSL_LIBRARIES
  NAMES wolfssl
  PATH_SUFFIXES lib
  HINTS ${PROJECT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
        ${WOLFSSL_ROOT_DIR}
        ${_WOLFSSL_EXTRA_FIND_ARGS})

if(WOLFSSL_LIBRARIES)
  set(wolfSSL_FOUND TRUE)
else()
  set(wolfSSL_FOUND FALSE)
  if(wolfSSL_FIND_REQUIRED)
    message(FATAL_ERROR "wolfSSL could not be found")
  endif()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
  wolfSSL
  FOUND_VAR
  wolfSSL_FOUND
  REQUIRED_VARS
  WOLFSSL_INCLUDE_DIR
  WOLFSSL_LIBRARIES
  VERSION_VAR)

if(NOT TARGET wolfssl)
  add_library(
    wolfssl
    UNKNOWN
    IMPORTED)
  set_target_properties(
    wolfssl
    PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${WOLFSSL_INCLUDE_DIR}"
               IMPORTED_LINK_INTERFACE_LANGUAGES "C"
               IMPORTED_LOCATION "${WOLFSSL_LIBRARIES}")
endif()

message(STATUS "WOLFSSL_INCLUDE_DIR: ${WOLFSSL_INCLUDE_DIR}")
message(STATUS "WOLFSSL_LIBRARIES: ${WOLFSSL_LIBRARIES}")
message(STATUS "WOLFSSL_ROOT_DIR: ${WOLFSSL_ROOT_DIR}")
