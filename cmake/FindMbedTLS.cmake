# FindMbedTLS
# -----------
#
# Find the MbedTLS encryption library.
#
# Imported Targets
# ^^^^^^^^^^^^^^^^
#
# This module defines the following :prop_tgt:`IMPORTED` targets:
#
# ``MbedTLS::mbedtls``
#   The MbedTLS ``mbedtls`` library, if found.
# ``MbedTLS::mbedx509``
#   The MbedTLS ``mbedx509`` library, if found.
# ``MbedTLS::mbedcrypto``
#   The MbedTLS ``mbedcrypto`` library, if found.
#
# Result Variables
# ^^^^^^^^^^^^^^^^
#
# This module will set the following variables in your project:
#
# ``MbedTLS_FOUND``
#   System has the MbedTLS library.
# ``MbedTLS_VERSION``
#   The version of MbedTLS found.
# ``MBEDTLS_INCLUDE_DIRS``
#   The MbedTLS include directory.
# ``MBEDTLS_LIBRARIES``
#   All MbedTLS libraries.
#
# Hints
# ^^^^^
#
# Set ``MBEDTLS_ROOT_DIR`` to the root directory of an MbedTLS installation.

if(MBEDTLS_INCLUDE_DIRS AND MBEDTLS_LIBRARIES)
  # in cache already
  set(MbedTLS_FIND_QUIETLY TRUE)
endif()

if(MBEDTLS_ROOT_DIR)
  set(_MBEDTLS_EXTRA_FIND_ARGS "NO_CMAKE_FIND_ROOT_PATH")
endif()

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
  pkg_check_modules(PC_MBEDTLS QUIET tinydtls)
endif()

find_path(
  MBEDTLS_INCLUDE_DIRS
  NAMES mbedtls/ssl.h
  PATH_SUFFIXES include
  HINTS ${PROJECT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
        ${MBEDTLS_ROOT_DIR}
		${PC_MBEDTLS_INCLUDE_DIRS}
        ${_MBEDTLS_EXTRA_FIND_ARGS})

find_library(
  MBEDTLS_LIBRARY
  NAMES mbedtls
  PATH_SUFFIXES lib
  HINTS ${PROJECT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
        ${MBEDTLS_ROOT_DIR}
		${PC_MBEDTLS_LIBRARY_DIRS}
        ${_MBEDTLS_EXTRA_FIND_ARGS})

find_library(
  MBEDX509_LIBRARY
  NAMES mbedx509
  PATH_SUFFIXES lib
  HINTS ${PROJECT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
        ${MBEDTLS_ROOT_DIR}
		${PC_MBEDTLS_LIBRARY_DIRS}
        ${_EXTRA_FIND_ARGS})

find_library(
  MBEDCRYPTO_LIBRARY
  NAMES mbedcrypto
  PATH_SUFFIXES lib
  HINTS ${PROJECT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
        ${MBEDTLS_ROOT_DIR}
		${PC_MBEDTLS_LIBRARY_DIRS}
        ${_EXTRA_FIND_ARGS})

set(MBEDTLS_LIBRARIES
    "${MBEDTLS_LIBRARY}"
    "${MBEDX509_LIBRARY}"
    "${MBEDCRYPTO_LIBRARY}")

if(MBEDTLS_INCLUDE_DIRS AND EXISTS "${MBEDTLS_INCLUDE_DIRS}/mbedtls/build_info.h")
  file(STRINGS "${MBEDTLS_INCLUDE_DIRS}/mbedtls/build_info.h" MbedTLS_VERSION_STR
    REGEX "#[\t ]*define[\t ]+MBEDTLS_VERSION_STRING[\t ]+\"[^\"]+\"")
  string(REGEX REPLACE "^.*MBEDTLS_VERSION_STRING[\t ]+\"([^\"]+)\""
    "\\1" MbedTLS_VERSION_STR "${MbedTLS_VERSION_STR}")
  set(MbedTLS_VERSION "${MbedTLS_VERSION_STR}")
  unset(MbedTLS_VERSION_STR)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
  MbedTLS
  FAIL_MESSAGE "Could NOT find MbedTLS, try to set the path to MbedTLS root folder in the system variable MBEDTLS_ROOT_DIR"
  REQUIRED_VARS MBEDTLS_INCLUDE_DIRS
                MBEDTLS_LIBRARY
                MBEDX509_LIBRARY
                MBEDCRYPTO_LIBRARY
  VERSION_VAR MbedTLS_VERSION)

if(NOT
   TARGET
   MbedTLS::mbedtls)
  add_library(
    MbedTLS::mbedtls
    UNKNOWN
    IMPORTED)
  set_target_properties(
    MbedTLS::mbedtls
    PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${MBEDTLS_INCLUDE_DIRS}"
               VERSION "${MbedTLS_VERSION}"
               IMPORTED_LINK_INTERFACE_LANGUAGES "C"
               IMPORTED_LOCATION "${MBEDTLS_LIBRARY}"
               INTERFACE_LINK_LIBRARIES "MbedTLS::mbedx509")
endif()

if(NOT
   TARGET
   MbedTLS::mbedx509)
  add_library(
    MbedTLS::mbedx509
    UNKNOWN
    IMPORTED)
  set_target_properties(
    MbedTLS::mbedx509
    PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${MBEDTLS_INCLUDE_DIRS}"
               VERSION "${MbedTLS_VERSION}"
               IMPORTED_LINK_INTERFACE_LANGUAGES "C"
               IMPORTED_LOCATION "${MBEDX509_LIBRARY}"
               INTERFACE_LINK_LIBRARIES "MbedTLS::mbedcrypto")
endif()

if(NOT
   TARGET
   MbedTLS::mbedcrypto)
  add_library(
    MbedTLS::mbedcrypto
    UNKNOWN
    IMPORTED)
  set_target_properties(
    MbedTLS::mbedcrypto
    PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${MBEDTLS_INCLUDE_DIRS}"
               VERSION "${MbedTLS_VERSION}"
               IMPORTED_LINK_INTERFACE_LANGUAGES "C"
               IMPORTED_LOCATION "${MBEDCRYPTO_LIBRARY}"
               INTERFACE_LINK_LIBRARIES "$<$<BOOL:${WIN32}>:bcrypt>")
endif()

mark_as_advanced(
  MBEDTLS_INCLUDE_DIRS
  MBEDTLS_LIBRARY
  MBEDX509_LIBRARY
  MBEDCRYPTO_LIBRARY)
