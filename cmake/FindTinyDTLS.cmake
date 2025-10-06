# FindTinyDTLS
# ------------
#
# Find the tinyDTLS encryption library.
#
# Imported Targets
# ^^^^^^^^^^^^^^^^
#
# This module defines the following :prop_tgt:`IMPORTED` targets:
#
# ``TinyDTLS::tinydtls``
#   The tinyDTLS ``tinydtls`` library, if found.
#
# Result Variables
# ^^^^^^^^^^^^^^^^
#
# This module will set the following variables in your project:
#
# ``TinyDTLS_FOUND``
#   System has the tinyDTLS library.
# ``TinyDTLS_VERSION``
#   The version of tinyDTLS found.
# ``TINYDTLS_INCLUDE_DIR``
#   The tinyDTLS include directory.
# ``TINYDTLS_LIBRARIES``
#   All tinyDTLS libraries.
#
# Hints
# ^^^^^
#
# Set ``TINYDTLS_ROOT_DIR`` to the root directory of an tinyDTLS installation.

if(TINYDTLS_INCLUDE_DIR AND TINYDTLS_LIBRARIES)
  # in cache already
  set(TinyDTLS_FIND_QUIETLY TRUE)
endif()

if(TINYDTLS_ROOT_DIR)
  set(_TINYDTLS_EXTRA_FIND_ARGS "NO_CMAKE_FIND_ROOT_PATH")
endif()

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
  pkg_check_modules(PC_TINYDTLS QUIET tinydtls)
endif()

find_path(
  TINYDTLS_INCLUDE_DIR
  NAMES tinydtls/dtls.h
  PATH_SUFFIXES include
  HINTS ${PROJECT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
        ${TINYDTLS_ROOT_DIR}
		${PC_TINYDTLS_INCLUDE_DIRS}
        ${_TINYDTLS_EXTRA_FIND_ARGS})

find_library(
  TINYDTLS_LIBRARIES
  NAMES tinydtls
  PATH_SUFFIXES lib
  HINTS ${PROJECT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
        ${TINYDTLS_ROOT_DIR}
		${PC_TINYDTLS_LIBRARY_DIRS}
        ${_TINYDTLS_EXTRA_FIND_ARGS})

if(TINYDTLS_INCLUDE_DIR AND EXISTS "${TINYDTLS_INCLUDE_DIR}/tinydtls/dtls_config.h")
  file(STRINGS "${TINYDTLS_INCLUDE_DIR}/tinydtls/dtls_config.h" TinyDTLS_VERSION_STR
    REGEX "#[\t ]*define[\t ]+PACKAGE_VERSION[\t ]+\"[^\"]+\"")
  string(REGEX REPLACE "^.*PACKAGE_VERSION[\t ]+\"([^\"]+)\""
    "\\1" TinyDTLS_VERSION_STR "${TinyDTLS_VERSION_STR}")
  set(TinyDTLS_VERSION "${TinyDTLS_VERSION_STR}")
  unset(TinyDTLS_VERSION_STR)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
  TinyDTLS
  FAIL_MESSAGE "Could NOT find TinyDTLS, try to set the path to TinyDTLS root folder in the system variable TINYDTLS_ROOT_DIR"
  REQUIRED_VARS TINYDTLS_INCLUDE_DIR
                TINYDTLS_LIBRARIES
  VERSION_VAR TinyDTLS_VERSION)

if(NOT
   TARGET
   TinyDTLS::tinydtls)
  add_library(
    TinyDTLS::tinydtls
    UNKNOWN
    IMPORTED)
  set_target_properties(
    TinyDTLS::tinydtls
    PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${TINYDTLS_INCLUDE_DIR};${TINYDTLS_INCLUDE_DIR}/tinydtls"
               VERSION "${TinyDTLS_VERSION}"
               IMPORTED_LINK_INTERFACE_LANGUAGES "C"
               IMPORTED_LOCATION "${TINYDTLS_LIBRARIES}")
endif()

mark_as_advanced(
  TINYDTLS_INCLUDE_DIR
  TINYDTLS_LIBRARIES)
