# FindopenHiTLS
# -------------
#
# Find the openHiTLS crypto and (D)TLS libraries.
#
# Imported Targets
# ^^^^^^^^^^^^^^^^
#
# ``openHiTLS::openhitls``
#   The openHiTLS libraries, if found.
#
# Result Variables
# ^^^^^^^^^^^^^^^^
#
# ``openHiTLS_FOUND``, ``openHiTLS_VERSION``, ``OPENHITLS_INCLUDE_DIRS``,
# ``OPENHITLS_LIBRARIES``.
#
# Hints
# ^^^^^
#
# ``OPENHITLS_ROOT_DIR``   openHiTLS installation prefix.

set(OPENHITLS_ROOT_DIR "" CACHE PATH "openHiTLS installation prefix")

find_path(
  OPENHITLS_INCLUDE_DIR
  NAMES hitls/crypto/crypt_eal_init.h
  HINTS ${OPENHITLS_ROOT_DIR}
  PATH_SUFFIXES include)
find_library(
  OPENHITLS_CRYPTO_LIBRARY
  NAMES hitls_crypto
  HINTS ${OPENHITLS_ROOT_DIR}
  PATH_SUFFIXES lib lib64)
find_library(
  OPENHITLS_BSL_LIBRARY
  NAMES hitls_bsl
  HINTS ${OPENHITLS_ROOT_DIR}
  PATH_SUFFIXES lib lib64)
find_library(
  OPENHITLS_TLS_LIBRARY
  NAMES hitls_tls
  HINTS ${OPENHITLS_ROOT_DIR}
  PATH_SUFFIXES lib lib64)
find_library(
  OPENHITLS_PKI_LIBRARY
  NAMES hitls_pki
  HINTS ${OPENHITLS_ROOT_DIR}
  PATH_SUFFIXES lib lib64)

set(_OPENHITLS_REQUIRED_VARS
    OPENHITLS_INCLUDE_DIR
    OPENHITLS_TLS_LIBRARY
    OPENHITLS_PKI_LIBRARY
    OPENHITLS_CRYPTO_LIBRARY
    OPENHITLS_BSL_LIBRARY)
set(OPENHITLS_INCLUDE_DIRS
    "${OPENHITLS_INCLUDE_DIR}"
    # TBD: openhitls internal header include sub module use bare path
    # (e.g. hitls/tls/hitls.h has #include "bsl_obj.h"), which only resolves when
    # each module directory is on the include path.
    # once openHiTLS adjust internal header include, below lines should be removed.
    "${OPENHITLS_INCLUDE_DIR}/hitls/tls"
    "${OPENHITLS_INCLUDE_DIR}/hitls/pki"
    "${OPENHITLS_INCLUDE_DIR}/hitls/bsl"
    "${OPENHITLS_INCLUDE_DIR}/hitls/crypto")
if(OPENHITLS_INCLUDE_DIR AND EXISTS "${OPENHITLS_INCLUDE_DIR}/hitls/bsl/bsl_version.h")
  file(STRINGS "${OPENHITLS_INCLUDE_DIR}/hitls/bsl/bsl_version.h" openHiTLS_VERSION_STR
    REGEX "#[\t ]*define[\t ]+OPENHITLS_VERSION_S[\t ]+\"[^\"]+\"")
  string(REGEX REPLACE "^.*OPENHITLS_VERSION_S[\t ]+\"openHiTLS[\t ]+([0-9]+\\.[0-9]+\\.[0-9]+).*$"
    "\\1" openHiTLS_VERSION_STR "${openHiTLS_VERSION_STR}")
  set(openHiTLS_VERSION "${openHiTLS_VERSION_STR}")
  unset(openHiTLS_VERSION_STR)
endif()
set(OPENHITLS_LIBRARIES
    "${OPENHITLS_TLS_LIBRARY}"
    "${OPENHITLS_PKI_LIBRARY}"
    "${OPENHITLS_CRYPTO_LIBRARY}"
    "${OPENHITLS_BSL_LIBRARY}"
    "${CMAKE_DL_LIBS}")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
  openHiTLS
  FAIL_MESSAGE "Could NOT find openHiTLS, set OPENHITLS_ROOT_DIR to the openHiTLS installation prefix"
  REQUIRED_VARS ${_OPENHITLS_REQUIRED_VARS}
  VERSION_VAR openHiTLS_VERSION)

if(openHiTLS_FOUND AND NOT TARGET openHiTLS::openhitls)
  add_library(openHiTLS::openhitls INTERFACE IMPORTED)
  set_target_properties(
    openHiTLS::openhitls
    PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${OPENHITLS_INCLUDE_DIRS}"
               INTERFACE_LINK_LIBRARIES "${OPENHITLS_LIBRARIES}")
endif()

mark_as_advanced(
  OPENHITLS_INCLUDE_DIR
  OPENHITLS_CRYPTO_LIBRARY
  OPENHITLS_BSL_LIBRARY
  OPENHITLS_TLS_LIBRARY
  OPENHITLS_PKI_LIBRARY)
