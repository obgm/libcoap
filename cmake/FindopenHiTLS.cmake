# FindopenHiTLS
# -------------
#
# Find the openHiTLS crypto and (D)TLS libraries.
#
# Components
# ^^^^^^^^^^
#
# ``tls``
#   Also require the (D)TLS libraries (``hitls_tls``, ``hitls_pki``).  Without
#   this component only the OSCORE crypto libraries (``hitls_crypto``,
#   ``hitls_bsl``) are required.
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
# ``openHiTLS_FOUND``, ``OPENHITLS_INCLUDE_DIRS``, ``OPENHITLS_LIBRARIES``.
#
# Hints
# ^^^^^
#
# ``OPENHITLS_ROOT_DIR``   openHiTLS source root (contains ``include/`` and
#                          ``config/macro_config/``).
# ``OPENHITLS_BUILD_DIR``  directory containing the ``libhitls_*`` libraries.

set(OPENHITLS_ROOT_DIR "" CACHE PATH "Root directory of openHiTLS")
set(OPENHITLS_BUILD_DIR "" CACHE PATH "Build directory of openHiTLS")

find_path(
  OPENHITLS_INCLUDE_DIR
  NAMES crypto/crypt_eal_init.h
  HINTS ${OPENHITLS_ROOT_DIR}
  PATH_SUFFIXES include)
find_path(
  OPENHITLS_CONFIG_INCLUDE_DIR
  NAMES hitls_build.h
  HINTS ${OPENHITLS_ROOT_DIR}
  PATH_SUFFIXES config/macro_config)
find_library(
  OPENHITLS_CRYPTO_LIBRARY
  NAMES hitls_crypto
  HINTS ${OPENHITLS_BUILD_DIR} ${OPENHITLS_ROOT_DIR}
  PATH_SUFFIXES . build lib lib64)
find_library(
  OPENHITLS_BSL_LIBRARY
  NAMES hitls_bsl
  HINTS ${OPENHITLS_BUILD_DIR} ${OPENHITLS_ROOT_DIR}
  PATH_SUFFIXES . build lib lib64)

set(_OPENHITLS_REQUIRED_VARS
    OPENHITLS_INCLUDE_DIR OPENHITLS_CONFIG_INCLUDE_DIR
    OPENHITLS_CRYPTO_LIBRARY OPENHITLS_BSL_LIBRARY)
set(OPENHITLS_INCLUDE_DIRS
    "${OPENHITLS_INCLUDE_DIR}"
    "${OPENHITLS_INCLUDE_DIR}/bsl"
    "${OPENHITLS_INCLUDE_DIR}/crypto"
    "${OPENHITLS_CONFIG_INCLUDE_DIR}")
set(OPENHITLS_LIBRARIES
    "${OPENHITLS_CRYPTO_LIBRARY}"
    "${OPENHITLS_BSL_LIBRARY}"
    "${CMAKE_DL_LIBS}")

list(FIND openHiTLS_FIND_COMPONENTS tls _OPENHITLS_TLS_INDEX)
if(NOT _OPENHITLS_TLS_INDEX EQUAL -1)
  find_library(
    OPENHITLS_TLS_LIBRARY
    NAMES hitls_tls
    HINTS ${OPENHITLS_BUILD_DIR} ${OPENHITLS_ROOT_DIR}
    PATH_SUFFIXES . build lib lib64)
  find_library(
    OPENHITLS_PKI_LIBRARY
    NAMES hitls_pki
    HINTS ${OPENHITLS_BUILD_DIR} ${OPENHITLS_ROOT_DIR}
    PATH_SUFFIXES . build lib lib64)
  list(APPEND _OPENHITLS_REQUIRED_VARS
       OPENHITLS_TLS_LIBRARY OPENHITLS_PKI_LIBRARY)
  list(APPEND OPENHITLS_INCLUDE_DIRS
       "${OPENHITLS_INCLUDE_DIR}/tls" "${OPENHITLS_INCLUDE_DIR}/pki")
  list(INSERT OPENHITLS_LIBRARIES 0
       "${OPENHITLS_TLS_LIBRARY}" "${OPENHITLS_PKI_LIBRARY}")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
  openHiTLS
  FAIL_MESSAGE "Could NOT find openHiTLS, set OPENHITLS_ROOT_DIR to the openHiTLS source tree and OPENHITLS_BUILD_DIR to the build directory"
  REQUIRED_VARS ${_OPENHITLS_REQUIRED_VARS})

if(openHiTLS_FOUND AND NOT TARGET openHiTLS::openhitls)
  add_library(openHiTLS::openhitls INTERFACE IMPORTED)
  set_target_properties(
    openHiTLS::openhitls
    PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${OPENHITLS_INCLUDE_DIRS}"
               INTERFACE_LINK_LIBRARIES "${OPENHITLS_LIBRARIES}")
endif()

mark_as_advanced(
  OPENHITLS_INCLUDE_DIR
  OPENHITLS_CONFIG_INCLUDE_DIR
  OPENHITLS_CRYPTO_LIBRARY
  OPENHITLS_BSL_LIBRARY
  OPENHITLS_TLS_LIBRARY
  OPENHITLS_PKI_LIBRARY)
