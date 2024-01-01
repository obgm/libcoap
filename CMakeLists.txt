# CMakeLists.txt for libcoap
#
# Copyright (C) 2020 Carlos Gomes Martinho <carlos.gomes_martinho@siemens.com>
# Copyright (C) 2020-2024 Jon Shallow <supjps-libcoap@jpshallow.com>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# This file is part of the CoAP library libcoap. Please see README for terms
# of use.

cmake_minimum_required(VERSION 3.10)

project(
  libcoap
  VERSION 4.3.4
  LANGUAGES CXX C)

set(LIBCOAP_API_VERSION 3)
set(LIBCOAP_ABI_VERSION 3.1.1)

set(COAP_LIBRARY_NAME "coap-${LIBCOAP_API_VERSION}")

option(
  BUILD_SHARED_LIBS
  "Build shared libs"
  OFF)

#
# global compiler options
# (need to do it before add_library())
#

add_compile_options(
  $<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>>:-pedantic>
  $<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>>:-Wall>
  $<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>>:-Wcast-qual>
  $<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>>:-Wextra>
  $<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>>:-Wformat-security>
  $<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>>:-Winline>
  $<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>>:-Wmissing-declarations>
  $<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>>:-Wmissing-prototypes>
  $<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>>:-Wnested-externs>
  $<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>>:-Wpointer-arith>
  $<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>>:-Wshadow>
  $<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>>:-Wstrict-prototypes>
  $<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>>:-Wswitch-default>
  $<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>>:-Wswitch-enum>
  $<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>>:-Wunused>
  $<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>>:-Wwrite-strings>)

if(MINGW)
add_compile_options(
  $<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>>:-Wno-format>
  $<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>>:-Wno-format-security>)
endif()

if(${WARNING_TO_ERROR})
add_compile_options(
  $<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>>:-Werror>)
endif()

if(CMAKE_GENERATOR MATCHES "Visual Studio")
  option(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS "Export all symbols when compiling to a .dll" ON)
  # add_compile_options(/Wall /wd4100 /wd4820 /wd4668 /wd4061)
  if(${WARNING_TO_ERROR})
    add_compile_options(/WX)
  endif()
endif()

#
# The libcoap library
#

add_library(${COAP_LIBRARY_NAME})
set_property(TARGET ${COAP_LIBRARY_NAME} PROPERTY C_STANDARD 99)
if(${CMAKE_VERSION} VERSION_GREATER "3.20.0")
  cmake_policy(SET CMP0115 OLD) # Supresses libcoap configuration warning
endif()

set_target_properties(${COAP_LIBRARY_NAME} PROPERTIES SOVERSION ${LIBCOAP_API_VERSION})
set_target_properties(${COAP_LIBRARY_NAME} PROPERTIES VERSION ${LIBCOAP_ABI_VERSION})

#
# options to tweak the library
#

option(
  ENABLE_DTLS
  "enable building with DTLS support"
  ON)
set(DTLS_BACKEND
    "default"
    CACHE
      STRING
      "\
Name of the dtls backend, only relevant if `ENABLE_DTLS` is ON which is default. \
Possible values: default, gnutls, openssl, tinydtls and mbedtls. \
If specified then this library will be searched and if found also used. \
If not found then the cmake configuration will stop with an error. \
If not specified, then cmake will try to use the first one found in the following order: \
gnutls, openssl, tinydtls, mbedtls \
    ")
set_property(
  CACHE DTLS_BACKEND
  PROPERTY STRINGS
           default
           openssl
           gnutls
           tinydtls
           mbedtls)
option(
  USE_VENDORED_TINYDTLS
  "compile with the tinydtls project in the submodule if on, otherwise try to find the compiled lib with find_package"
  ON)
option(
  ENABLE_CLIENT_MODE
  "compile with support for client mode code"
  ON)
option(
  ENABLE_SERVER_MODE
  "compile with support for server mode code"
  ON)
option(
  ENABLE_OSCORE
  "compile with support for OSCORE"
  ON)
option(
  WITH_OBSERVE_PERSIST
  "compile with observe persist support for server restarts"
  ON)
option(
  WITH_EPOLL
  "compile with epoll support"
  ON)
option(
  ENABLE_THREAD_SAFE
  "enable building with thread safe support"
  ON)
option(
  ENABLE_THREAD_RECURSIVE_LOCK_CHECK
  "enable building with thread recursive lock detection"
  OFF)
option(
  ENABLE_SMALL_STACK
  "enable if the system has small stack size"
  OFF)
option(
  ENABLE_TCP
  "enable building with TCP support"
  ON)
option(
  ENABLE_IPV4
  "enable building with IPv4 support"
  ON)
option(
  ENABLE_IPV6
  "enable building with IPv6 support"
  ON)
option(
  ENABLE_AF_UNIX
  "enable building with Unix socket support"
  ON)
option(
  ENABLE_WS
  "enable building with WebSockets support"
  ON)
option(
  ENABLE_ASYNC
  "enable building with async separate response support"
  ON)
option(
  ENABLE_Q_BLOCK
  "enable building with Q-Block (RFC9177) support"
  ON)
option(
  ENABLE_TESTS
  "build also tests"
  OFF)
option(
  ENABLE_EXAMPLES
  "build also examples"
  ON)
option(
  ENABLE_DOCS
  "build also doxygen documentation"
  ON)
option(
  WARNING_TO_ERROR
  "force all compiler warnings to be errors"
  OFF)
set(MAX_LOGGING_LEVEL
    "8"
    CACHE
      STRING
      "\
Only build logging code up to and including the specified logging level (0 - 8)[default=8]]
    ")
set_property(
  CACHE MAX_LOGGING_LEVEL
  PROPERTY STRINGS
           "0"
           "1"
           "2"
           "3"
           "4"
           "5"
           "6"
           "7"
           "8")

if(NOT CMAKE_C_STANDARD)
  set(CMAKE_C_STANDARD 11)
endif()

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

if(MSVC)
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()

if(APPLE)
  add_definitions(-D__APPLE_USE_RFC_3542=1)
endif()

list(APPEND CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR})
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_BINARY_DIR})
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

include(CheckCSourceCompiles)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckSymbolExists)
include(CheckTypeSize)
include(TestBigEndian)

# check for headers
check_include_file(assert.h HAVE_ASSERT_H)
check_include_file(string.h HAVE_STRING_H)
check_include_file(strings.h HAVE_STRINGS_H)
check_include_file(byteswap.h HAVE_BYTESWAP_H)
check_include_file(inttypes.h HAVE_INTTYPES_H)
check_include_file(errno.h HAVE_ERRNO_H)
check_include_file(limits.h HAVE_LIMITS_H)
check_include_file(memory.h HAVE_MEMORY_H)
check_include_file(strings.h HAVE_STRINGS_H)
check_include_file(string.h HAVE_STRING_H)
check_include_file(sys/sysctl.h HAVE_SYS_SYSCTL_H)
check_include_file(net/if.h HAVE_NET_IF_H)
check_include_file(ifaddrs.h HAVE_IFADDRS_H)
check_include_file(netinet/in.h HAVE_NETINET_IN_H)
check_include_file(sys/epoll.h HAVE_EPOLL_H)
check_include_file(sys/timerfd.h HAVE_TIMERFD_H)
check_include_file(arpa/inet.h HAVE_ARPA_INET_H)
check_include_file(stdbool.h HAVE_STDBOOL_H)
check_include_file(netdb.h HAVE_NETDB_H)
check_include_file(pthread.h HAVE_PTHREAD_H)
check_include_file(stdlib.h HAVE_STDINT_H)
check_include_file(stdint.h HAVE_STDLIB_H)
check_include_file(sys/ioctl.h HAVE_SYS_IOCTL_H)
check_include_file(sys/socket.h HAVE_SYS_SOCKET_H)
check_include_file(sys/stat.h HAVE_SYS_STAT_H)
check_include_file(sys/time.h HAVE_SYS_TIME_H)
check_include_file(sys/types.h HAVE_SYS_TYPES_H)
check_include_file(sys/unistd.h HAVE_SYS_UNISTD_H)
check_include_file(time.h HAVE_TIME_H)
check_include_file(unistd.h HAVE_UNISTD_H)
check_include_file(float.h HAVE_FLOAT_H)
check_include_file(stddef.h HAVE_STDDEF_H)
check_include_file(winsock2.h HAVE_WINSOCK2_H)
check_include_file(ws2tcpip.h HAVE_WS2TCPIP_H)

# check for functions
check_function_exists(malloc HAVE_MALLOC)
check_function_exists(memset HAVE_MEMSET)
check_function_exists(select HAVE_SELECT)
check_function_exists(socket HAVE_SOCKET)
check_function_exists(strcasecmp HAVE_STRCASECMP)
check_function_exists(pthread_mutex_lock HAVE_PTHREAD_MUTEX_LOCK)
check_function_exists(getaddrinfo HAVE_GETADDRINFO)
check_function_exists(strnlen HAVE_STRNLEN)
check_function_exists(strrchr HAVE_STRRCHR)
check_function_exists(getrandom HAVE_GETRANDOM)
check_function_exists(random HAVE_RANDOM)
check_function_exists(if_nametoindex HAVE_IF_NAMETOINDEX)

# check for symbols
if(WIN32 AND NOT MINGW)
  set(HAVE_STRUCT_CMSGHDR 1)
  message(STATUS "setting HAVE_STRUCT_CMSGHDR")
else()
  check_symbol_exists(
    CMSG_FIRSTHDR
    sys/socket.h
    HAVE_STRUCT_CMSGHDR)
endif()

if(${ENABLE_CLIENT_MODE})
  set(COAP_CLIENT_SUPPORT "1")
  message(STATUS "compiling with client support")
else()
  message(STATUS "compiling without client support")
endif()

if(${ENABLE_SERVER_MODE})
  set(COAP_SERVER_SUPPORT "1")
  message(STATUS "compiling with server support")
else()
  message(STATUS "compiling without server support")
endif()

if(${ENABLE_OSCORE})
  set(COAP_OSCORE_SUPPORT "1")
  message(STATUS "compiling with OSCORE support")
else()
  message(STATUS "compiling without OSCORE support")
endif()

if(${ENABLE_WS} AND ${ENABLE_TCP})
  set(COAP_WS_SUPPORT "1")
  message(STATUS "compiling with WebSockets support")
else()
  if(${ENABLE_WS})
    set(ENABLE_WS OFF)
    message(STATUS "WebSockets disabled as TCP not enabled")
  endif()
  message(STATUS "compiling without WebSockets support")
endif()

if(${ENABLE_ASYNC})
  set(COAP_ASYNC_SUPPORT "1")
  message(STATUS "compiling with async separate response support")
else()
  message(STATUS "compiling without async separate response support")
endif()

if(${ENABLE_IPV4})
  set(COAP_IPV4_SUPPORT "1")
  message(STATUS "compiling with IPv4 support")
else()
  message(STATUS "compiling without IPv4 support")
endif()

if(${ENABLE_IPV6})
  set(COAP_IPV6_SUPPORT "1")
  message(STATUS "compiling with IPv6 support")
else()
  message(STATUS "compiling without IPv6 support")
endif()

if(${ENABLE_AF_UNIX})
  set(COAP_AF_UNIX_SUPPORT "1")
  message(STATUS "compiling with Unix socket support")
else()
  message(STATUS "compiling without Unix socket support")
endif()

if(${ENABLE_Q_BLOCK})
  set(COAP_Q_BLOCK_SUPPORT "1")
  message(STATUS "compiling with Q-Block (RFC9177) support")
else()
  message(STATUS "compiling without Q-Block (RFC9177) support")
endif()


if(${WITH_OBSERVE_PERSIST})
  set(COAP_WITH_OBSERVE_PERSIST "1")
  message(STATUS "compiling with observe persistence support")
else()
  message(STATUS "compiling without observe persistence support")
endif()

if(${WITH_EPOLL}
   AND HAVE_EPOLL_H
   AND HAVE_TIMERFD_H)
  set(COAP_EPOLL_SUPPORT "1")
  message(STATUS "compiling with epoll support")
else()
  if(${WITH_EPOLL})
    set(WITH_EPOLL OFF)
    message(STATUS "epoll disabled as kernel support not available")
  endif()
  message(STATUS "compiling without epoll support")
endif()

if(ENABLE_THREAD_SAFE)
  set(COAP_THREAD_SAFE "${ENABLE_THREAD_SAFE}")
  message(STATUS "compiling with thread safe support")
endif()

if(ENABLE_THREAD_RECURSIVE_LOCK_CHECK)
  set(COAP_THREAD_RECURSIVE_CHECK "${ENABLE_THREAD_RECURSIVE_LOCK_CHECK}")
  message(STATUS "compiling with thread recursive lock detection support")
endif()

if(ENABLE_SMALL_STACK)
  set(COAP_CONSTRAINED_STACK "${ENABLE_SMALL_STACK}")
  message(STATUS "compiling with small stack support")
endif()

if(${MAX_LOGGING_LEVEL} MATCHES "[0-8]")
  set(COAP_MAX_LOGGING_LEVEL ${MAX_LOGGING_LEVEL})
  message(STATUS "compiling with max logging level set to ${MAX_LOGGING_LEVEL}")
else()
  message(STATUS "compiling with max logging level set to none")
endif()

set(WITH_GNUTLS OFF)
set(WITH_OPENSSL OFF)
set(WITH_TINYDTLS OFF)
set(WITH_MBEDTLS OFF)

function(compile_tinydtls)
  set(TINYDTLS_SOURCES_DIR ${CMAKE_CURRENT_LIST_DIR}/ext/tinydtls)
  set(TINYDTLS_SOURCES_GENERATED ${TINYDTLS_SOURCES_DIR}/dtls_config.h)

  message(STATUS "compiling the tinydtls lib")

  include(ExternalProject)

  externalproject_add(
    external_tinydtls
    SOURCE_DIR "${TINYDTLS_SOURCES_DIR}"
    BUILD_IN_SOURCE 1
    DOWNLOAD_COMMAND ""
    UPDATE_COMMAND ""
    CONFIGURE_COMMAND
      ${TINYDTLS_SOURCES_DIR}/configure
      --disable-manpages
      --prefix=${CMAKE_BINARY_DIR}
    BUILD_COMMAND make install
    INSTALL_COMMAND ""
    LOG_DOWNLOAD 1
    LOG_CONFIGURE 1)

  externalproject_add_step(
    external_tinydtls autoreconf
    COMMAND ./autogen.sh
    ALWAYS 1
    WORKING_DIRECTORY "${TINYDTLS_SOURCES_DIR}"
    DEPENDERS configure
    DEPENDEES download)

  # Let cmake know that it needs to execute the external_tinydtls target to generate those files.
  add_custom_command(
    OUTPUT ${TINYDTLS_SOURCES_GENERATED}
    WORKING_DIRECTORY "${TINYDTLS_SOURCES_DIR}"
    COMMAND "make install"
    DEPENDS external_tinydtls)

  add_dependencies(${COAP_LIBRARY_NAME} external_tinydtls)

  if(BUILD_SHARED_LIBS)
    set(LIBTINYDTLS_PATH "${CMAKE_CURRENT_BINARY_DIR}/lib/libtinydtls.so")
  else()
    set(LIBTINYDTLS_PATH "${CMAKE_CURRENT_BINARY_DIR}/lib/libtinydtls.a")
  endif()

  add_library(
    tinydtls
    UNKNOWN
    IMPORTED)
  set_target_properties(
    tinydtls
    PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
               "${CMAKE_CURRENT_BINARY_DIR}/include"
               IMPORTED_LINK_INTERFACE_LANGUAGES "C"
               IMPORTED_LOCATION "${LIBTINYDTLS_PATH}")

endfunction()

if(ENABLE_DTLS)
  message(STATUS "compiling with DTLS support")
  message(STATUS "DTLS_BACKEND: ${DTLS_BACKEND}")

  if(DTLS_BACKEND
     STREQUAL
     "default")
    # try to find a crypto lib and use it, use the first one found

    # libgnutls (e.g. debian libgnutls28-dev)
    find_package(GnuTLS)
    if(GnuTLS_FOUND)
      set(WITH_GNUTLS ON)
      message(STATUS "compiling with gnutls support")
      set(COAP_WITH_LIBGNUTLS 1)
    else()
      # gnutls not found
      find_package(OpenSSL)
      if(OpenSSL_FOUND)
        set(WITH_OPENSSL ON)
        message(STATUS "compiling with openssl support")
        set(COAP_WITH_LIBOPENSSL 1)
      else()
        # openssl not found
        # libmbedtls (e.g. debian libmbedtls-dev)
        find_package(MbedTLS)
        if(MbedTLS_FOUND)
          set(WITH_MBEDTLS ON)
          message(STATUS "compiling with mbedtls support")
          set(COAP_WITH_LIBMBEDTLS 1)
        else()
          # mbedtls not found
          if(USE_VENDORED_TINYDTLS)
            compile_tinydtls()
          else()
            find_package(TinyDTLS)
            if(TINYDTLS_FOUND)

            else()
              # no cryto lib found
              message(
                FATAL_ERROR
                  "cannot find any cryto lib, either install one or compile without DTLS support"
              )
            endif()

          endif()

          set(WITH_TINYDTLS ON)
          message(STATUS "compiling with tinydtls support")
          set(COAP_WITH_LIBTINYDTLS 1)

        endif()

      endif()

    endif()

  else()
    # DTLS_BACKEND variable is not empty, so set all to false and set the only right to true
    set(WITH_GNUTLS OFF)
    set(WITH_TINYDTLS OFF)
    set(WITH_MBEDTLS OFF)
    set(WITH_OPENSSL OFF)

    if(DTLS_BACKEND
       STREQUAL
       "gnutls")
      # libgnutls (e.g. debian libgnutls28-dev)
      find_package(GnuTLS REQUIRED)
      set(WITH_GNUTLS ON)
      message(STATUS "compiling with gnutls support")
      set(COAP_WITH_LIBGNUTLS 1)
    endif()

    if(DTLS_BACKEND
       STREQUAL
       "openssl")
      # libssl (e.g. debian libssl1.0-dev)
      find_package(OpenSSL REQUIRED)
      set(WITH_OPENSSL ON)
      message(STATUS "compiling with openssl support")
      set(COAP_WITH_LIBOPENSSL 1)
    endif()

    if(DTLS_BACKEND
       STREQUAL
       "mbedtls")
      # libmbedtls (e.g. debian libmbedtls-dev)
      find_package(MbedTLS REQUIRED)
      set(WITH_MBEDTLS ON)
      message(STATUS "compiling with mbedtls support")
      set(COAP_WITH_LIBMBEDTLS 1)
    endif()

    if(DTLS_BACKEND
       STREQUAL
       "tinydtls")

      if(USE_VENDORED_TINYDTLS)
        compile_tinydtls()
      else(USE_VENDORED_TINYDTLS)
        find_package(TinyDTLS REQUIRED)
      endif(USE_VENDORED_TINYDTLS)

      message(STATUS "compiling with tinydtls support")
      set(WITH_TINYDTLS ON)
      set(COAP_WITH_LIBTINYDTLS 1)

    endif()

  endif()

endif()

execute_process(COMMAND git describe --tags --dirty --always
                RESULT_VARIABLE USING_GIT
                OUTPUT_VARIABLE LIBCOAP_PACKAGE_BUILD
                OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_QUIET)
if(NOT ${USING_GIT} EQUAL 0)
  set(LIBCOAP_PACKAGE_BUILD ${PROJECT_VERSION})
else()
  set(LIBCOAP_PACKAGE_BUILD "${LIBCOAP_PACKAGE_BUILD}")
endif()

set(PACKAGE_URL "https://libcoap.net/")
set(PACKAGE_NAME "${PROJECT_NAME}")
set(PACKAGE_TARNAME "${PROJECT_NAME}")
set(PACKAGE_STRING "${PROJECT_NAME} ${PROJECT_VERSION}")
set(PACKAGE_VERSION "${PROJECT_VERSION}")
set(PACKAGE_BUGREPORT "libcoap-developers@lists.sourceforge.net")
set(LIBCOAP_PACKAGE_VERSION "${PACKAGE_VERSION}")
set(LIBCOAP_PACKAGE_URL "${PACKAGE_URL}")
set(LIBCOAP_PACKAGE_NAME "${PACKAGE_NAME}")
set(LIBCOAP_PACKAGE_STRING "${PACKAGE_STRING}")
set(LIBCOAP_PACKAGE_BUGREPORT "${PACKAGE_BUGREPORT}")

message(STATUS "")
message(STATUS "libcoap Configuration Summary:")
message(STATUS "")
message(STATUS "PACKAGE VERSION..................${PACKAGE_VERSION}")
message(STATUS "PACKAGE SOURCE...................${LIBCOAP_PACKAGE_BUILD}")
message(STATUS "LIBRARY API VERSION..............${LIBCOAP_API_VERSION}")
message(STATUS "LIBRARY ABI VERSION..............${LIBCOAP_ABI_VERSION}")
message(STATUS "ENABLE_DTLS:.....................${ENABLE_DTLS}")
message(STATUS "ENABLE_TCP:......................${ENABLE_TCP}")
message(STATUS "ENABLE_IPV4:.....................${ENABLE_IPV4}")
message(STATUS "ENABLE_IPV6:.....................${ENABLE_IPV6}")
message(STATUS "ENABLE_AF_UNIX:..................${ENABLE_AF_UNIX}")
message(STATUS "ENABLE_WEBSOCKETS:...............${ENABLE_WS}")
message(STATUS "ENABLE_Q_BLOCK:..................${ENABLE_Q_BLOCK}")
message(STATUS "ENABLE_CLIENT_MODE:..............${ENABLE_CLIENT_MODE}")
message(STATUS "ENABLE_SERVER_MODE:..............${ENABLE_SERVER_MODE}")
message(STATUS "ENABLE_OSCORE:...................${ENABLE_OSCORE}")
message(STATUS "ENABLE_ASYNC:....................${ENABLE_ASYNC}")
message(STATUS "ENABLE_THREAD_SAFE:..............${ENABLE_THREAD_SAFE}")
message(STATUS "ENABLE_THREAD_RECURSIVE_CHECK....${ENABLE_THREAD_RECURSIVE_LOCK_CHECK}")
message(STATUS "ENABLE_DOCS:.....................${ENABLE_DOCS}")
message(STATUS "ENABLE_EXAMPLES:.................${ENABLE_EXAMPLES}")
message(STATUS "DTLS_BACKEND:....................${DTLS_BACKEND}")
message(STATUS "WITH_GNUTLS:.....................${WITH_GNUTLS}")
message(STATUS "WITH_TINYDTLS:...................${WITH_TINYDTLS}")
message(STATUS "WITH_OPENSSL:....................${WITH_OPENSSL}")
message(STATUS "WITH_MBEDTLS:....................${WITH_MBEDTLS}")
message(STATUS "HAVE_LIBTINYDTLS:................${COAP_WITH_LIBTINYDTLS}")
message(STATUS "HAVE_LIBGNUTLS:..................${COAP_WITH_LIBGNUTLS}")
message(STATUS "HAVE_LIBOPENSSL:.................${COAP_WITH_LIBOPENSSL}")
message(STATUS "HAVE_LIBMBEDTLS:.................${COAP_WITH_LIBMBEDTLS}")
message(STATUS "WITH_EPOLL:......................${WITH_EPOLL}")
message(STATUS "WITH_OBSERVE_PERSIST:............${WITH_OBSERVE_PERSIST}")
message(STATUS "BUILD_SHARED_LIBS:...............${BUILD_SHARED_LIBS}")
message(STATUS "MAX_LOGGING_LEVEL:...............${MAX_LOGGING_LEVEL}")
message(STATUS "WARNING_TO_ERROR:................${WARNING_TO_ERROR}")
message(STATUS "CMAKE_C_COMPILER:................${CMAKE_C_COMPILER}")
message(STATUS "CMAKE_CXX_COMPILER_ID:...........${CMAKE_CXX_COMPILER_ID}")
message(STATUS "CMAKE_BUILD_TYPE:................${CMAKE_BUILD_TYPE}")
message(STATUS "CMAKE_SYSTEM_PROCESSOR:..........${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "CMAKE_HOST_SYSTEM_NAME:..........${CMAKE_HOST_SYSTEM_NAME}")
message(STATUS "CMAKE_GENERATOR:.................${CMAKE_GENERATOR}")
message(STATUS "")

set(top_srcdir "${CMAKE_CURRENT_LIST_DIR}")
set(top_builddir "${CMAKE_CURRENT_BINARY_DIR}")
if(ENABLE_TCP)
  set(COAP_DISABLE_TCP 0)
else(ENABLE_TCP)
  set(COAP_DISABLE_TCP 1)
endif(ENABLE_TCP)

# creates config header file in build directory
configure_file(${CMAKE_CURRENT_LIST_DIR}/include/coap${LIBCOAP_API_VERSION}/coap.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/include/coap${LIBCOAP_API_VERSION}/coap.h)

configure_file(${CMAKE_CURRENT_LIST_DIR}/cmake_coap_config.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/coap_config.h)

configure_file(${CMAKE_CURRENT_LIST_DIR}/tests/test_common.h.in
               ${CMAKE_CURRENT_LIST_DIR}/tests/test_common.h)

#
# sources
#

target_sources(
  ${COAP_LIBRARY_NAME}
  PRIVATE ${CMAKE_CURRENT_LIST_DIR}/src/coap_address.c
          ${CMAKE_CURRENT_LIST_DIR}/src/coap_asn1.c
          ${CMAKE_CURRENT_LIST_DIR}/src/coap_async.c
          ${CMAKE_CURRENT_LIST_DIR}/src/coap_block.c
          ${CMAKE_CURRENT_LIST_DIR}/src/coap_cache.c
          ${CMAKE_CURRENT_LIST_DIR}/src/coap_debug.c
          ${CMAKE_CURRENT_LIST_DIR}/src/coap_dtls.c
          ${CMAKE_CURRENT_LIST_DIR}/src/coap_encode.c
          ${CMAKE_CURRENT_LIST_DIR}/src/coap_event.c
          ${CMAKE_CURRENT_LIST_DIR}/src/coap_hashkey.c
          ${CMAKE_CURRENT_LIST_DIR}/src/coap_io.c
          ${CMAKE_CURRENT_LIST_DIR}/src/coap_layers.c
          ${CMAKE_CURRENT_LIST_DIR}/src/coap_mem.c
          ${CMAKE_CURRENT_LIST_DIR}/src/coap_net.c
          ${CMAKE_CURRENT_LIST_DIR}/src/coap_netif.c
          ${CMAKE_CURRENT_LIST_DIR}/src/coap_notls.c
          ${CMAKE_CURRENT_LIST_DIR}/src/coap_option.c
          ${CMAKE_CURRENT_LIST_DIR}/src/coap_oscore.c
          ${CMAKE_CURRENT_LIST_DIR}/src/coap_pdu.c
          ${CMAKE_CURRENT_LIST_DIR}/src/coap_prng.c
          ${CMAKE_CURRENT_LIST_DIR}/src/coap_resource.c
          ${CMAKE_CURRENT_LIST_DIR}/src/coap_session.c
          ${CMAKE_CURRENT_LIST_DIR}/src/coap_sha1.c
          ${CMAKE_CURRENT_LIST_DIR}/src/coap_str.c
          ${CMAKE_CURRENT_LIST_DIR}/src/coap_subscribe.c
          ${CMAKE_CURRENT_LIST_DIR}/src/coap_tcp.c
          ${CMAKE_CURRENT_LIST_DIR}/src/coap_threadsafe.c
          ${CMAKE_CURRENT_LIST_DIR}/src/coap_time.c
          ${CMAKE_CURRENT_LIST_DIR}/src/coap_uri.c
          ${CMAKE_CURRENT_LIST_DIR}/src/coap_ws.c
          # no need to parse those files if we do not need them
          $<$<BOOL:${COAP_WITH_LIBOPENSSL}>:${CMAKE_CURRENT_LIST_DIR}/src/coap_openssl.c>
          $<$<BOOL:${COAP_WITH_LIBTINYDTLS}>:${CMAKE_CURRENT_LIST_DIR}/src/coap_tinydtls.c>
          $<$<BOOL:${COAP_WITH_LIBGNUTLS}>:${CMAKE_CURRENT_LIST_DIR}/src/coap_gnutls.c>
          $<$<BOOL:${COAP_WITH_LIBMBEDTLS}>:${CMAKE_CURRENT_LIST_DIR}/src/coap_mbedtls.c>
          # needed for OSCORE is enabled
          $<$<BOOL:${COAP_OSCORE_SUPPORT}>:${CMAKE_CURRENT_LIST_DIR}/src/oscore/oscore.c>
          $<$<BOOL:${COAP_OSCORE_SUPPORT}>:${CMAKE_CURRENT_LIST_DIR}/src/oscore/oscore_cbor.c>
          $<$<BOOL:${COAP_OSCORE_SUPPORT}>:${CMAKE_CURRENT_LIST_DIR}/src/oscore/oscore_context.c>
          $<$<BOOL:${COAP_OSCORE_SUPPORT}>:${CMAKE_CURRENT_LIST_DIR}/src/oscore/oscore_cose.c>
          $<$<BOOL:${COAP_OSCORE_SUPPORT}>:${CMAKE_CURRENT_LIST_DIR}/src/oscore/oscore_crypto.c>
          # headers
          ${CMAKE_CURRENT_LIST_DIR}/include/coap${LIBCOAP_API_VERSION}/coap.h
          ${CMAKE_CURRENT_LIST_DIR}/include/coap${LIBCOAP_API_VERSION}/libcoap.h
          ${CMAKE_CURRENT_LIST_DIR}/include/coap${LIBCOAP_API_VERSION}/coap_address.h
          ${CMAKE_CURRENT_LIST_DIR}/include/coap${LIBCOAP_API_VERSION}/coap_async.h
          ${CMAKE_CURRENT_LIST_DIR}/include/coap${LIBCOAP_API_VERSION}/coap_block.h
          ${CMAKE_CURRENT_LIST_DIR}/include/coap${LIBCOAP_API_VERSION}/coap_cache.h
          ${CMAKE_CURRENT_LIST_DIR}/include/coap${LIBCOAP_API_VERSION}/coap_debug.h
          ${CMAKE_CURRENT_LIST_DIR}/include/coap${LIBCOAP_API_VERSION}/coap_dtls.h
          ${CMAKE_CURRENT_LIST_DIR}/include/coap${LIBCOAP_API_VERSION}/coap_encode.h
          ${CMAKE_CURRENT_LIST_DIR}/include/coap${LIBCOAP_API_VERSION}/coap_event.h
          ${CMAKE_CURRENT_LIST_DIR}/include/coap${LIBCOAP_API_VERSION}/coap_io.h
          ${CMAKE_CURRENT_LIST_DIR}/include/coap${LIBCOAP_API_VERSION}/coap_mem.h
          ${CMAKE_CURRENT_LIST_DIR}/include/coap${LIBCOAP_API_VERSION}/coap_net.h
          ${CMAKE_CURRENT_LIST_DIR}/include/coap${LIBCOAP_API_VERSION}/coap_option.h
          ${CMAKE_CURRENT_LIST_DIR}/include/coap${LIBCOAP_API_VERSION}/coap_pdu.h
          ${CMAKE_CURRENT_LIST_DIR}/include/coap${LIBCOAP_API_VERSION}/coap_prng.h
          ${CMAKE_CURRENT_LIST_DIR}/include/coap${LIBCOAP_API_VERSION}/coap_resource.h
          ${CMAKE_CURRENT_LIST_DIR}/include/coap${LIBCOAP_API_VERSION}/coap_session.h
          ${CMAKE_CURRENT_LIST_DIR}/include/coap${LIBCOAP_API_VERSION}/coap_str.h
          ${CMAKE_CURRENT_LIST_DIR}/include/coap${LIBCOAP_API_VERSION}/coap_subscribe.h
          ${CMAKE_CURRENT_LIST_DIR}/include/coap${LIBCOAP_API_VERSION}/coap_time.h
          ${CMAKE_CURRENT_LIST_DIR}/include/coap${LIBCOAP_API_VERSION}/coap_uri.h
          ${CMAKE_CURRENT_LIST_DIR}/include/coap${LIBCOAP_API_VERSION}/coap_ws.h)
target_include_directories(
  ${COAP_LIBRARY_NAME}
  PUBLIC # config headers are generated during configuration time
         $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/>
         $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include/>
         $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include/>
         $<INSTALL_INTERFACE:include/>
         $<$<AND:$<BOOL:${COAP_WITH_LIBTINYDTLS}>,$<BOOL:${USE_VENDORED_TINYDTLS}>>:${CMAKE_BINARY_DIR}/include/tinydtls>
         $<$<BOOL:${COAP_WITH_LIBGNUTLS}>:${GNUTLS_INCLUDE_DIR}>
         $<$<BOOL:${COAP_WITH_LIBMBEDTLS}>:${MBEDTLS_INCLUDE_DIRS}>)
target_link_libraries(
  ${COAP_LIBRARY_NAME}
  PUBLIC $<$<BOOL:${COAP_WITH_LIBOPENSSL}>:OpenSSL::SSL>
         $<$<BOOL:${COAP_WITH_LIBOPENSSL}>:OpenSSL::Crypto>
         $<$<BOOL:${COAP_WITH_LIBGNUTLS}>:${GNUTLS_LIBRARIES}>
         $<$<BOOL:${COAP_WITH_LIBTINYDTLS}>:tinydtls>
         $<$<BOOL:${COAP_WITH_LIBMBEDTLS}>:${MBEDTLS_LIBRARY}>
         $<$<BOOL:${COAP_WITH_LIBMBEDTLS}>:${MBEDX509_LIBRARY}>
         $<$<BOOL:${COAP_WITH_LIBMBEDTLS}>:${MBEDCRYPTO_LIBRARY}>
         $<$<BOOL:${MINGW}>:ws2_32>)

target_compile_options(
  ${COAP_LIBRARY_NAME}
  PUBLIC -DLIBCOAP_PACKAGE_BUILD="${LIBCOAP_PACKAGE_BUILD}")

add_library(
  ${PROJECT_NAME}::${COAP_LIBRARY_NAME}
  ALIAS
  ${COAP_LIBRARY_NAME})

#
# tests
#

if(ENABLE_TESTS)
  add_executable(
    testdriver
    ${CMAKE_CURRENT_LIST_DIR}/tests/testdriver.c
    ${CMAKE_CURRENT_LIST_DIR}/tests/test_common.h
    ${CMAKE_CURRENT_LIST_DIR}/tests/test_encode.c
    ${CMAKE_CURRENT_LIST_DIR}/tests/test_encode.h
    ${CMAKE_CURRENT_LIST_DIR}/tests/test_error_response.c
    ${CMAKE_CURRENT_LIST_DIR}/tests/test_error_response.h
    ${CMAKE_CURRENT_LIST_DIR}/tests/test_options.c
    ${CMAKE_CURRENT_LIST_DIR}/tests/test_options.h
    ${CMAKE_CURRENT_LIST_DIR}/tests/test_oscore.c
    ${CMAKE_CURRENT_LIST_DIR}/tests/test_oscore.h
    ${CMAKE_CURRENT_LIST_DIR}/tests/test_pdu.c
    ${CMAKE_CURRENT_LIST_DIR}/tests/test_pdu.h
    ${CMAKE_CURRENT_LIST_DIR}/tests/test_sendqueue.c
    ${CMAKE_CURRENT_LIST_DIR}/tests/test_sendqueue.h
    ${CMAKE_CURRENT_LIST_DIR}/tests/test_session.c
    ${CMAKE_CURRENT_LIST_DIR}/tests/test_session.h
    ${CMAKE_CURRENT_LIST_DIR}/tests/test_tls.c
    ${CMAKE_CURRENT_LIST_DIR}/tests/test_tls.h
    ${CMAKE_CURRENT_LIST_DIR}/tests/test_uri.c
    ${CMAKE_CURRENT_LIST_DIR}/tests/test_uri.h
    ${CMAKE_CURRENT_LIST_DIR}/tests/test_wellknown.c
    ${CMAKE_CURRENT_LIST_DIR}/tests/test_wellknown.h)
  # tests require libcunit (e.g. debian libcunit1-dev)
  target_link_libraries(testdriver PUBLIC ${PROJECT_NAME}::${COAP_LIBRARY_NAME}
                                          -lcunit)
endif()

#
# examples
#

if(ENABLE_EXAMPLES)
  add_executable(coap-client ${CMAKE_CURRENT_LIST_DIR}/examples/coap-client.c)
  target_link_libraries(coap-client
                        PUBLIC ${PROJECT_NAME}::${COAP_LIBRARY_NAME})

  add_executable(coap-rd ${CMAKE_CURRENT_LIST_DIR}/examples/coap-rd.c)
  target_include_directories(coap-rd
    PRIVATE
         $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include/coap${LIBCOAP_API_VERSION}>)
  target_link_libraries(coap-rd PUBLIC ${PROJECT_NAME}::${COAP_LIBRARY_NAME})

  add_executable(coap-server ${CMAKE_CURRENT_LIST_DIR}/examples/coap-server.c)
  target_link_libraries(coap-server
                        PUBLIC ${PROJECT_NAME}::${COAP_LIBRARY_NAME})

  if(NOT WIN32 AND NOT MINGW)
    add_executable(etsi_iot_01 ${CMAKE_CURRENT_LIST_DIR}/examples/etsi_iot_01.c)
    target_link_libraries(etsi_iot_01
                          PUBLIC ${PROJECT_NAME}::${COAP_LIBRARY_NAME})

    add_executable(tiny ${CMAKE_CURRENT_LIST_DIR}/examples/tiny.c)
    target_link_libraries(tiny PUBLIC ${PROJECT_NAME}::${COAP_LIBRARY_NAME})

    add_executable(oscore-interop-server
                   ${CMAKE_CURRENT_LIST_DIR}/examples/oscore-interop-server.c)
    target_link_libraries(oscore-interop-server
                          PUBLIC ${PROJECT_NAME}::${COAP_LIBRARY_NAME})
  endif()
endif()

#
# docs
#

if(ENABLE_DOCS)
  find_package(Doxygen)

  if(Doxygen_FOUND)
    # set input and output files
    set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/doc/Doxyfile.in)
    set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)

    # Make necessary temporary directories
    file(MAKE_DIRECTORY  ${CMAKE_CURRENT_BINARY_DIR}/doc/man_tmp)
    file(MAKE_DIRECTORY  ${CMAKE_CURRENT_BINARY_DIR}/doc/man_html)

    # request to configure the file
    configure_file(
      ${DOXYGEN_IN}
      ${DOXYGEN_OUT}
      @ONLY)

    # note the option ALL which allows to build the docs together with the
    # application
    add_custom_target(
      doc_doxygen ALL
      COMMAND ${DOXYGEN_EXECUTABLE} -u > /dev/null 2>&1
      COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
      COMMENT "Generating API documentation with Doxygen"
      VERBATIM)

    message(STATUS "Setup up the Doxygen documention build")

  else(Doxygen_FOUND)
    message(
      WARNING
        "Doxygen need to be installed to generate the doxygen documentation")
  endif(Doxygen_FOUND)

endif()

#
# install
#

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(LIBCOAP_CONFIG_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})
install(
  TARGETS ${COAP_LIBRARY_NAME}
  EXPORT ${PROJECT_NAME}Targets
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT lib
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT lib)

install(
  EXPORT ${PROJECT_NAME}Targets
  DESTINATION ${LIBCOAP_CONFIG_INSTALL_DIR}
  NAMESPACE ${PROJECT_NAME}::
  COMPONENT dev)

configure_package_config_file(
  cmake/Config.cmake.in
  ${PROJECT_NAME}Config.cmake
  INSTALL_DESTINATION
  ${LIBCOAP_CONFIG_INSTALL_DIR})
write_basic_package_version_file(
  ${PROJECT_NAME}ConfigVersion.cmake
  COMPATIBILITY SameMajorVersion)
install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
  DESTINATION ${LIBCOAP_CONFIG_INSTALL_DIR}
  COMPONENT dev)

install(
  DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/include/
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  COMPONENT dev
  FILES_MATCHING
  PATTERN "*.h"
  PATTERN "coap.h" EXCLUDE
  PATTERN "coap_riot.h" EXCLUDE
  PATTERN "*_internal.h" EXCLUDE
  PATTERN "oscore*" EXCLUDE)
install(
  DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/include/
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  COMPONENT dev
  FILES_MATCHING
  PATTERN "*.h")
if(ENABLE_EXAMPLES)
  install(
    TARGETS coap-server coap-client coap-rd
    DESTINATION ${CMAKE_INSTALL_BINDIR}
    COMPONENT dev)
  if(NOT WIN32 AND NOT MINGW)
    install(
      TARGETS etsi_iot_01 tiny oscore-interop-server
      DESTINATION ${CMAKE_INSTALL_BINDIR}
      COMPONENT dev)
  endif()
endif()
