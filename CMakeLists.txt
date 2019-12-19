cmake_minimum_required(VERSION 3.12)

project(libcoap VERSION 4.3.0 LANGUAGES CXX C)

set(LIBCOAP_API_VERSION 2)

# available options to tweak the library
option(ENABLE_DTLS "Enable building with DTLS support" ON)
option(WITH_OPENSSL "Use OpenSSL for DTLS functions" ON)
option(WITH_GNUTLS "Use GnuTLS for DTLS functions" OFF)
option(WITH_TINYDTLS "Use TinyDTLS for DTLS functions" OFF)
option(WITH_EPOLL "compile with epoll support" OFF)
option(ENABLE_SMALL_STACK "Define if the system has small stack size" OFF)
option(ENABLE_TESTS "build also tests" OFF)
option(ENABLE_EXAMPLES "build also examples" OFF)
option(ENABLE_DOCS "build also doxygen documentation" OFF)

if(NOT CMAKE_C_STANDARD)
  set(CMAKE_C_STANDARD 11)
endif()

include(CheckCSourceCompiles)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckSymbolExists)
include(CheckTypeSize)
include(TestBigEndian)

# check for headers
check_include_file(byteswap.h HAVE_BYTESWAP_H)
check_include_file(inttypes.h HAVE_INTTYPES_H)
check_include_file(limits.h HAVE_LIMITS_H)
check_include_file(memory.h HAVE_MEMORY_H)
check_include_file(strings.h HAVE_STRINGS_H)
check_include_file(string.h HAVE_STRING_H)
check_include_file(sys/sysctl.h HAVE_SYS_SYSCTL_H)
check_include_file(netinet/in.h HAVE_NETINET_IN_H)
check_include_file(sys/epoll.h HAVE_EPOLL_H)
check_include_file(sys/timerfd.h HAVE_TIMERFD_H)
check_include_file(arpa/inet.h HAVE_ARPA_INET_H)
check_include_file(stdbool.h HAVE_STDBOOL_H)
check_include_file(netdb.h HAVE_NETDB_H)
check_include_file(pthread.h HAVE_PTHREAD_H)
check_include_file(strings.h HAVE_STRINGS_H)
check_include_file(stdlib.h HAVE_STDINT_H)
check_include_file(stdint.h HAVE_STDLIB_H)
check_include_file(inttypes.h HAVE_INTTYPES_H)
check_include_file(syslog.h HAVE_SYSLOG_H)
check_include_file(sys/ioctl.h HAVE_SYS_IOCTL_H)
check_include_file(sys/socket.h HAVE_SYS_SOCKET_H)
check_include_file(sys/stat.h HAVE_SYS_STAT_H)
check_include_file(sys/time.h HAVE_SYS_TIME_H)
check_include_file(sys/types.h HAVE_SYS_TYPES_H)
check_include_file(sys/unistd.h HAVE_SYS_UNISTD_H)
check_include_file(time.h HAVE_TIME_H)
check_include_file(unistd.h HAVE_UNISTD_H)
check_include_file(winsock2.h HAVE_WINSOCK2_H)
check_include_file(float.h HAVE_FLOAT_H)
check_include_file(stddef.h HAVE_STDDEF_H)

if(HAVE_STRING_H
   AND HAVE_STRINGS_H
   AND HAVE_FLOAT_H
   AND HAVE_STDLIB_H
   AND HAVE_STDDEF_H
   AND HAVE_STDINT_H
   AND HAVE_INTTYPES_H
   AND HAVE_DLFCN_H)
  set(STDC_HEADERS 1)
endif()

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

# check for symbols
check_symbol_exists(cmsghdr sys/socket.h HAVE_STRUCT_CMSGHDR)

option(WITH_OPENSSL "Use OpenSSL for DTLS functions" ON)
option(WITH_GNUTLS "Use GnuTLS for DTLS functions" OFF)
option(WITH_TINYDTLS "Use TinyDTLS for DTLS functions" OFF)

if(WITH_GNUTLS OR WITH_TINYDTLS)
  set(WITH_OPENSSL OFF)
endif()

if(WITH_GNUTLS AND WITH_TINYDTLS)
  message(FATAL_ERROR "cannot build with gnutls and tinydtls")
endif()

if(${WITH_EPOLL} AND ${HAVE_EPOLL_H} AND ${HAVE_TIMERFD_H})
  set(COAP_EPOLL_SUPPORT "1")
  message(STATUS "compiling with epoll support")
endif()

if(WITH_OPENSSL)
  set(WITH_OPENSSL "${WITH_OPENSSL}")
  message(STATUS "compiling with openssl support")
  find_package(OpenSSL REQUIRED)
  set(HAVE_OPENSSL 1)
endif()

if(WITH_GNUTLS)
  set(WITH_GNUTLS "${WITH_GNUTLS}")
  message(STATUS "compiling with gnutls support")
  find_package(FindGnuTLS REQUIRED)
  set(HAVE_LIBGNUTLS 1)
endif()

if(WITH_TINYDTLS)
  set(WITH_TINYDTLS "${WITH_TINYDTLS}")
  message(STATUS "compiling with tinydtls support")
  set(HAVE_LIBTINYDTLS 1)
endif()

if(ENABLE_SMALL_STACK)
  set(ENABLE_SMALL_STACK "${ENABLE_SMALL_STACK}")
  message(STATUS "compiling with small stack support")
endif()

set(PACKAGE_URL "https://libcoap.net/")
set(PACKAGE_NAME "${PROJECT_NAME}")
set(PACKAGE_TARNAME "${PROJECT_NAME}")
set(PACKAGE_STRING "${PROJECT_NAME} ${PROJECT_VERSION}")
set(LIBCOAP_PACKAGE_VERSION "${PROJECT_VERSION}")
set(LIBCOAP_PACKAGE_URL "${PACKAGE_URL}")
set(LIBCOAP_PACKAGE_NAME "${PROJECT_NAME}")
set(LIBCOAP_PACKAGE_STRING "TODO")
set(LIBCOAP_PACKAGE_BUGREPORT "libcoap-developers@lists.sourceforge.net")
set(top_srcdir "${CMAKE_CURRENT_LIST_DIR}")
set(top_builddir "${CMAKE_CURRENT_BINARY_DIR}")

# creates config header file in build directory
configure_file(${CMAKE_CURRENT_LIST_DIR}/include/coap2/coap.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/include/coap2/coap.h)

configure_file(${CMAKE_CURRENT_LIST_DIR}/coap_config.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/include/coap2/coap_config.h)

add_library(${PROJECT_NAME}
            # sources
            ${CMAKE_CURRENT_LIST_DIR}/src/pdu.c
            ${CMAKE_CURRENT_LIST_DIR}/src/net.c
            ${CMAKE_CURRENT_LIST_DIR}/src/coap_debug.c
            ${CMAKE_CURRENT_LIST_DIR}/src/encode.c
            ${CMAKE_CURRENT_LIST_DIR}/src/uri.c
            ${CMAKE_CURRENT_LIST_DIR}/src/subscribe.c
            ${CMAKE_CURRENT_LIST_DIR}/src/resource.c
            ${CMAKE_CURRENT_LIST_DIR}/src/str.c
            ${CMAKE_CURRENT_LIST_DIR}/src/option.c
            ${CMAKE_CURRENT_LIST_DIR}/src/async.c
            ${CMAKE_CURRENT_LIST_DIR}/src/block.c
            ${CMAKE_CURRENT_LIST_DIR}/src/mem.c
            ${CMAKE_CURRENT_LIST_DIR}/src/coap_io.c
            ${CMAKE_CURRENT_LIST_DIR}/src/coap_session.c
            ${CMAKE_CURRENT_LIST_DIR}/src/coap_notls.c
            ${CMAKE_CURRENT_LIST_DIR}/src/coap_hashkey.c
            ${CMAKE_CURRENT_LIST_DIR}/src/address.c
            ${CMAKE_CURRENT_LIST_DIR}/src/coap_time.c
            ${CMAKE_CURRENT_LIST_DIR}/src/coap_event.c
            # headers
            ${CMAKE_CURRENT_LIST_DIR}/include/coap2/address.h
            ${CMAKE_CURRENT_LIST_DIR}/include/coap2/async.h
            ${CMAKE_CURRENT_LIST_DIR}/include/coap2/bits.h
            ${CMAKE_CURRENT_LIST_DIR}/include/coap2/block.h
            ${CMAKE_CURRENT_LIST_DIR}/include/coap2/coap_debug.h
            ${CMAKE_CURRENT_LIST_DIR}/include/coap2/coap_dtls.h
            ${CMAKE_CURRENT_LIST_DIR}/include/coap2/coap_event.h
            ${CMAKE_CURRENT_LIST_DIR}/include/coap2/coap.h
            ${CMAKE_CURRENT_LIST_DIR}/include/coap2/coap_hashkey.h
            ${CMAKE_CURRENT_LIST_DIR}/include/coap2/coap.h.in
            ${CMAKE_CURRENT_LIST_DIR}/include/coap2/coap_io.h
            ${CMAKE_CURRENT_LIST_DIR}/include/coap2/coap_session.h
            ${CMAKE_CURRENT_LIST_DIR}/include/coap2/coap_time.h
            ${CMAKE_CURRENT_LIST_DIR}/include/coap2/encode.h
            ${CMAKE_CURRENT_LIST_DIR}/include/coap2/libcoap.h
            ${CMAKE_CURRENT_LIST_DIR}/include/coap2/lwippools.h
            ${CMAKE_CURRENT_LIST_DIR}/include/coap2/mem.h
            ${CMAKE_CURRENT_LIST_DIR}/include/coap2/net.h
            ${CMAKE_CURRENT_LIST_DIR}/include/coap2/option.h
            ${CMAKE_CURRENT_LIST_DIR}/include/coap2/pdu.h
            ${CMAKE_CURRENT_LIST_DIR}/include/coap2/prng.h
            ${CMAKE_CURRENT_LIST_DIR}/include/coap2/resource.h
            ${CMAKE_CURRENT_LIST_DIR}/include/coap2/str.h
            ${CMAKE_CURRENT_LIST_DIR}/include/coap2/subscribe.h
            ${CMAKE_CURRENT_LIST_DIR}/include/coap2/uri.h
            ${CMAKE_CURRENT_LIST_DIR}/include/coap2/uthash.h
            ${CMAKE_CURRENT_LIST_DIR}/include/coap2/utlist.h)
target_include_directories(
  ${PROJECT_NAME}
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include/coap2>
         # some *.c  are still including the filename instead of
         # "coap2/header.h"
         $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include/>
         # config headers are generated during configuration time
         $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include/>
         $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include/coap2/>
         $<INSTALL_INTERFACE:include/>)
target_link_libraries(${PROJECT_NAME}
                      PRIVATE $<$<BOOL:${WITH_OPENSSL}>:OpenSSL::SSL>
                              $<$<BOOL:${WITH_OPENSSL}>:OpenSSL::Crypto>
                              $<$<BOOL:${WITH_GNUTLS}>:GnuTLS::GnuTLS>
                              $<$<BOOL:${WITH_TINYDTLS}>:-ltinydtls>
                              
                              
                              
                              )

if(ENABLE_TESTS)
  add_executable(libcoap_tests
                 ${CMAKE_CURRENT_LIST_DIR}/tests/testdriver.c
                 ${CMAKE_CURRENT_LIST_DIR}/tests/test_encode.c
                 ${CMAKE_CURRENT_LIST_DIR}/tests/test_encode.h
                 ${CMAKE_CURRENT_LIST_DIR}/tests/test_error_response.c
                 ${CMAKE_CURRENT_LIST_DIR}/tests/test_error_response.h
                 ${CMAKE_CURRENT_LIST_DIR}/tests/test_options.c
                 ${CMAKE_CURRENT_LIST_DIR}/tests/test_options.h
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
  target_link_libraries(libcoap_tests PUBLIC ${PROJECT_NAME} -lcunit)
endif()

if(ENABLE_EXAMPLES)
  add_executable(client ${CMAKE_CURRENT_LIST_DIR}/examples/client.c)
  target_link_libraries(client PUBLIC ${PROJECT_NAME})

  add_executable(coap-rd ${CMAKE_CURRENT_LIST_DIR}/examples/coap-rd.c)
  target_link_libraries(coap-rd PUBLIC ${PROJECT_NAME})

  add_executable(coap-server ${CMAKE_CURRENT_LIST_DIR}/examples/coap-server.c)
  target_link_libraries(coap-server PUBLIC ${PROJECT_NAME})

  add_executable(etsi_iot_01 ${CMAKE_CURRENT_LIST_DIR}/examples/etsi_iot_01.c)
  target_link_libraries(etsi_iot_01 PUBLIC ${PROJECT_NAME})

  add_executable(tiny ${CMAKE_CURRENT_LIST_DIR}/examples/tiny.c)
  target_link_libraries(tiny PUBLIC ${PROJECT_NAME})
endif()

if(ENABLE_DOCS)
  find_package(Doxygen)

  if(Doxygen_FOUND)
    # set input and output files
    set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/doc/Doxyfile.in)
    set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)

    # request to configure the file
    configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)

    # note the option ALL which allows to build the docs together with the
    # application
    add_custom_target(doc_doxygen ALL
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
