cmake_minimum_required(VERSION 3.12)

project(libcoap
        VERSION 4.3.0
        LANGUAGES CXX
                  C)

option(WITH_EPOLL
       "compile with epoll support"
       OFF)
option(WITH_GNUTLS
       "compile with gnutls support"
       OFF)
option(WITH_OPENSSL
       "compile with OPENSSL support"
       ON)

include(CheckCSourceCompiles)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckSymbolExists)
include(CheckTypeSize)
include(TestBigEndian)

# check for headers

check_include_file(byteswap.h
                   HAVE_BYTESWAP_H)
check_include_file(inttypes.h
                   HAVE_INTTYPES_H)
check_include_file(limits.h
                   HAVE_LIMITS_H)
check_include_file(memory.h
                   HAVE_MEMORY_H)
check_include_file(strings.h
                   HAVE_STRINGS_H)
check_include_file(string.h
                   HAVE_STRING_H)
check_include_file(sys/sysctl.h
                   HAVE_SYS_SYSCTL_H)
check_include_file(netinet/in.h
                   HAVE_NETINET_IN_H)
check_include_file(sys/epoll.h
                   HAVE_EPOLL_H)
check_include_file(sys/timerfd.h
                   HAVE_TIMERFD_H)
check_include_file(arp/inet.h
                   HAVE_ARPA_INET_H)
check_include_file(stdbool.h
                   HAVE_STDBOOL_H)
check_include_file(netdb.h
                   HAVE_NETDB_H)
check_include_file(pthread.h
                   HAVE_PTHREAD_H)
check_include_file(strings.h
                   HAVE_STRINGS_H)
check_include_file(stdlib.h
                   HAVE_STDINT_H)
check_include_file(stdint.h
                   HAVE_STDLIB_H)
check_include_file(inttypes.h
                   HAVE_INTTYPES_H)
check_include_file(syslog.h
                   HAVE_SYSLOG_H)
check_include_file(sys/ioctl.h
                   HAVE_SYS_IOCTL_H)
check_include_file(sys/socket.h
                   HAVE_SYS_SOCKET_H)
check_include_file(sys/stat.h
                   HAVE_SYS_STAT_H)
check_include_file(sys/time.h
                   HAVE_SYS_TIME_H)
check_include_file(sys/types.h
                   HAVE_SYS_TYPES_H)
check_include_file(sys/unistd.h
                   HAVE_SYS_UNISTD_H)
check_include_file(time.h
                   HAVE_TIME_H)
check_include_file(unistd.h
                   HAVE_UNISTD_H)

# check for functions

check_function_exists(malloc
                      HAVE_MALLOC)
check_function_exists(memset
                      HAVE_MEMSET)
check_function_exists(select
                      HAVE_SELECT)
check_function_exists(socket
                      HAVE_SOCKET)
check_function_exists(strcasecmp
                      HAVE_STRCASECMP)
check_function_exists(pthread_mutex_lock
                      HAVE_PTHREAD_MUTEX_LOCK)
check_function_exists(getaddrinfo
                      HAVE_GETADDRINFO)
check_function_exists(strnlen
                      HAVE_STRNLEN)
check_function_exists(strrchr
                      HAVE_STRRCHR)

if(${WITH_EPOLL} AND ${HAVE_EPOLL_H} AND ${HAVE_TIMERFD_H})
  set(COAP_EPOLL_SUPPORT "1")
  message(STATUS "compiling with epoll support")
endif()

if(WITH_OPENSSL)
  set(WITH_OPENSSL "${WITH_OPENSSL}")
  message(STATUS "compiling with openssl support")
endif()

set(PACKAGE_URL "https://libcoap.net/")
set(PACKAGE_STRING "${PROJECT_NAME} ${PROJECT_VERSION}")
set(LIBCOAP_PACKAGE_VERSION "${PROJECT_VERSION}")
set(LIBCOAP_PACKAGE_URL "${PACKAGE_URL}")
set(LIBCOAP_PACKAGE_NAME "${PROJECT_NAME}")
set(LIBCOAP_PACKAGE_STRING "TODO")
set(LIBCOAP_PACKAGE_BUGREPORT "libcoap-developers@lists.sourceforge.net")

configure_file(${CMAKE_CURRENT_LIST_DIR}/include/coap2/coap.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/include/coap2/coap.h)

configure_file(${CMAKE_CURRENT_LIST_DIR}/coap_config.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/include/coap2/coap_config.h)

add_library(libcoap
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
            #     ${CMAKE_CURRENT_LIST_DIR}/include/coap2/coap.h.windows
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
target_include_directories(libcoap
                           PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include/>
                                  $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/>
                                  $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include/coap2>
                                  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include/>
                                  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include/coap2/>
                                  $<INSTALL_INTERFACE:include/>)
