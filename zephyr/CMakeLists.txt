# zephyr/CMakeLists.txt for libcoap
#
# Copyright (C) 2023-2024 Jon Shallow <supjps-libcoap@jpshallow.com>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# This file is part of the CoAP library libcoap. Please see README for terms
# of use.
#
###############################################################################

cmake_minimum_required(VERSION 3.20.0)

if(CONFIG_LIBCOAP)
  if(CONFIG_MBEDTLS)
    set(ENABLE_DTLS ON)
    set(DTLS_BACKEND "zephyr" CACHE STRING "Zephyr build")
    set_property(
      CACHE DTLS_BACKEND
      PROPERTY STRINGS
             zephyr)
    set(COAP_WITH_LIBMBEDTLS 1)
  else()
    set(ENABLE_DTLS OFF)
  endif()
  if (CONFIG_LIBCOAP_CLIENT_SUPPORT)
    set (ENABLE_CLIENT_MODE ON)
  else()
    set (ENABLE_CLIENT_MODE OFF)
  endif()
  if (CONFIG_LIBCOAP_SERVER_SUPPORT)
    set (ENABLE_SERVER_MODE ON)
  else()
    set (ENABLE_SERVER_MODE OFF)
  endif()
  if (CONFIG_LIBCOAP_OSCORE_SUPPORT)
    set (ENABLE_OSCORE ON)
  else()
    set (ENABLE_OSCORE OFF)
  endif()
  if (CONFIG_LIBCOAP_OBSERVE_PERSIST)
    set (WITH_OBSERVE_PERSIST ON)
  else()
    set (WITH_OBSERVE_PERSIST OFF)
  endif()
  if (CONFIG_LIBCOAP_OBSERVE_PERSIST)
    set (WITH_OBSERVE_PERSIST ON)
  else()
    set (WITH_OBSERVE_PERSIST OFF)
  endif()
  if (CONFIG_LIBCOAP_TCP_SUPPORT)
    set (ENABLE_TCP ON)
  else()
    set (ENABLE_TCP OFF)
  endif()
  if (CONFIG_LIBCOAP_IPV4_SUPPORT)
    set (ENABLE_IPV4 ON)
  else()
    set (ENABLE_IPV4 OFF)
  endif()
  if (CONFIG_LIBCOAP_IPV6_SUPPORT)
    set (ENABLE_IPV6 ON)
  else()
    set (ENABLE_IPV6 OFF)
  endif()
  if (CONFIG_LIBCOAP_WS_SOCKET)
    set (ENABLE_WS ON)
  else()
    set (ENABLE_WS OFF)
  endif()
  if (CONFIG_LIBCOAP_ASYNC_SUPPORT)
    set (ENABLE_ASYNC ON)
  else()
    set (ENABLE_ASYNC OFF)
  endif()
  if (CONFIG_LIBCOAP_Q_BLOCK_SUPPORT)
    set (ENABLE_Q_BLOCK ON)
  else()
    set (ENABLE_Q_BLOCK OFF)
  endif()

  set (ENABLE_SMALL_STACK ON)
  set (ENABLE_AF_UNIX OFF)
  set (WITH_EPOLL OFF)
  set (ENABLE_TESTS OFF)
  set (ENABLE_EXAMPLES OFF)
  set (WARNING_TO_ERROR OFF)

  if(CONFIG_MBEDTLS)
    target_include_directories(mbedTLS INTERFACE ${ZEPHYR_LIBCOAP_MODULE_DIR}/include)
  endif()

  add_subdirectory(.. build)
  target_compile_definitions(coap-3 PUBLIC WITH_ZEPHYR)
  target_link_libraries(coap-3 PUBLIC zephyr_interface)
  set_property(GLOBAL APPEND PROPERTY ZEPHYR_INTERFACE_LIBS coap-3)

  target_link_libraries(app PUBLIC coap-3)
endif()
