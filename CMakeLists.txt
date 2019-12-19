project(libcoap
        VERSION 4.2.1
        LANGUAGES CXX
                  C)

message(STATUS "building libcoap with cmake")

set(PACKAGE_STRING "${PROJECT_NAME} ${PROJECT_VERSION}")
set(LIBCOAP_PACKAGE_VERSION "${PROJECT_VERSION}")
set(LIBCOAP_PACKAGE_URL "TODO")
set(LIBCOAP_PACKAGE_NAME "${PROJECT_NAME}")
set(LIBCOAP_PACKAGE_STRING "TODO")
set(LIBCOAP_PACKAGE_BUGREPORT "${PROJECT_NAME} ${PROJECT_VERSION}")

configure_file(${CMAKE_CURRENT_LIST_DIR}/libcoap/include/coap2/coap.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/include/coap2/coap.h)

configure_file(${CMAKE_CURRENT_LIST_DIR}/libcoap/coap_config.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/include/coap2/coap_config.h)

add_library(libcoap
            # sources
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/src/pdu.c
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/src/net.c
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/src/coap_debug.c
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/src/encode.c
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/src/uri.c
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/src/subscribe.c
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/src/resource.c
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/src/str.c
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/src/option.c
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/src/async.c
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/src/block.c
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/src/mem.c
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/src/coap_io.c
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/src/coap_session.c
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/src/coap_notls.c
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/src/coap_hashkey.c
            # headers
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/include/coap2/address.h
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/include/coap2/async.h
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/include/coap2/bits.h
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/include/coap2/block.h
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/include/coap2/coap_debug.h
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/include/coap2/coap_dtls.h
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/include/coap2/coap_event.h
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/include/coap2/coap.h
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/include/coap2/coap_hashkey.h
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/include/coap2/coap.h.in
            #     ${CMAKE_CURRENT_LIST_DIR}/libcoap/include/coap2/coap.h.windows
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/include/coap2/coap_io.h
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/include/coap2/coap_session.h
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/include/coap2/coap_time.h
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/include/coap2/encode.h
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/include/coap2/libcoap.h
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/include/coap2/lwippools.h
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/include/coap2/mem.h
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/include/coap2/net.h
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/include/coap2/option.h
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/include/coap2/pdu.h
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/include/coap2/prng.h
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/include/coap2/resource.h
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/include/coap2/str.h
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/include/coap2/subscribe.h
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/include/coap2/uri.h
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/include/coap2/uthash.h
            ${CMAKE_CURRENT_LIST_DIR}/libcoap/include/coap2/utlist.h)
target_include_directories(libcoap
                           PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/libcoap/include/>
                                  $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/libcoap/>
                                  $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/libcoap/include/coap2>
                                  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include/>
                                  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include/coap2/>
                                  $<INSTALL_INTERFACE:include/>)
