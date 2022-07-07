/*
 * coap_include_windows_internal.h -- #include list specifically for Windows
 *
 * Copyright (C) 2022 Olaf Bergmann <bergmann@tzi.org>
 *               2022 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#ifndef COAP_INCLUDE_WINDOWS_INTERNAL_H_
#define COAP_INCLUDE_WINDOWS_INTERNAL_H_

#pragma comment(lib,"Ws2_32.lib")
#include <ws2tcpip.h>
typedef SSIZE_T ssize_t;
typedef USHORT in_port_t;

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>

#endif /* COAP_INCLUDE_WINDOWS_INTERNAL_H_ */
