/*
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (c) 2017 Intel Corporation.
 * Copyright (c) 2018 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * libcoap configuration for (D)TLS, manageable by Kconfig.
 */

#ifndef CONFIG_MBEDTLS_LIBCOAP_H
#define CONFIG_MBEDTLS_LIBCOAP_H

#ifndef MBEDTLS_TIMING_C
#define MBEDTLS_TIMING_C
#endif /* ! MBEDTLS_TIMING_C */

#ifndef MBEDTLS_VERSION_C
#define MBEDTLS_VERSION_C
#endif /* ! MBEDTLS_VERSION_C */

#if defined(MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED)
#ifndef MBEDTLS_CAN_ECDH
#define MBEDTLS_CAN_ECDH
#endif /* ! MBEDTLS_CAN_ECDH */

#ifndef MBEDTLS_PK_CAN_ECDSA_SIGN
#define MBEDTLS_PK_CAN_ECDSA_SIGN
#endif /* ! MBEDTLS_PK_CAN_ECDSA_SIGN */

#ifndef MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_CRT_PARSE_C
#endif /* ! MBEDTLS_X509_CRT_PARSE_C */
#endif /* MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED */

#if defined(MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED)
#ifndef MBEDTLS_CAN_ECDH
#define MBEDTLS_CAN_ECDH
#endif /* ! MBEDTLS_CAN_ECDH */

#ifndef MBEDTLS_RSA_C
#define MBEDTLS_RSA_C
#endif /* ! MBEDTLS_RSA_C */

#ifndef MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_CRT_PARSE_C
#endif /* ! MBEDTLS_X509_CRT_PARSE_C */
#endif /* MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED */

#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED)
#ifndef MBEDTLS_CAN_ECDH
#define MBEDTLS_CAN_ECDH
#endif /* ! MBEDTLS_CAN_ECDH */
#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED */

#endif /* CONFIG_MBEDTLS_LIBCOAP_H */
