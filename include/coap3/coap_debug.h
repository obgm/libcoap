/*
 * coap_debug.h -- debug utilities
 *
 * Copyright (C) 2010-2011,2014-2022 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_debug.h
 * @brief CoAP Logging support
 */

#ifndef COAP_DEBUG_H_
#define COAP_DEBUG_H_

/**
 * @ingroup application_api
 * @defgroup logging Logging Support
 * API for logging support
 * @{
 */

#ifndef COAP_DEBUG_FD
/**
 * Used for output for @c COAP_LOG_OSCORE to @c COAP_LOG_ERR.
 */
#define COAP_DEBUG_FD stdout
#endif

#ifndef COAP_ERR_FD
/**
 * Used for output for @c COAP_LOG_CRIT to @c COAP_LOG_EMERG.
 */
#define COAP_ERR_FD stderr
#endif

#define coap_log_emerg(...) coap_log(COAP_LOG_EMERG, __VA_ARGS__)
#define coap_log_alert(...) coap_log(COAP_LOG_ALERT, __VA_ARGS__)
#define coap_log_crit(...) coap_log(COAP_LOG_CRIT, __VA_ARGS__)
#define coap_log_err(...) coap_log(COAP_LOG_ERR, __VA_ARGS__)
#define coap_log_warn(...) coap_log(COAP_LOG_WARN, __VA_ARGS__)
#define coap_log_info(...) coap_log(COAP_LOG_INFO, __VA_ARGS__)
#define coap_log_notice(...) coap_log(COAP_LOG_NOTICE, __VA_ARGS__)
#define coap_log_debug(...) coap_log(COAP_LOG_DEBUG, __VA_ARGS__)
#define coap_log_oscore(...) coap_log(COAP_LOG_OSCORE, __VA_ARGS__)

/**
 * Logging type.  These should be used where possible in the code instead
 * of the syslog definitions, or alternatively use the coap_log_*() functions
 * to reduce line length.
 */
typedef enum {
  COAP_LOG_EMERG = 0,
  COAP_LOG_ALERT,
  COAP_LOG_CRIT,
  COAP_LOG_ERR,
  COAP_LOG_WARN,
  COAP_LOG_NOTICE,
  COAP_LOG_INFO,
  COAP_LOG_DEBUG,
  COAP_LOG_OSCORE,
  COAP_LOG_DTLS_BASE,
#define COAP_LOG_CIPHERS COAP_LOG_DTLS_BASE /* For backward compatability */
} coap_log_t;

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#else
#if defined(RIOT_VERSION)
/* RIOT defines a subset of the syslog levels in log.h with different
 * numeric values. The remaining levels are defined here. Note that
 * output granularity differs from what would be expected when
 * adhering to the syslog levels.
 */
#include <log.h>
#endif /* RIOT_VERSION */
#endif /* HAVE_SYSLOG_H */

#ifndef LOG_EMERG
# define LOG_EMERG  COAP_LOG_EMERG
#endif
#ifndef LOG_ALERT
# define LOG_ALERT  COAP_LOG_ALERT
#endif
#ifndef LOG_CRIT
# define LOG_CRIT   COAP_LOG_CRIT
#endif
#ifndef LOG_ERR
# define LOG_ERR    COAP_LOG_ERR
#endif
#ifndef LOG_WARNING
# define LOG_WARNING COAP_LOG_WARN
#endif
#ifndef LOG_NOTICE
# define LOG_NOTICE COAP_LOG_NOTICE
#endif
#ifndef LOG_INFO
# define LOG_INFO   COAP_LOG_INFO
#endif
#ifndef LOG_DEBUG
# define LOG_DEBUG  COAP_LOG_DEBUG
#endif

/**
 * Get the current logging level.
 *
 * @return One of the COAP_LOG_* values.
 */
coap_log_t coap_get_log_level(void);

/**
 * Sets the log level to the specified value.
 *
 * @param level One of the COAP_LOG_* values.
 */
void coap_set_log_level(coap_log_t level);

/**
 * Sets the (D)TLS logging level to the specified @p level.
 *
 * @param level One of the COAP_LOG_* values.
 */
void coap_dtls_set_log_level(coap_log_t level);

/**
 * Get the current (D)TLS logging.
 *
 * @return One of the COAP_LOG_* values.
 */
coap_log_t coap_dtls_get_log_level(void);

/**
 * Logging callback handler definition.
 *
 * @param level One of the COAP_LOG_* values, or if used for (D)TLS logging,
 *              COAP_LOG_DTLS_BASE + one of the COAP_LOG_* values.
 * @param message Zero-terminated string message to log.
 */
typedef void (*coap_log_handler_t) (coap_log_t level, const char *message);

/**
 * Add a custom log callback handler.
 *
 * @param handler The logging handler to use or @p NULL to use default handler.
 *                 This handler will be used for both CoAP and (D)TLS logging.
 */
void coap_set_log_handler(coap_log_handler_t handler);

/**
 * Get the library package name.
 *
 * @return Zero-terminated string with the name of this library.
 */
const char *coap_package_name(void);

/**
 * Get the library package version.
 *
 * @return Zero-terminated string with the library version.
 */
const char *coap_package_version(void);

/**
 * Get the library package build.
 *
 * @return Zero-terminated string with the library build.
 */
const char *coap_package_build(void);

/**
 * Writes the given text to @c COAP_ERR_FD (for @p level <= @c COAP_LOG_CRIT) or
 * @c COAP_DEBUG_FD (for @p level >= @c COAP_LOG_ERR). The text is output only
 * when @p level is below or equal to the log level that set by
 * coap_set_log_level().
 *
 * Internal function.
 *
 * @param level One of the COAP_LOG_* values.
 & @param format The format string to use.
 */
#if (defined(__GNUC__))
void coap_log_impl(coap_log_t level,
              const char *format, ...) __attribute__ ((format(printf, 2, 3)));
#else
void coap_log_impl(coap_log_t level, const char *format, ...);
#endif

#ifndef coap_log
/**
 * Logging function.
 * Writes the given text to @c COAP_ERR_FD (for @p level <= @c COAP_LOG_CRIT) or @c
 * COAP_DEBUG_FD (for @p level >= @c COAP_LOG_ERR). The text is output only when
 * @p level is below or equal to the log level that set by coap_set_log_level().
 *
 * @param level One of the COAP_LOG_* values.
 */
#define coap_log(level, ...) do { \
  if ((int)((level))<=(int)coap_get_log_level()) \
     coap_log_impl((level), __VA_ARGS__); \
} while(0)
#endif

#ifndef coap_dtls_log
/**
 * Logging function.
 * Writes the given text to @c COAP_ERR_FD (for @p level <= @c COAP_LOG_CRIT) or @c
 * COAP_DEBUG_FD (for @p level >= @c COAP_LOG_ERR). The text is output only when
 * @p level is below or equal to the log level that set by coap_dtls_set_log_level().
 *
 * @param level One of the COAP_LOG_* values.
 */
#define coap_dtls_log(level, ...) do { \
  if ((int)((level))<=(int)coap_dtls_get_log_level()) \
     coap_log_impl((level)+COAP_LOG_DTLS_BASE, __VA_ARGS__); \
} while(0)
#endif

#include "pdu.h"

/**
 * Defines the output mode for the coap_show_pdu() function.
 *
 * @param use_fprintf @p 1 if the output is to use fprintf() (the default)
 *                    @p 0 if the output is to use coap_log().
 */
void coap_set_show_pdu_output(int use_fprintf);

/**
 * Display the contents of the specified @p pdu.
 * Note: The output method of coap_show_pdu() is dependent on the setting of
 * coap_set_show_pdu_output().
 *
 * @param level The required minimum logging level.
 * @param pdu The PDU to decode.
 */
void coap_show_pdu(coap_log_t level, const coap_pdu_t *pdu);

/**
 * Display the current (D)TLS library linked with and built for version.
 *
 * @param level The required minimum logging level.
 */
void coap_show_tls_version(coap_log_t level);

/**
 * Build a string containing the current (D)TLS library linked with and
 * built for version.
 *
 * @param buffer The buffer to put the string into.
 * @param bufsize The size of the buffer to put the string into.
 *
 * @return A pointer to the provided buffer.
 */
char *coap_string_tls_version(char *buffer, size_t bufsize);

/**
 * Build a string containing the current (D)TLS library support
 *
 * @param buffer The buffer to put the string into.
 * @param bufsize The size of the buffer to put the string into.
 *
 * @return A pointer to the provided buffer.
 */
char *coap_string_tls_support(char *buffer, size_t bufsize);

/**
 * Print the address into the defined buffer.
 *
 * Internal Function.
 *
 * @param address The address to print.
 * @param buffer The buffer to print into.
 * @param size The size of the buffer to print into.
 *
 * @return The amount written into the buffer.
 */
size_t coap_print_addr(const coap_address_t *address,
                       unsigned char *buffer, size_t size);

/** @} */

/**
 * Set the packet loss level for testing.  This can be in one of two forms.
 *
 * Percentage : 0% to 100%.  Use the specified probability.
 * 0% is send all packets, 100% is drop all packets.
 *
 * List: A comma separated list of numbers or number ranges that are the
 * packets to drop.
 *
 * @param loss_level The defined loss level (percentage or list).
 *
 * @return @c 1 If loss level set, @c 0 if there is an error.
 */
int coap_debug_set_packet_loss(const char *loss_level);

/**
 * Check to see whether a packet should be sent or not.
 *
 * Internal function
 *
 * @return @c 1 if packet is to be sent, @c 0 if packet is to be dropped.
 */
int coap_debug_send_packet(void);


#endif /* COAP_DEBUG_H_ */
