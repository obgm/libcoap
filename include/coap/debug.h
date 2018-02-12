/*
 * debug.h -- debug utilities
 *
 * Copyright (C) 2010-2011,2014 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#ifndef _COAP_DEBUG_H_
#define _COAP_DEBUG_H_

#ifndef COAP_DEBUG_FD
#define COAP_DEBUG_FD stdout
#endif

#ifndef COAP_ERR_FD
#define COAP_ERR_FD stderr
#endif

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
typedef short coap_log_t;
#else
/** Pre-defined log levels akin to what is used in \b syslog. */
typedef enum {
  LOG_EMERG=0,
  LOG_ALERT,
  LOG_CRIT,
  LOG_ERR,
  LOG_WARNING,
  LOG_NOTICE,
  LOG_INFO,
  LOG_DEBUG
} coap_log_t;
#endif

/** Returns the current log level. */
coap_log_t coap_get_log_level(void);

/** Sets the log level to the specified value. */
void coap_set_log_level(coap_log_t level);

typedef void (*coap_log_handler_t) (coap_log_t level, const char *message);

/** Add a custom log callback, use NULL to reset default handler */
void coap_set_log_handler(coap_log_handler_t handler);

/** Returns a zero-terminated string with the name of this library. */
const char *coap_package_name(void);

/** Returns a zero-terminated string with the library version. */
const char *coap_package_version(void);

/**
 * Writes the given text to @c COAP_ERR_FD (for @p level <= @c LOG_CRIT) or @c
 * COAP_DEBUG_FD (for @p level >= @c LOG_WARNING). The text is output only when
 * @p level is below or equal to the log level that set by coap_set_log_level().
 */
#if (defined(__GNUC__))
void coap_log_impl(coap_log_t level,
              const char *format, ...) __attribute__ ((format(printf, 2, 3)));
#else
void coap_log_impl(coap_log_t level, const char *format, ...);
#endif

#ifndef coap_log
#define coap_log(level, ...) do { if ((level)<=coap_get_log_level()) coap_log_impl((level), __VA_ARGS__); } while(0)
#endif

/* A set of convenience macros for common log levels. */
#define info(...) coap_log(LOG_INFO, __VA_ARGS__)
#define warn(...) coap_log(LOG_WARNING, __VA_ARGS__)
#define debug(...) coap_log(LOG_DEBUG, __VA_ARGS__)

#include "pdu.h"
void coap_show_pdu(const coap_pdu_t *);

struct coap_address_t;
size_t coap_print_addr(const struct coap_address_t *, unsigned char *, size_t);

int coap_debug_set_packet_loss(const char *loss_level);
int coap_debug_send_packet(void);

#endif /* _COAP_DEBUG_H_ */
