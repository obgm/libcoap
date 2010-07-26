/* debug.c -- debug utilities
 *
 * (c) 2010 Olaf Bergmann <bergmann@tzi.org>
 */

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

#include "debug.h"

void debug(char *format, ...) {
  static char timebuf[32];
  struct tm *tmp;
  time_t now;
  va_list ap;

  time(&now);
  tmp = localtime(&now);

  if ( strftime(timebuf,sizeof(timebuf), "%b %d %H:%M:%S", tmp) )
    fprintf(stderr,"%s ", timebuf);
  
  va_start(ap, format);
  vfprintf(stderr,format, ap);
  va_end(ap);
}
