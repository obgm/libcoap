/* uri.h -- helper functions for URI treatment
 *
 * (c) 2010 Olaf Bergmann <bergmann@tzi.org>
 */

#ifndef _COAP_URI_H_
#define _COAP_URI_H_

typedef struct {
  char *scheme;	/* URI scheme */
  char *na;	/* network authority */
  char *path;  	/* path */
} coap_uri_t;

/**
 * Splits given URI into pieces and fills the specified uri object accordingly.
 * URI parts that are not available will be set to NULL in uri. The function 
 * returns -1 on error, 0 on success. Note that the passed str will be altered.
 */
int coap_split_uri( char *str, coap_uri_t *uri);

#endif /* _COAP_URI_H_ */
