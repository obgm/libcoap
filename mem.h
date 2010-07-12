/* mem.h -- CoAP memory handling
 *          Currently, this is just a dummy for malloc/free
 *
 * (c) 2010 Olaf Bergmann <bergmann@tzi.org>
 */

#ifndef _COAP_MEM_H_
#define _COAP_MEM_H_

#include <stdlib.h>

#define coap_malloc(size) malloc(size)
#define coap_free(size) free(size)

#endif /* _COAP_MEM_H_ */
