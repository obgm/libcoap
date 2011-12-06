#ifndef _CONFIG_H_
#define _CONFIG_H_

#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"

#define WITH_CONTIKI 1

#ifndef BYTE_ORDER
# ifdef UIP_CONF_BYTE_ORDER
#  define BYTE_ORDER UIP_CONF_BYTE_ORDER
# else
#  error "UIP_CONF_BYTE_ORDER not defined"
# endif /* UIP_CONF_BYTE_ORDER */
#endif /* BYTE_ORDER */

#endif /* _CONFIG_H_ */

