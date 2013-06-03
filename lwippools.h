/** Memory pool definitions for the libcoap when used with lwIP (which has its
 * own mechanism for quickly allocating chunks of data with known sizes). Has
 * to be findable by lwIP (ie. an #include <lwippools.h> must either directly
 * include this or include something more generic which includes this), and
 * MEMP_USE_CUSTOM_POOLS has to be set in lwipopts.h. */

#include <net.h>
#include <subscribe.h>

#ifndef MEMP_NUM_COAPNODE
#define MEMP_NUM_COAPNODE 4
#endif

#ifndef MEMP_NUM_COAP_SUBSCRIPTION
#define MEMP_NUM_COAP_SUBSCRIPTION 4
#endif

LWIP_MEMPOOL(COAP_NODE, MEMP_NUM_COAPNODE, sizeof(coap_queue_t), "COAP_NODE")
LWIP_MEMPOOL(COAP_subscription, MEMP_NUM_COAP_SUBSCRIPTION, sizeof(coap_subscription_t), "COAP_subscription")
