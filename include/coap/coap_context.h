#ifndef _COAP_CONTEXT_H_
#define _COAP_CONTEXT_H_

#include <stdlib.h>
#include <string.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include "pdu.h"
#include "coap_time.h"
#include "coap_timer.h"

typedef struct coap_queue_t { // TODO create coap_queue.h
  struct coap_queue_t *next;
  coap_tick_t t;                /**< when to send PDU for the next time */
  unsigned char retransmit_cnt; /**< retransmission counter, will be removed
                                 *    when zero */
  unsigned int timeout;         /**< the randomized timeout value */
  coap_endpoint_t local_if;     /**< the local address interface */
  coap_address_t remote;        /**< remote address */
  coap_tid_t id;                /**< unique transaction id */
  coap_pdu_t *pdu;              /**< the CoAP PDU to send */
} coap_queue_t;

/** Message handler that is used as call-back in coap_context_t */
typedef void (*coap_response_handler_t)(struct coap_context_t  *,
                                        const coap_endpoint_t *local_interface,
                                        const coap_address_t *remote,
                                        coap_pdu_t *sent,
                                        coap_pdu_t *received,
                                        const coap_tid_t id);

/** The CoAP stack's global state is stored in a coap_context_t object */
typedef struct coap_context_t {
  coap_opt_filter_t known_options;
  struct coap_resource_t *resources; /**< hash table or list of known resources */

#ifndef WITHOUT_ASYNC
  /**
   * list of asynchronous transactions */
  struct coap_async_state_t *async_state;
#endif /* WITHOUT_ASYNC */

  /**
   * The time stamp in the first element of the sendqeue is relative
   * to sendqueue_basetime. */
  coap_tick_t sendqueue_basetime;
  coap_queue_t *sendqueue;
  coap_endpoint_t *endpoint;      /**< the endpoint used for listening  */

#ifdef WITH_CONTIKI
  struct uip_udp_conn *conn;      /**< uIP connection object */
#endif /* WITH_CONTIKI */

  coap_timer_t *retransmit_timer; /**< fires when the next packet must be sent */
  coap_timer_t *notify_timer;     /**< used to check resources periodically */

  /**
   * The last message id that was used is stored in this field. The initial
   * value is set by coap_new_context() and is usually a random value. A new
   * message id can be created with coap_new_message_id().
   */
  unsigned short message_id;

  /**
   * The next value to be used for Observe. This field is global for all
   * resources and will be updated when notifications are created.
   */
  unsigned int observe;

  coap_response_handler_t response_handler;

  ssize_t (*network_send)(struct coap_context_t *context,
                          const coap_endpoint_t *local_interface,
                          const coap_address_t *dst,
                          unsigned char *data, size_t datalen);

  ssize_t (*network_read)(coap_endpoint_t *ep, coap_packet_t **packet);

} coap_context_t;

/**
 * Creates a new coap_context_t object that will hold the CoAP stack status.
 */
coap_context_t *coap_new_context(const coap_address_t *listen_addr);

/**
 * CoAP stack context must be released with coap_free_context(). This function
 * clears all entries from the receive queue and send queue and deletes the
 * resources that have been registered with @p context, and frees the attached
 * endpoints.
 */
void coap_free_context(coap_context_t *context);

#endif /* _COAP_CONTEXT_H_ */
