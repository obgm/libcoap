/* net.h -- CoAP network interface
 *
 * Copyright (C) 2010,2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

#ifndef _COAP_NET_H_
#define _COAP_NET_H_

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>

#include "option.h"
#include "pdu.h"

typedef unsigned int coap_tick_t; 

/** multi-purpose address abstraction */
typedef struct {
  socklen_t size;		/**< size of addr */
  union {
    struct sockaddr     sa;
    struct sockaddr_in  sin;
    struct sockaddr_in6 sin6;
  } addr;
} coap_address_t;

struct coap_listnode {
  struct coap_listnode *next;

  coap_tick_t t;	        /* when to send PDU for the next time */
  unsigned char retransmit_cnt;	/* retransmission counter, will be removed when zero */
  unsigned int timeout;		/* the randomized timeout value */

  coap_address_t remote;	/**< remote address */

  coap_pdu_t *pdu;		/**< the CoAP PDU to send */
};

typedef struct coap_listnode coap_queue_t;

/* adds node to given queue, ordered by specified order function */
int coap_insert_node(coap_queue_t **queue, coap_queue_t *node,
		     int (*order)(coap_queue_t *, coap_queue_t *node) );

/* destroys specified node */
int coap_delete_node(coap_queue_t *node);

/* removes all items from given queue and frees the allocated storage */
void coap_delete_all(coap_queue_t *queue);

/* creates a new node suitable for adding to the CoAP sendqueue */
coap_queue_t *coap_new_node();

struct coap_resource_t;

/* The CoAP stack's global state is stored in a coap_context_t object */
typedef struct {
  coap_opt_filter_t known_options;
  struct coap_resource_t *resources; /**< hash table of known resources */
  coap_list_t *subscriptions; /* FIXME: make these hash tables */
  coap_queue_t *sendqueue, *recvqueue; /* FIXME make these coap_list_t */
  int sockfd;			/* send/receive socket */

  void ( *msg_handler )( void *, coap_queue_t *, void *);
} coap_context_t;

typedef void (*coap_message_handler_t)( coap_context_t  *, coap_queue_t *, void *);

/**
 * Registers a new message handler that is called whenever a new PDU
 * was received. Note that the transactions are handled on the lower
 * layer previously to stop retransmissions, e.g. */
void coap_register_message_handler( coap_context_t *context, coap_message_handler_t handler);

/**
 * Registers a new handler function that is called when a RST message
 * has been received.
 */
void coap_register_error_handler( coap_context_t *context, coap_message_handler_t handler);

/** 
 * Registers the option type @p type with the given context object @p
 * ctx.
 * 
 * @param ctx  The context to use.
 * @param type The option type to register.
 */
inline static void 
coap_register_option(coap_context_t *ctx, unsigned char type) {
  coap_option_setb(ctx->known_options, type);
}

/* Returns the next pdu to send without removing from sendqeue. */
coap_queue_t *coap_peek_next( coap_context_t *context );

/* Returns the next pdu to send and removes it from the sendqeue. */
coap_queue_t *coap_pop_next( coap_context_t *context );

/* Creates a new coap_context_t object that will hold the CoAP stack status.  */
coap_context_t *coap_new_context(const struct sockaddr *listen_addr, size_t addr_size);

/* CoAP stack context must be released with coap_free_context() */
void coap_free_context( coap_context_t *context );


/**
 * Sends a confirmed CoAP message to given destination. The memory
 * that is allocated by pdu will be released by
 * coap_send_confirmed(). The caller must not make any assumption on
 * the lifetime of pdu.
 *
 * @param context The CoAP context to use.
 * @param dst     The address to send to.
 * @param addrlen The actual length of @p dst
 * @param pdu     The CoAP PDU to send.
 * @return The message id of the sent message or @c COAP_INVALID_TID on error.
 */
coap_tid_t coap_send_confirmed( coap_context_t *context, 
				const struct sockaddr *dst, 
				socklen_t addrlen,
				coap_pdu_t *pdu );

/**
 * Sends a non-confirmed CoAP message to given destination. The memory
 * that is allocated by pdu will be released by coap_send(). The
 * caller must not make any assumption on the lifetime of pdu.
 *
 * @param context The CoAP context to use.
 * @param dst     The address to send to.
 * @param addrlen The actual length of @p dst
 * @param pdu     The CoAP PDU to send.
 * @return The message id of the sent message or @c COAP_INVALID_TID on error.
 */
coap_tid_t coap_send( coap_context_t *context, 
		      const struct sockaddr *dst, 
		      socklen_t addrlen,
		      coap_pdu_t *pdu );

/** Handles retransmissions of confirmable messages */
coap_tid_t coap_retransmit( coap_context_t *context, coap_queue_t *node );

/**
 * Reads data from the network and tries to parse as CoAP PDU. On success, 0 is returned
 * and a new node with the parsed PDU is added to the receive queue in the specified context
 * object.
 */
int coap_read( coap_context_t *context );

/** Removes transaction with specified id from given queue. Returns 0 if not found, 1 otherwise. */
int coap_remove_transaction( coap_queue_t **queue, coap_tid_t id );

/**
 * Retrieves transaction from queue.
 * @queue The transaction queue to be searched
 * @id Unique key of the transaction to find.
 * @return A pointer to the transaction object or NULL if not found
 */
coap_queue_t *coap_find_transaction(coap_queue_t *queue, coap_tid_t id);

/** Dispatches the PDUs from the receive queue in given context. */
void coap_dispatch( coap_context_t *context );

/** Returns 1 if there are no messages to send or to dispatch in the context's queues. */
int coap_can_exit( coap_context_t *context );

#define COAP_TICKS_PER_SECOND 1024

/**
 * Returns the current value of an internal tick counter. The counter
 * counts \c COAP_TICKS_PER_SECOND ticks every second. 
 */
void coap_ticks(coap_tick_t *);

/** 
 * Verifies that @p pdu contains no unknown critical options. Options
 * must be registered at @p ctx, using the function
 * coap_register_option(). A basic set of options is registered
 * automatically by coap_new_context(). This function returns @c 1 if
 * @p pdu is ok, @c 0 otherwise. The given filter object @p unknown
 * will be updated with the unknown options. As only @c COAP_MAX_OPT
 * options can be signalled this way, remaining options must be
 * examined manually. 
 *
 * @code
  coap_opt_filter_t f = COAP_OPT_NONE;
  coap_opt_iterator_t opt_iter;
  
  if (coap_option_check_critical(ctx, pdu, f) == 0) {
    coap_option_iterator_init(pdu, &opt_iter, f);

    while (coap_option_next(&opt_iter)) {
      if (opt_iter.type & 0x01) {
	... handle unknown critical option in opt_iter ...
      }
    }
  }
 * @endcode 
 *
 * @param ctx      The context where all known options are registered.
 * @param pdu      The PDU to check.
 * @param unknown  The output filter that will be updated to indicate the
 *                 unknown critical options found in @p pdu.
 * 
 * @return @c 1 if everything was ok, @c 0 otherwise.
 */
int coap_option_check_critical(coap_context_t *ctx, 
			       coap_pdu_t *pdu,
			       coap_opt_filter_t unknown);

#endif /* _COAP_NET_H_ */
