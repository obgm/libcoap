/*
 * coap_net_internal.h -- CoAP context internal information
 * exposed to application programming
 *
 * Copyright (C) 2010-2024 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_net_internal.h
 * @brief CoAP context internal information
 */

#ifndef COAP_NET_INTERNAL_H_
#define COAP_NET_INTERNAL_H_

#include "coap_internal.h"
#include "coap_subscribe.h"
#include "coap_threadsafe_internal.h"

/**
 * @ingroup internal_api
 * @defgroup context_internal Context Handling
 * Internal API for Context Handling
 * @{
 */

/**
 * Queue entry
 */
struct coap_queue_t {
  struct coap_queue_t *next;
  coap_tick_t t;                /**< when to send PDU for the next time */
  unsigned char retransmit_cnt; /**< retransmission counter, will be removed
                                 *    when zero */
  uint8_t is_mcast;             /**< Set if this is a queued mcast response */
  unsigned int timeout;         /**< the randomized timeout value */
  coap_session_t *session;      /**< the CoAP session */
  coap_mid_t id;                /**< CoAP message id */
  coap_pdu_t *pdu;              /**< the CoAP PDU to send */
};

/**
 * The CoAP stack's global state is stored in a coap_context_t object.
 */
struct coap_context_t {
  coap_opt_filter_t known_options;
#if COAP_SERVER_SUPPORT
  coap_resource_t *resources; /**< hash table or list of known
                                   resources */
  coap_resource_t *unknown_resource; /**< can be used for handling
                                          unknown resources */
  coap_resource_t *proxy_uri_resource; /**< can be used for handling
                                            proxy URI resources */
  coap_resource_release_userdata_handler_t release_userdata;
  /**< function to  release user_data
       when resource is deleted */
#endif /* COAP_SERVER_SUPPORT */

#if COAP_ASYNC_SUPPORT
  /**
   * list of asynchronous message ids */
  coap_async_t *async_state;
#endif /* COAP_ASYNC_SUPPORT */

  /**
   * The time stamp in the first element of the sendqeue is relative
   * to sendqueue_basetime. */
  coap_tick_t sendqueue_basetime;
  coap_queue_t *sendqueue;
#if COAP_SERVER_SUPPORT
  coap_endpoint_t *endpoint;      /**< the endpoints used for listening  */
#endif /* COAP_SERVER_SUPPORT */
#if COAP_CLIENT_SUPPORT
  coap_session_t *sessions;       /**< client sessions */
#endif /* COAP_CLIENT_SUPPORT */

#ifdef WITH_CONTIKI
  struct uip_udp_conn *conn;      /**< uIP connection object */
  struct ctimer io_timer;         /**< fires when it's time to call
                                       coap_io_prepare_io */
#endif /* WITH_CONTIKI */

#ifdef WITH_LWIP
  coap_lwip_input_wait_handler_t input_wait; /** Input wait / timeout handler if set */
  void *input_arg;                /** argument to pass it input handler */
  uint8_t timer_configured;       /**< Set to 1 when a retransmission is
                                   *   scheduled using lwIP timers for this
                                   *   context, otherwise 0. */
#endif /* WITH_LWIP */
#ifdef RIOT_VERSION
  thread_t *selecting_thread;
#endif /* RIOT_VERSION */
#if COAP_OSCORE_SUPPORT
  struct oscore_ctx_t *p_osc_ctx; /**< primary oscore context  */
#endif /* COAP_OSCORE_SUPPORT */

#if COAP_CLIENT_SUPPORT
  coap_response_handler_t response_handler; /**< Called when a response is
                                                 received */
#endif /* COAP_CLIENT_SUPPORT */
  coap_nack_handler_t nack_handler; /**< Called when a response issue has
                                         occurred */
  coap_ping_handler_t ping_handler; /**< Called when a CoAP ping is received */
  coap_pong_handler_t pong_handler; /**< Called when a ping response
                                         is received */

#if COAP_SERVER_SUPPORT
  coap_observe_added_t observe_added; /**< Called when there is a new observe
                                           subscription request */
  coap_observe_deleted_t observe_deleted; /**< Called when there is a observe
                                           subscription de-register request */
  void *observe_user_data; /**< App provided data for use in observe_added or
                                observe_deleted */
  uint32_t observe_save_freq; /**< How frequently to update observe value */
  coap_track_observe_value_t track_observe_value; /**< Callback to save observe
                                                       value when updated */
  coap_dyn_resource_added_t dyn_resource_added; /**< Callback to save dynamic
                                                     resource when created */
  coap_resource_deleted_t resource_deleted; /**< Invoked when resource
                                                 is deleted */
#if COAP_WITH_OBSERVE_PERSIST
  coap_bin_const_t *dyn_resource_save_file; /** Where dynamic resource requests
                                                that create resources are
                                                tracked */
  coap_bin_const_t *obs_cnt_save_file; /** Where resource observe counters are
                                            tracked */
  coap_bin_const_t *observe_save_file; /** Where observes are tracked */
  coap_pdu_t *unknown_pdu;        /** PDU used for unknown resource request */
  coap_session_t *unknown_session; /** Session used for unknown resource request */
#endif /* COAP_WITH_OBSERVE_PERSIST */
#endif /* COAP_SERVER_SUPPORT */

  /**
   * Callback function that is used to signal events to the
   * application.  This field is set by coap_set_event_handler().
   */
  coap_event_handler_t handle_event;

  void *dtls_context;

#if COAP_SERVER_SUPPORT
  coap_dtls_spsk_t spsk_setup_data;  /**< Contains the initial PSK server setup
                                          data */
#endif /* COAP_SERVER_SUPPORT */

  unsigned int session_timeout;    /**< Number of seconds of inactivity after
                                        which an unused session will be closed.
                                        0 means use default. */
  unsigned int max_idle_sessions;  /**< Maximum number of simultaneous unused
                                        sessions per endpoint. 0 means no
                                        maximum. */
  unsigned int max_handshake_sessions; /**< Maximum number of simultaneous
                                            negotating sessions per endpoint. 0
                                            means use default. */
  unsigned int ping_timeout;           /**< Minimum inactivity time before
                                            sending a ping message. 0 means
                                            disabled. */
  uint32_t csm_timeout_ms;         /**< Timeout for waiting for a CSM from
                                           the remote side. */
  uint32_t csm_max_message_size;   /**< Value for CSM Max-Message-Size */
  uint64_t etag;                   /**< Next ETag to use */

#if COAP_SERVER_SUPPORT
  coap_cache_entry_t *cache;       /**< CoAP cache-entry cache */
  uint16_t *cache_ignore_options;  /**< CoAP options to ignore when creating a
                                        cache-key */
  size_t cache_ignore_count;       /**< The number of CoAP options to ignore
                                        when creating a cache-key */
#endif /* COAP_SERVER_SUPPORT */
  void *app;                       /**< application-specific data */
  uint32_t max_token_size;         /**< Largest token size supported RFC8974 */
#ifdef COAP_EPOLL_SUPPORT
  int epfd;                        /**< External FD for epoll */
  int eptimerfd;                   /**< Internal FD for timeout */
  coap_tick_t next_timeout;        /**< When the next timeout is to occur */
#else /* ! COAP_EPOLL_SUPPORT */
#if !defined(RIOT_VERSION) && !defined(WITH_CONTIKI)
  fd_set readfds, writefds, exceptfds; /**< Used for select call
                                            in coap_io_process_with_fds_lkd() */
  coap_socket_t *sockets[64];      /**< Track different socket information
                                        in coap_io_process_with_fds_lkd() */
  unsigned int num_sockets;        /**< Number of sockets being tracked */
#endif /* ! RIOT_VERSION && ! WITH_CONTIKI */
#endif /* ! COAP_EPOLL_SUPPORT */
#if COAP_SERVER_SUPPORT
  uint8_t observe_pending;         /**< Observe response pending */
  uint8_t observe_no_clear;        /**< Observe 4.04 not to be sent on deleting
                                        resource */
  uint8_t mcast_per_resource;      /**< Mcast controlled on a per resource
                                        basis */
#endif /* COAP_SERVER_SUPPORT */
#if COAP_PROXY_SUPPORT
  coap_proxy_list_t *proxy_list;   /**< Set of active proxy sessions */
  size_t proxy_list_count;         /**< Number of active proxy sessions */
#endif /* COAP_PROXY_SUPPORT */
#if COAP_CLIENT_SUPPORT
  uint8_t testing_cids;            /**< Change client's source port every testing_cids */
#endif /* COAP_CLIENT_SUPPORT */
  uint32_t block_mode;             /**< Zero or more COAP_BLOCK_ or'd options */
};

/**
 * Adds @p node to given @p queue, ordered by variable t in @p node.
 *
 * @param queue Queue to add to.
 * @param node Node entry to add to Queue.
 *
 * @return @c 1 added to queue, @c 0 failure.
 */
int coap_insert_node(coap_queue_t **queue, coap_queue_t *node);

/**
 * Destroys specified @p node.
 *
 * Note: Not a part of the Public API.
 *
 * @param node Node entry to remove.
 *
 * @return @c 1 node deleted from queue, @c 0 failure.
 */
COAP_API int coap_delete_node(coap_queue_t *node);

/**
 * Destroys specified @p node.
 *
 * Note: Needs to be called in a locked state if node->session is set.
 *
 * @param node Node entry to remove.
 *
 * @return @c 1 node deleted from queue, @c 0 failure.
 */
int coap_delete_node_lkd(coap_queue_t *node);

/**
 * Removes all items from given @p queue and frees the allocated storage.
 *
 * Internal function.
 *
 * @param queue The queue to delete.
 */
void coap_delete_all(coap_queue_t *queue);

/**
 * Creates a new node suitable for adding to the CoAP sendqueue.
 *
 * @return New node entry, or @c NULL if failure.
 */
coap_queue_t *coap_new_node(void);

/**
 * Set sendqueue_basetime in the given context object @p ctx to @p now. This
 * function returns the number of elements in the queue head that have timed
 * out.
 */
unsigned int coap_adjust_basetime(coap_context_t *ctx, coap_tick_t now);

/**
 * Returns the next pdu to send without removing from sendqeue.
 */
coap_queue_t *coap_peek_next(coap_context_t *context);

/**
 * Returns the next pdu to send and removes it from the sendqeue.
 */
coap_queue_t *coap_pop_next(coap_context_t *context);

/**
 * Handles retransmissions of confirmable messages
 *
 * @param context      The CoAP context.
 * @param node         The node to retransmit.
 *
 * @return             The message id of the sent message or @c
 *                     COAP_INVALID_MID on error.
 */
coap_mid_t coap_retransmit(coap_context_t *context, coap_queue_t *node);

/**
 * Parses and interprets a CoAP datagram with context @p ctx. This function
 * returns @c 0 if the datagram was handled, or a value less than zero on
 * error.
 *
 * @param ctx    The current CoAP context.
 * @param session The current CoAP session.
 * @param data The received packet'd data.
 * @param data_len The received packet'd data length.
 *
 * @return       @c 0 if message was handled successfully, or less than zero on
 *               error.
 */
int coap_handle_dgram(coap_context_t *ctx, coap_session_t *session, uint8_t *data, size_t data_len);

/**
 * This function removes the element with given @p id from the list given list.
 * If @p id was found, @p node is updated to point to the removed element. Note
 * that the storage allocated by @p node is @b not released. The caller must do
 * this manually using coap_delete_node(). This function returns @c 1 if the
 * element with id @p id was found, @c 0 otherwise. For a return value of @c 0,
 * the contents of @p node is undefined.
 *
 * @param queue The queue to search for @p id.
 * @param session The session to look for.
 * @param id    The message id to look for.
 * @param node  If found, @p node is updated to point to the removed node. You
 *              must release the storage pointed to by @p node manually.
 *
 * @return      @c 1 if @p id was found, @c 0 otherwise.
 */
int coap_remove_from_queue(coap_queue_t **queue,
                           coap_session_t *session,
                           coap_mid_t id,
                           coap_queue_t **node);

coap_mid_t coap_wait_ack(coap_context_t *context, coap_session_t *session,
                         coap_queue_t *node);

/**
 * Cancels all outstanding messages for session @p session that have the specified
 * token.
 *
 * @param context      The context in use.
 * @param session      Session of the messages to remove.
 * @param token        Message token.
 */
void coap_cancel_all_messages(coap_context_t *context,
                              coap_session_t *session,
                              coap_bin_const_t *token);

/**
* Cancels all outstanding messages for session @p session.
*
* @param context      The context in use.
* @param session      Session of the messages to remove.
* @param reason       The reasion for the session cancellation
*/
void coap_cancel_session_messages(coap_context_t *context,
                                  coap_session_t *session,
                                  coap_nack_reason_t reason);

/**
 * Returns a new message id and updates @p session->tx_mid accordingly. The
 * message id is returned in network byte order to make it easier to read in
 * tracing tools.
 *
 * Note: This function must be called in the locked state.
 *
 * @param session The current coap_session_t object.
 *
 * @return        Incremented message id in network byte order.
 */
uint16_t coap_new_message_id_lkd(coap_session_t *session);

/**
 * Dispatches the PDUs from the receive queue in given context.
 */
void coap_dispatch(coap_context_t *context, coap_session_t *session,
                   coap_pdu_t *pdu);

/**
 * Verifies that @p pdu contains no unknown critical options. Options must be
 * registered at @p ctx, using the function coap_register_option(). A basic set
 * of options is registered automatically by coap_new_context(). This function
 * returns @c 1 if @p pdu is ok, @c 0 otherwise. The given filter object @p
 * unknown will be updated with the unknown options. As only @c COAP_MAX_OPT
 * options can be signalled this way, remaining options must be examined
 * manually.
 *
 * @code
  coap_opt_filter_t f = COAP_OPT_NONE;
  coap_opt_iterator_t opt_iter;

  if (coap_option_check_critical(session, pdu, f) == 0) {
    coap_option_iterator_init(pdu, &opt_iter, f);

    while (coap_option_next(&opt_iter)) {
      if (opt_iter.type & 0x01) {
        ... handle unknown critical option in opt_iter ...
      }
    }
  }
   @endcode
 *
 * @param session  The current session.
 * @param pdu      The PDU to check.
 * @param unknown  The output filter that will be updated to indicate the
 *                 unknown critical options found in @p pdu.
 *
 * @return         @c 1 if everything was ok, @c 0 otherwise.
 */
int coap_option_check_critical(coap_session_t *session,
                               coap_pdu_t *pdu,
                               coap_opt_filter_t *unknown);

/**
 * Creates a new response for given @p request with the contents of @c
 * .well-known/core. The result is NULL on error or a newly allocated PDU that
 * must be either sent with coap_sent() or released by coap_delete_pdu().
 *
 * @param context The current coap context to use.
 * @param session The CoAP session.
 * @param request The request for @c .well-known/core .
 *
 * @return        A new 2.05 response for @c .well-known/core or NULL on error.
 */
coap_pdu_t *coap_wellknown_response(coap_context_t *context,
                                    coap_session_t *session,
                                    coap_pdu_t *request);

/**
 * Calculates the initial timeout based on the session CoAP transmission
 * parameters 'ack_timeout', 'ack_random_factor', and COAP_TICKS_PER_SECOND.
 * The calculation requires 'ack_timeout' and 'ack_random_factor' to be in
 * Qx.FRAC_BITS fixed point notation, whereas the passed parameter @p r
 * is interpreted as the fractional part of a Q0.MAX_BITS random value.
 *
 * @param session session timeout is associated with
 * @param r  random value as fractional part of a Q0.MAX_BITS fixed point
 *           value
 * @return   COAP_TICKS_PER_SECOND * 'ack_timeout' *
 *           (1 + ('ack_random_factor' - 1) * r)
 */
unsigned int coap_calc_timeout(coap_session_t *session, unsigned char r);

/**
 * Check whether the pdu contains a valid code class
 *
 * @param session The CoAP session.
 * @param pdu     The PDU to check.
 *
 * @return        @c 1 valid, @c 0 invalid.
 */
int coap_check_code_class(coap_session_t *session, coap_pdu_t *pdu);

/**
 * Sends a CoAP message to given peer. The memory that is
 * allocated for the pdu will be released by coap_send_internal().
 * The caller must not use the pdu after calling coap_send_internal().
 *
 * If the response body is split into multiple payloads using blocks, libcoap
 * will handle asking for the subsequent blocks and any necessary recovery
 * needed.
 *
 * @param session   The CoAP session.
 * @param pdu       The CoAP PDU to send.
 *
 * @return          The message id of the sent message or @c
 *                  COAP_INVALID_MID on error.
 */
coap_mid_t coap_send_internal(coap_session_t *session, coap_pdu_t *pdu);

/**
 * Delay the sending of the first client request until some other negotiation
 * has completed.
 *
 * @param session   The CoAP session.
 *
 * @return          @c 1 if everything was ok, @c 0 otherwise.
 */
int coap_client_delay_first(coap_session_t *session);

/**
 * CoAP stack context must be released with coap_free_context_lkd(). This
 * function  clears all entries from the receive queue and send queue and deletes the
 * resources that have been registered with @p context, and frees the attached
 * endpoints.
 *
 * Note: This function must be called in the locked state.
 *
 * @param context The current coap_context_t object to free off.
 */
void coap_free_context_lkd(coap_context_t *context);

/**
 * Invokes the event handler of @p context for the given @p event and
 * @p data.
 *
 * Note: This function must be called in the locked state.
 *
 * @param context The CoAP context whose event handler is to be called.
 * @param event   The event to deliver.
 * @param session The session related to @p event.
 * @return The result from the associated event handler or 0 if none was
 * registered.
 */
int coap_handle_event_lkd(coap_context_t *context,
                          coap_event_t event,
                          coap_session_t *session);

/**
 * Returns 1 if there are no messages to send or to dispatch in the context's
 * queues.
 *
 * Note: This function must be called in the locked state.
 *
 * @param context The CoAP context to check.
 *
 * @return @c 0 if there are still pending transmits else @c 1 if nothing
 *         queued for transmission.  Note that @c 0 does not mean there has
 *         been a response to a transmitted request.
 */
int coap_can_exit_lkd(coap_context_t *context);

/**
 * Function interface for joining a multicast group for listening for the
 * currently defined endpoints that are UDP.
 *
 * Note: This function must be called in the locked state.
 *
 * @param ctx       The current context.
 * @param groupname The name of the group that is to be joined for listening.
 * @param ifname    Network interface to join the group on, or NULL if first
 *                  appropriate interface is to be chosen by the O/S.
 *
 * @return       0 on success, -1 on error
 */
int coap_join_mcast_group_intf_lkd(coap_context_t *ctx, const char *groupname,
                                   const char *ifname);

/**
 * Registers the option type @p type with the given context object @p ctx.
 *
 * Note: This function must be called in the locked state.
 *
 * @param ctx  The context to use.
 * @param type The option type to register.
 */
void coap_register_option_lkd(coap_context_t *ctx, uint16_t type);

/**
 * Set the context's default PKI information for a server.
 *
 * Note: This function must be called in the locked state.
 *
 * @param context        The current coap_context_t object.
 * @param setup_data     If NULL, PKI authentication will fail. Certificate
 *                       information required.
 *
 * @return @c 1 if successful, else @c 0.
 */
int coap_context_set_pki_lkd(coap_context_t *context,
                             const coap_dtls_pki_t *setup_data);

/**
 * Set the context's default Root CA information for a client or server.
 *
 * Note: This function must be called in the locked state.
 *
 * @param context        The current coap_context_t object.
 * @param ca_file        If not NULL, is the full path name of a PEM encoded
 *                       file containing all the Root CAs to be used.
 * @param ca_dir         If not NULL, points to a directory containing PEM
 *                       encoded files containing all the Root CAs to be used.
 *
 * @return @c 1 if successful, else @c 0.
 */
int coap_context_set_pki_root_cas_lkd(coap_context_t *context,
                                      const char *ca_file,
                                      const char *ca_dir);

/**
 * Set the context's default PSK hint and/or key for a server.
 *
 * @deprecated Use coap_context_set_psk2() instead.
 *
 * Note: This function must be called in the locked state.
 *
 * @param context The current coap_context_t object.
 * @param hint    The default PSK server hint sent to a client. If NULL, PSK
 *                authentication is disabled. Empty string is a valid hint.
 * @param key     The default PSK key. If NULL, PSK authentication will fail.
 * @param key_len The default PSK key's length. If @p 0, PSK authentication will
 *                fail.
 *
 * @return @c 1 if successful, else @c 0.
 */
int coap_context_set_psk_lkd(coap_context_t *context, const char *hint,
                             const uint8_t *key, size_t key_len);

/**
 * Set the context's default PSK hint and/or key for a server.
 *
 * Note: This function must be called in the locked state.
 *
 * @param context    The current coap_context_t object.
 * @param setup_data If NULL, PSK authentication will fail. PSK
 *                   information required.
 *
 * @return @c 1 if successful, else @c 0.
 */
int coap_context_set_psk2_lkd(coap_context_t *context,
                              coap_dtls_spsk_t *setup_data);

/** @} */

/**
 * @ingroup internal_api
 * @defgroup app_io_internal Application I/O Handling
 * Internal API for Application Input / Output checking
 * @{
 */

/**
 * Processes any outstanding read, write, accept or connect I/O as indicated
 * in the coap_socket_t structures (COAP_SOCKET_CAN_xxx set) embedded in
 * endpoints or sessions associated with @p ctx.
 *
 * Note: If epoll support is compiled into libcoap, coap_io_do_epoll_lkd() must
 * be used instead of coap_io_do_io_lkd().
 *
 * Note: This function must be called in the locked state.
 *
 * @param ctx The CoAP context
 * @param now Current time
 */
void coap_io_do_io_lkd(coap_context_t *ctx, coap_tick_t now);

/**
 * Process all the epoll events
 *
 * Note: If epoll support is compiled into libcoap, coap_io_do_epoll_lkd() must
 * be used instead of coap_io_do_io_lkd().
 *
 * Note: This function must be called in the locked state.
 *
 * @param ctx    The current CoAP context.
 * @param events The list of events returned from an epoll_wait() call.
 * @param nevents The number of events.
 *
 */
void coap_io_do_epoll_lkd(coap_context_t *ctx, struct epoll_event *events,
                          size_t nevents);

/**
 * Check to see if there is any i/o pending for the @p context.
 *
 * This includes Observe active (client) and partial large block transfers.
 *
 * Note: This function must be called in the locked state.
 *
 * coap_io_process_lkd() is called internally to try to send outstanding
 * data as well as process any packets just received.
 *
 * @param context The CoAP context.
 *
 * @return @c 1 I/O still pending, @c 0 no I/O pending.
 */
int coap_io_pending_lkd(coap_context_t *context);

/**
 * Any now timed out delayed packet is transmitted, along with any packets
 * associated with requested observable response.
 *
 * In addition, it returns when the next expected I/O is expected to take place
 * (e.g. a packet retransmit).
 *
 * Note: If epoll support is compiled into libcoap, coap_io_prepare_epoll_lkd()
 * must  be used instead of coap_io_prepare_io_lkd().
 *
 * Note: This function must be called in the locked state.
 *
 * @param ctx The CoAP context
 * @param now Current time.
 *
 * @return timeout Maxmimum number of milliseconds that can be used by a
 *                 epoll_wait() to wait for network events or 0 if wait should be
 *                 forever.
 */
unsigned int coap_io_prepare_epoll_lkd(coap_context_t *ctx, coap_tick_t now);

/**
 * Iterates through all the coap_socket_t structures embedded in endpoints or
 * sessions associated with the @p ctx to determine which are wanting any
 * read, write, accept or connect I/O (COAP_SOCKET_WANT_xxx is set). If set,
 * the coap_socket_t is added to the @p sockets.
 *
 * Any now timed out delayed packet is transmitted, along with any packets
 * associated with requested observable response.
 *
 * In addition, it returns when the next expected I/O is expected to take place
 * (e.g. a packet retransmit).
 *
 * Prior to calling coap_io_do_io_lkd(), the @p sockets must be tested to see
 * if any of the COAP_SOCKET_WANT_xxx have the appropriate information and if
 * so, COAP_SOCKET_CAN_xxx is set. This typically will be done after using a
 * select() call.
 *
 * Note: If epoll support is compiled into libcoap, coap_io_prepare_epoll_lkd()
 * must be used instead of coap_io_prepare_io_lkd().
 *
 * Note: This function must be called in the locked state.
 *
 * @param ctx The CoAP context
 * @param sockets Array of socket descriptors, filled on output
 * @param max_sockets Size of socket array.
 * @param num_sockets Pointer to the number of valid entries in the socket
 *                    arrays on output.
 * @param now Current time.
 *
 * @return timeout Maxmimum number of milliseconds that can be used by a
 *                 select() to wait for network events or 0 if wait should be
 *                 forever.
 */
unsigned int coap_io_prepare_io_lkd(coap_context_t *ctx,
                                    coap_socket_t *sockets[],
                                    unsigned int max_sockets,
                                    unsigned int *num_sockets,
                                    coap_tick_t now
                                   );

/**
 * The main I/O processing function.  All pending network I/O is completed,
 * and then optionally waits for the next input packet.
 *
 * This internally calls coap_io_prepare_io_lkd(), then select() for the
 * appropriate sockets, updates COAP_SOCKET_CAN_xxx where appropriate and then
 * calls coap_io_do_io_lkd() before returning with the time spent in the
 * function.
 *
 * Alternatively, if libcoap is compiled with epoll support, this internally
 * calls coap_io_prepare_epoll_lkd(), then epoll_wait() for waiting for any file
 * descriptors that have (internally) been set up with epoll_ctl() and
 * finally coap_io_do_epoll_lkd() before returning with the time spent in the
 * function.
 *
 * Note: This function must be called in the locked state.
 *
 * @param ctx The CoAP context
 * @param timeout_ms Minimum number of milliseconds to wait for new packets
 *                   before returning after doing any processing.
 *                   If COAP_IO_WAIT, the call will block until the next
 *                   internal action (e.g. packet retransmit) if any, or block
 *                   until the next packet is received whichever is the sooner
 *                   and do the necessary processing.
 *                   If COAP_IO_NO_WAIT, the function will return immediately
 *                   after processing without waiting for any new input
 *                   packets to arrive.
 *
 * @return Number of milliseconds spent in function or @c -1 if there was
 *         an error
 */
int coap_io_process_lkd(coap_context_t *ctx, uint32_t timeout_ms);

#if !defined(RIOT_VERSION) && !defined(WITH_CONTIKI)
/**
 * The main message processing loop with additional fds for internal select.
 *
 * Note: This function must be called in the locked state.
 *
 * @param ctx The CoAP context
 * @param timeout_ms Minimum number of milliseconds to wait for new packets
 *                   before returning after doing any processing.
 *                   If COAP_IO_WAIT, the call will block until the next
 *                   internal action (e.g. packet retransmit) if any, or block
 *                   until the next packet is received whichever is the sooner
 *                   and do the necessary processing.
 *                   If COAP_IO_NO_WAIT, the function will return immediately
 *                   after processing without waiting for any new input
 *                   packets to arrive.
 * @param nfds      The maximum FD set in readfds, writefds or exceptfds
 *                  plus one,
 * @param readfds   Read FDs to additionally check for in internal select()
 *                  or NULL if not required.
 * @param writefds  Write FDs to additionally check for in internal select()
 *                  or NULL if not required.
 * @param exceptfds Except FDs to additionally check for in internal select()
 *                  or NULL if not required.
 *
 *
 * @return Number of milliseconds spent in coap_io_process_with_fds_lkd, or @c -1
 *         if there was an error.  If defined, readfds, writefds, exceptfds
 *         are updated as returned by the internal select() call.
 */
int coap_io_process_with_fds_lkd(coap_context_t *ctx, uint32_t timeout_ms,
                                 int nfds, fd_set *readfds, fd_set *writefds,
                                 fd_set *exceptfds);
#endif /* ! RIOT_VERSION && ! WITH_CONTIKI */

/**
* Sends a CoAP message to given peer. The memory that is
* allocated for the pdu will be released by coap_send_lkd().
* The caller must not use or delete the pdu after calling coap_send_lkd().
 *
 * Note: This function must be called in the locked state.
*
* @param session         The CoAP session.
* @param pdu             The CoAP PDU to send.
*
* @return                The message id of the sent message or @c
*                        COAP_INVALID_MID on error.
*/
coap_mid_t coap_send_lkd(coap_session_t *session, coap_pdu_t *pdu);

/**
 * Sends an error response with code @p code for request @p request to @p dst.
 * @p opts will be passed to coap_new_error_response() to copy marked options
 * from the request. This function returns the message id if the message was
 * sent, or @c COAP_INVALID_MID otherwise.
 *
 * Note: This function must be called in the locked state.
 *
 * @param session         The CoAP session.
 * @param request         The original request to respond to.
 * @param code            The response code.
 * @param opts            A filter that specifies the options to copy from the
 *                        @p request.
 *
 * @return                The message id if the message was sent, or @c
 *                        COAP_INVALID_MID otherwise.
 */
coap_mid_t coap_send_error_lkd(coap_session_t *session,
                               const coap_pdu_t *request,
                               coap_pdu_code_t code,
                               coap_opt_filter_t *opts);

/**
 * Helper function to create and send a message with @p type (usually ACK or
 * RST). This function returns @c COAP_INVALID_MID when the message was not
 * sent, a valid transaction id otherwise.
 *
 * Note: This function must be called in the locked state.
 *
 * @param session         The CoAP session.
 * @param request         The request that should be responded to.
 * @param type            Which type to set.
 * @return                message id on success or @c COAP_INVALID_MID
 *                        otherwise.
 */
coap_mid_t coap_send_message_type_lkd(coap_session_t *session, const coap_pdu_t *request,
                                      coap_pdu_type_t type);

/**
 * Sends an ACK message with code @c 0 for the specified @p request to @p dst.
 * This function returns the corresponding message id if the message was
 * sent or @c COAP_INVALID_MID on error.
 *
 * Note: This function must be called in the locked state.
 *
 * @param session         The CoAP session.
 * @param request         The request to be acknowledged.
 *
 * @return                The message id if ACK was sent or @c
 *                        COAP_INVALID_MID on error.
 */
coap_mid_t coap_send_ack_lkd(coap_session_t *session, const coap_pdu_t *request);

/**
 * Sends an RST message with code @c 0 for the specified @p request to @p dst.
 * This function returns the corresponding message id if the message was
 * sent or @c COAP_INVALID_MID on error.
 *
 * Note: This function must be called in the locked state.
 *
 * @param session         The CoAP session.
 * @param request         The request to be reset.
 *
 * @return                The message id if RST was sent or @c
 *                        COAP_INVALID_MID on error.
 */
coap_mid_t coap_send_rst_lkd(coap_session_t *session, const coap_pdu_t *request);

/**@}*/

extern int coap_started;

#endif /* COAP_NET_INTERNAL_H_ */
