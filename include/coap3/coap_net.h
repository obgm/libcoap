/*
 * coap_net.h -- CoAP context interface
 *
 * Copyright (C) 2010-2025 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_net.h
 * @brief CoAP context interface
 */

#ifndef COAP_NET_H_
#define COAP_NET_H_

#include <stdlib.h>
#include <string.h>

#if !defined(WITH_LWIP) && !defined(WITH_CONTIKI) && !defined(RIOT_VERSION) && !defined(_WIN32)
#include <sys/select.h>
#endif /* ! WITH_LWIP && ! WITH_CONTIKI && ! RIOT_VERSION && ! _WIN32 */

#ifdef WITH_LWIP
#include <lwip/ip_addr.h>
#endif

#if defined(__ZEPHYR__) && !defined(__unix__) && !defined(__linux__)
#include <zephyr/net/socket_select.h>
#define fd_set zsock_fd_set
#endif

#include "coap_io.h"
#include "coap_dtls.h"
#include "coap_event.h"
#include "coap_pdu.h"
#include "coap_session.h"
#include "coap_debug.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup application_api
 * @defgroup context Context Handling
 * API for handling PDUs using CoAP Contexts
 * @{
 */

typedef enum coap_response_t {
  COAP_RESPONSE_FAIL, /**< Response not liked - send CoAP RST packet */
  COAP_RESPONSE_OK    /**< Response is fine */
} coap_response_t;

/**
 * Response handler that is used as callback in coap_context_t.
 *
 * @param session CoAP session.
 * @param sent The PDU that was transmitted.
 * @param received The PDU that was received.
 * @param mid CoAP transaction ID.
 *
 * @return @c COAP_RESPONSE_OK if successful, else @c COAP_RESPONSE_FAIL which
 *         triggers sending a RST packet if the received PDU is a CON or NON.
 */
typedef coap_response_t (*coap_response_handler_t)(coap_session_t *session,
                                                   const coap_pdu_t *sent,
                                                   const coap_pdu_t *received,
                                                   const coap_mid_t mid);

/**
 * Negative Acknowedge handler that is used as callback in coap_context_t.
 *
 * @param session CoAP session.
 * @param sent The PDU that was transmitted.
 * @param reason The reason for the NACK.
 * @param mid CoAP message ID.
 */
typedef void (*coap_nack_handler_t)(coap_session_t *session,
                                    const coap_pdu_t *sent,
                                    const coap_nack_reason_t reason,
                                    const coap_mid_t mid);

/**
 * Received Ping handler that is used as callback in coap_context_t.
 *
 * @param session CoAP session.
 * @param received The PDU that was received.
 * @param mid CoAP message ID.
 */
typedef void (*coap_ping_handler_t)(coap_session_t *session,
                                    const coap_pdu_t *received,
                                    const coap_mid_t mid);

/**
 * Received Pong handler that is used as callback in coap_context_t.
 *
 * @param session CoAP session.
 * @param received The PDU that was received.
 * @param mid CoAP message ID.
 */
typedef void (*coap_pong_handler_t)(coap_session_t *session,
                                    const coap_pdu_t *received,
                                    const coap_mid_t mid);

/**
 * Definition of resource dynamic creation handler function
 *
 * @param session The CoAP session.
 * @param request The request PDU.
 *
 * @return       A pointer to the new resource or @c NULL on error.
 */
typedef coap_resource_t *(*coap_resource_dynamic_create_t)(coap_session_t *session,
                                                           const coap_pdu_t *request);
/**
 * Registers a new message handler that is called whenever a response is
 * received.
 *
 * @param context The context to register the handler for.
 * @param handler The response handler to register.
 */
void coap_register_response_handler(coap_context_t *context,
                                    coap_response_handler_t handler);

/**
 * Registers a new message handler that is called whenever a confirmable
 * message (request or response) is dropped after all retries have been
 * exhausted, or a rst message was received, or a network or TLS level
 * event was received that indicates delivering the message is not possible.
 *
 * @param context The context to register the handler for.
 * @param handler The nack handler to register.
 */
void coap_register_nack_handler(coap_context_t *context,
                                coap_nack_handler_t handler);

/**
 * Registers a new message handler that is called whenever a CoAP Ping
 * message is received.
 *
 * @param context The context to register the handler for.
 * @param handler The ping handler to register.
 */
void coap_register_ping_handler(coap_context_t *context,
                                coap_ping_handler_t handler);

/**
 * Registers a new message handler that is called whenever a CoAP Pong
 * message is received.
 *
 * @param context The context to register the handler for.
 * @param handler The pong handler to register.
 */
void coap_register_pong_handler(coap_context_t *context,
                                coap_pong_handler_t handler);

/**
 * Sets up a handler for calling when an unknown resource is requested.
 * The @p create_handler is expected to create the required resource to handle
 * the request which is then used to call the appropriate method handler.
 *
 * Doing this stops multiple threads asking for the same unknown resource and
 * means that a resource unknown handler does not need to be thread safe.
 *
 * @param context The context to add this support to.
 * @param create_handler Called to create a new resource.
 * @param dynamic_max Maximum number of currently created dynamic resources.  If
 *                    0, unlimited.
 *
 */
void coap_register_dynamic_resource_handler(coap_context_t *context,
                                            coap_resource_dynamic_create_t create_handler,
                                            uint32_t dynamic_max);

/**
 * Registers the option number @p number with the given context object @p context.
 *
 * A registered option should only be for options that libcoap library does not
 * know about (not defined in the CoAP RFCs). On receipt or sending of a PDU,
 * this registered option will get ignored when checking for unknown critical
 * options, duplicate options or the options defined as Reserved in RFC 7252 Table 7.
 *
 * @param context The context to use.
 * @param number  The option number to register.
 */
COAP_API void coap_register_option(coap_context_t *context,
                                   coap_option_num_t number);

/**
 * Creates a new coap_context_t object that will hold the CoAP stack status.
 */
coap_context_t *coap_new_context(const coap_address_t *listen_addr);

/**
 * Set the context's default PSK hint and/or key for a server.
 *
 * @deprecated Use coap_context_set_psk2() instead.
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
COAP_API int coap_context_set_psk(coap_context_t *context, const char *hint,
                                  const uint8_t *key, size_t key_len);

/**
 * Set the context's default PSK hint and/or key for a server.
 *
 * @param context    The current coap_context_t object.
 * @param setup_data If NULL, PSK authentication will fail. PSK
 *                   information required.
 *
 * @return @c 1 if successful, else @c 0.
 */
COAP_API int coap_context_set_psk2(coap_context_t *context,
                                   coap_dtls_spsk_t *setup_data);

/**
 * Set the context's default PKI information for a server.
 *
 * @param context        The current coap_context_t object.
 * @param setup_data     If NULL, PKI authentication will fail. Certificate
 *                       information required.
 *
 * @return @c 1 if successful, else @c 0.
 */
COAP_API int coap_context_set_pki(coap_context_t *context,
                                  const coap_dtls_pki_t *setup_data);

/**
 * Set the context's default Root CA information for a client or server.
 *
 * @param context        The current coap_context_t object.
 * @param ca_file        If not NULL, is the full path name of a PEM encoded
 *                       file containing all the Root CAs to be used.
 * @param ca_dir         If not NULL, points to a directory containing PEM
 *                       encoded files containing all the Root CAs to be used.
 *
 * @return @c 1 if successful, else @c 0.
 */
COAP_API int coap_context_set_pki_root_cas(coap_context_t *context,
                                           const char *ca_file,
                                           const char *ca_dir);

/**
 * Load the hosts's default trusted CAs for a client or server.
 *
 * @param context        The current coap_context_t object.
 *
 * @return @c 1 if successful, else @c 0.
 */
COAP_API int coap_context_load_pki_trust_store(coap_context_t *context);

/**
 * Set the context keepalive timer for sessions.
 * A keepalive message will be sent after if a session has been inactive,
 * i.e. no packet sent or received, for the given number of seconds.
 * For unreliable protocols, a CoAP Empty message will be sent. If a
 * CoAP RST is not received, the CoAP Empty messages will get resent based
 * on the Confirmable retry parameters until there is a failure timeout,
 * at which point the session will be considered as disconnected.
 * For reliable protocols, a CoAP PING message will be sent. If a CoAP PONG
 * has not been received before the next PING is due to be sent, the session
 * will be considered as disconnected.
 *
 * @param context        The coap_context_t object.
 * @param seconds        Number of seconds for the inactivity timer, or zero
 *                       to disable CoAP-level keepalive messages.
 */
void coap_context_set_keepalive(coap_context_t *context, unsigned int seconds);

/**
 * Set the Connection ID client tuple frequency change for testing CIDs.
 *
 * @param context        The coap_context_t object.
 * @param every          Change the client's source port @p every packets sent.
 *
 * @return @c 1 if frequency change set (CID supported), else @c 0.
 */
int coap_context_set_cid_tuple_change(coap_context_t *context, uint8_t every);

/**
 * Set the maximum token size (RFC8974).
 *
 * @param context        The coap_context_t object.
 * @param max_token_size The maximum token size.  A value between 8 and 65804
 *                       inclusive.
 */
void coap_context_set_max_token_size(coap_context_t *context,
                                     size_t max_token_size);

/**
 * Get the libcoap internal file descriptor for using in an application's
 * select() or returned as an event in an application's epoll_wait() call.
 *
 * @param context        The coap_context_t object.
 *
 * @return The libcoap file descriptor or @c -1 if epoll is not available.
 */
int coap_context_get_coap_fd(const coap_context_t *context);

/**
 * Set the maximum idle sessions count. The number of server sessions that
 * are currently not in use. If this number is exceeded, the least recently
 * used server session is completely removed.
 * 0 (the default) means that the number is not monitored.
 *
 * @param context           The coap_context_t object.
 * @param max_idle_sessions The maximum idle session count.
 */
void coap_context_set_max_idle_sessions(coap_context_t *context,
                                        unsigned int max_idle_sessions);

/**
 * Get the maximum idle sessions count.
 *
 * @param context The coap_context_t object.
 *
 * @return The count of max idle sessions.
 */
unsigned int coap_context_get_max_idle_sessions(const coap_context_t *context);

/**
 * Set the session timeout value. The number of seconds of inactivity after
 * which an unused server session will be closed.
 * 0 means use default (300 secs).
 *
 * @param context         The coap_context_t object.
 * @param session_timeout The session timeout value.
 */
void coap_context_set_session_timeout(coap_context_t *context,
                                      unsigned int session_timeout);

/**
 * Set the session reconnect delay time after a working client session has
 * failed.  0 (the default) means use no restart.
 *
 * If a session is reconnected, then any active observe subscriptions are
 * automatically restarted.
 *
 * However, if the session failure was caused by a server restart, a restart
 * observe subscription attempt for a previously dynamically created resource
 * will not cause the resource to be recreated.  This can be done by using
 * coap_persist(3) in the server.
 *
 * @param context        The coap_context_t object.
 * @param reconnect_time The time before a failed client session is reconnected
                         in seconds. 0 if reconnection is to be disabled.
 */
void coap_context_set_session_reconnect_time(coap_context_t *context,
                                             unsigned int reconnect_time);
/**
 * Get the session timeout value
 *
 * @param context The coap_context_t object.
 *
 * @return The session timeout value.
 */
unsigned int coap_context_get_session_timeout(const coap_context_t *context);

/*
 * Stop sending out observe subscriptons when calling coap_free_context().
 *
 * If this is not called, then 5.03 messages are sent out for every observe
 * subscription when the context is freed off.
 *
 * @param context The coap_context_t object.
 */
void coap_context_set_shutdown_no_observe(coap_context_t *context);

/**
 * Set the CSM timeout value. The number of seconds to wait for a (TCP) CSM
 * negotiation response from the peer.
 * 0 (the default) means use wait forever.
 *
 * @param context    The coap_context_t object.
 * @param csm_timeout The CSM timeout value.
 *
 * @deprecated Use coap_context_set_csm_timeout_ms() instead.
 */
COAP_DEPRECATED void coap_context_set_csm_timeout(coap_context_t *context,
                                                  unsigned int csm_timeout);

/**
 * Get the CSM timeout value
 *
 * @param context The coap_context_t object.
 *
 * @return The CSM timeout value.
 *
 * @deprecated Use coap_context_get_csm_timeout_ms() instead.
 */
COAP_DEPRECATED unsigned int coap_context_get_csm_timeout(const coap_context_t *context);

/**
 * Set the CSM timeout value. The number of milliseconds to wait for a (TCP) CSM
 * negotiation response from the peer.
 * The initial default is 1000 milliseconds.
 *
 * @param context        The coap_context_t object.
 * @param csm_timeout_ms The CSM timeout value in milliseconds (which could get updated
 *                       to be in the range of 10 - 10000 milliseconds).
 */
void coap_context_set_csm_timeout_ms(coap_context_t *context,
                                     unsigned int csm_timeout_ms);

/**
 * Get the CSM timeout value
 *
 * @param context The coap_context_t object.
 *
 * @return The CSM timeout value in millisecs.
 */
unsigned int coap_context_get_csm_timeout_ms(const coap_context_t *context);

/**
 * Set the CSM max session size value. The largest PDU that can be received.
 *
 * @param context    The coap_context_t object.
 * @param csm_max_message_size The CSM max message size value.
 */
void coap_context_set_csm_max_message_size(coap_context_t *context,
                                           uint32_t csm_max_message_size);

/**
 * Get the CSM max session size  value
 *
 * @param context The coap_context_t object.
 *
 * @return The CSM max session size  value.
 */
uint32_t coap_context_get_csm_max_message_size(const coap_context_t *context);

/**
 * Set the maximum number of sessions in (D)TLS handshake value. If this number
 * is exceeded, the least recently used server session in handshake is
 * completely removed.
 * 0 (the default) means that the number is not monitored.
 *
 * @param context         The coap_context_t object.
 * @param max_handshake_sessions The maximum number of sessions in handshake.
 */
void coap_context_set_max_handshake_sessions(coap_context_t *context,
                                             unsigned int max_handshake_sessions);

/**
 * Get the session timeout value
 *
 * @param context The coap_context_t object.
 *
 * @return The maximim number of sessions in (D)TLS handshake value.
 */
unsigned int coap_context_get_max_handshake_sessions(const coap_context_t *context);

/**
 * Returns a new message id and updates @p session->tx_mid accordingly. The
 * message id is returned in network byte order to make it easier to read in
 * tracing tools.
 *
 * @param session The current coap_session_t object.
 *
 * @return        Incremented message id in network byte order.
 */
COAP_API uint16_t coap_new_message_id(coap_session_t *session);

/**
 * CoAP stack context must be released with coap_free_context(). This function
 * clears all entries from the receive queue and send queue and deletes the
 * resources that have been registered with @p context, and frees the attached
 * endpoints.
 *
 * @param context The current coap_context_t object to free off.
 */
COAP_API void coap_free_context(coap_context_t *context);

/**
 * @deprecated Use coap_context_set_app_data() instead.
 *
 * Stores @p data with the given CoAP context. This function
 * overwrites any value that has previously been stored with @p
 * context.
 *
 * @param context The CoAP context.
 * @param data The data to store with wih the context. Note that this data
 *             must be valid during the lifetime of @p context.
 */
COAP_DEPRECATED void coap_set_app_data(coap_context_t *context, void *data);

/**
 * @deprecated Use coap_context_get_app_data() instead.
 *
 * Returns any application-specific data that has been stored with @p
 * context using the function coap_set_app_data(). This function will
 * return @c NULL if no data has been stored.
 *
 * @param context The CoAP context.
 *
 * @return The data previously stored or @c NULL if not data stored.
 */
COAP_DEPRECATED void *coap_get_app_data(const coap_context_t *context);

/**
 * Creates a new ACK PDU with specified error @p code. The options specified by
 * the filter expression @p opts will be copied from the original request
 * contained in @p request. Unless @c SHORT_ERROR_RESPONSE was defined at build
 * time, the textual reason phrase for @p code will be added as payload, with
 * Content-Type @c 0.
 * This function returns a pointer to the new response message, or @c NULL on
 * error. The storage allocated for the new message must be released with
 * coap_free().
 *
 * @param request Specification of the received (confirmable) request.
 * @param code    The error code to set.
 * @param opts    An option filter that specifies which options to copy from
 *                the original request in @p node.
 *
 * @return        A pointer to the new message or @c NULL on error.
 */
coap_pdu_t *coap_new_error_response(const coap_pdu_t *request,
                                    coap_pdu_code_t code,
                                    coap_opt_filter_t *opts);

/**
 * Sends an error response with code @p code for request @p request to @p dst.
 * @p opts will be passed to coap_new_error_response() to copy marked options
 * from the request. This function returns the message id if the message was
 * sent, or @c COAP_INVALID_MID otherwise.
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
COAP_API coap_mid_t coap_send_error(coap_session_t *session,
                                    const coap_pdu_t *request,
                                    coap_pdu_code_t code,
                                    coap_opt_filter_t *opts);

/**
 * Helper function to create and send a message with @p type (usually ACK or
 * RST). This function returns @c COAP_INVALID_MID when the message was not
 * sent, a valid transaction id otherwise.
 *
 * @param session         The CoAP session.
 * @param request         The request that should be responded to.
 * @param type            Which type to set.
 * @return                message id on success or @c COAP_INVALID_MID
 *                        otherwise.
 */
COAP_API coap_mid_t coap_send_message_type(coap_session_t *session, const coap_pdu_t *request,
                                           coap_pdu_type_t type);

/**
 * Sends an ACK message with code @c 0 for the specified @p request to @p dst.
 * This function returns the corresponding message id if the message was
 * sent or @c COAP_INVALID_MID on error.
 *
 * @param session         The CoAP session.
 * @param request         The request to be acknowledged.
 *
 * @return                The message id if ACK was sent or @c
 *                        COAP_INVALID_MID on error.
 */
COAP_API coap_mid_t coap_send_ack(coap_session_t *session, const coap_pdu_t *request);

/**
 * Sends an RST message with code @c 0 for the specified @p request to @p dst.
 * This function returns the corresponding message id if the message was
 * sent or @c COAP_INVALID_MID on error.
 *
 * @param session         The CoAP session.
 * @param request         The request to be reset.
 *
 * @return                The message id if RST was sent or @c
 *                        COAP_INVALID_MID on error.
 */
COAP_API coap_mid_t coap_send_rst(coap_session_t *session, const coap_pdu_t *request);

/**
* Sends a CoAP message to given peer. The memory that is
* allocated for the pdu will be released by coap_send().
* The caller must not use or delete the pdu after calling coap_send().
*
* @param session         The CoAP session.
* @param pdu             The CoAP PDU to send.
*
* @return                The message id of the sent message or @c
*                        COAP_INVALID_MID on error.
*/
COAP_API coap_mid_t coap_send(coap_session_t *session, coap_pdu_t *pdu);

#define coap_send_large(session, pdu) coap_send(session, pdu)

/*
 * Send a request PDU and wait for the response PDU.
 *
 * @param session     The CoAP session.
 * @param request_pdu The requesting PDU. If this PDU contains the Observe
 *                    option, the unsolocited responses will get handled by the
 *                    defined response handler. This PDU must be freed off by the
 *                    caller after processing.
 * @param response_pdu If there is a response, the response PDU is put here.
 *                     This PDU must be freed off by the caller after processing.
 * @param timeout_ms Positive maximum number of milliseconds to wait for response
 *                   packet following the request. If there is a large block transfer
 *                   this timeout is for between each request and response.
 *
 * @return 0 or +ve Time in function in ms after successful transfer (which can be
 *                  bigger than timeout_ms).
 *               -1 Invalid timeout parameter
 *               -2 Failed to transmit PDU
 *               -3 Nack or Event handler invoked, cancelling request
 *               -4 coap_io_process returned error (fail to re-lock or select())
 *               -5 Response not received in the given time
 *               -6 Terminated by user
 *               -7 Client mode code not enabled
 */
COAP_API int coap_send_recv(coap_session_t *session, coap_pdu_t *request_pdu,
                            coap_pdu_t **response_pdu, uint32_t timeout_ms);

/**
 * Terminate any active coap_send_recv() sessions
 */
void coap_send_recv_terminate(void);

/**
 * Invokes the event handler of @p context for the given @p event and
 * @p data.
 *
 * @param context The CoAP context whose event handler is to be called.
 * @param event   The event to deliver.
 * @param session The session related to @p event.
 * @return The result from the associated event handler or 0 if none was
 * registered.
 */
COAP_API int coap_handle_event(coap_context_t *context,
                               coap_event_t event,
                               coap_session_t *session);
/**
 * Returns 1 if there are no messages to send or to dispatch in the context's
 * queues.
 *
 * @param context The CoAP context to check.
 *
 * @return @c 0 if there are still pending transmits else @c 1 if nothing
 *         queued for transmission.  Note that @c 0 does not mean there has
 *         been a response to a transmitted request.
 */
COAP_API int coap_can_exit(coap_context_t *context);

/**
 * Returns the current value of an internal tick counter. The counter counts \c
 * COAP_TICKS_PER_SECOND ticks every second.
 */
void coap_ticks(coap_tick_t *);

/**
 * Function interface for joining a multicast group for listening for the
 * currently defined endpoints that are UDP.
 *
 * @param ctx       The current context.
 * @param groupname The name of the group that is to be joined for listening.
 * @param ifname    Network interface to join the group on, or NULL if first
 *                  appropriate interface is to be chosen by the O/S.
 *
 * @return       0 on success, -1 on error
 */
COAP_API int coap_join_mcast_group_intf(coap_context_t *ctx, const char *groupname,
                                        const char *ifname);

#define coap_join_mcast_group(ctx, groupname) \
  (coap_join_mcast_group_intf(ctx, groupname, NULL))

/**
 * Function interface for defining the hop count (ttl) for sending
 * multicast traffic.  The default is 1 so that the ttl expires after
 * decrementing if the packet is trying to pass out of the local network.
 *
 * @param session The current session.
 * @param hops    The number of hops (ttl) to use before the multicast
 *                packet expires.
 *
 * @return       1 on success, 0 on error
 */
int coap_mcast_set_hops(coap_session_t *session, size_t hops);

/**
 * Function interface to enable processing mcast requests on a per resource
 * basis.  This then enables a set of configuration flags set up when
 * configuring the resources (coap_resource_init()).
 *
 * @param context The current context.
 */
void coap_mcast_per_resource(coap_context_t *context);

/**
 * Stores @p data with the given context. This function overwrites any value
 * that has previously been stored with @p context.
 *
 * @deprecated Use coap_context_set_app_data2() instead.
 *
 * @param context The CoAP context.
 * @param data The pointer to the data to store.
 */
COAP_DEPRECATED void coap_context_set_app_data(coap_context_t *context,
                                               void *data);

/**
 * Stores @p data with the given context, returning the previously stored
 * value or NULL. The data @p callback can be defined if the data is to be
 * released when the context is deleted.
 *
 * Note: It is the responsibility of the caller to free off (if appropriate) any
 * returned data.
 *
 * @param context The CoAP context.
 * @param data The pointer to the data to store or NULL to just clear out the
 *             previous data.
 * @param callback The optional release call-back for data on context
 *                 removal or NULL.
 *
 * @return The previous data (if any) stored in the context.
 */
COAP_API void *coap_context_set_app_data2(coap_context_t *context, void *data,
                                          coap_app_data_free_callback_t callback);

/**
 * Returns any application-specific data that has been stored with @p
 * context using the function coap_context_set_app_data(). This function will
 * return @c NULL if no data has been stored.
 *
 * @param context The CoAP context.
 *
 * @return Pointer to the stored data or @c NULL.
 */
void *coap_context_get_app_data(const coap_context_t *context);

/**@}*/

/**
 * @ingroup application_api
 * @defgroup app_io Application I/O Handling
 * API for Application Input / Output checking
 * @{
 */

#define COAP_IO_WAIT    0
#define COAP_IO_NO_WAIT ((uint32_t)-1)

/**
 * The main I/O processing function.  All pending network I/O is completed,
 * and then optionally waits for the next input packet.
 *
 * This internally calls coap_io_prepare_io(), then select() for the appropriate
 * sockets, updates COAP_SOCKET_CAN_xxx where appropriate and then calls
 * coap_io_do_io() before returning with the time spent in the function.
 *
 * Alternatively, if libcoap is compiled with epoll support, this internally
 * calls coap_io_prepare_epoll(), then epoll_wait() for waiting for any file
 * descriptors that have (internally) been set up with epoll_ctl() and
 * finally coap_io_do_epoll() before returning with the time spent in the
 * function.
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
COAP_API int coap_io_process(coap_context_t *ctx, uint32_t timeout_ms);

#if !defined(WITH_LWIP) && !defined(RIOT_VERSION) && !defined(WITH_CONTIKI)
/**
 * The main message processing loop with additional fds for internal select.
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
 * @return Number of milliseconds spent in coap_io_process_with_fds, or @c -1
 *         if there was an error.  If defined, readfds, writefds, exceptfds
 *         are updated as returned by the internal select() call.
 */
COAP_API int coap_io_process_with_fds(coap_context_t *ctx, uint32_t timeout_ms,
                                      int nfds, fd_set *readfds, fd_set *writefds,
                                      fd_set *exceptfds);
#endif /* ! WITH_LWIP && ! RIOT_VERSION && ! WITH_CONTIKI */

/**
 * Check to see if there is any i/o pending for the @p context.
 *
 * This includes Observe active (client) and partial large block transfers.
 *
 * coap_io_process() is called internally to try to send outstanding
 * data as well as process any packets just received.
 *
 * @param context The CoAP context.
 *
 * @return @c 1 I/O still pending, @c 0 no I/O pending.
 */
COAP_API int coap_io_pending(coap_context_t *context);

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
* Prior to calling coap_io_do_io(), the @p sockets must be tested to see
* if any of the COAP_SOCKET_WANT_xxx have the appropriate information and if
* so, COAP_SOCKET_CAN_xxx is set. This typically will be done after using a
* select() call.
*
* Note: If epoll support is compiled into libcoap, coap_io_prepare_epoll() must
* be used instead of coap_io_prepare_io().
*
* Internal function.
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
COAP_API unsigned int coap_io_prepare_io(coap_context_t *ctx,
                                         coap_socket_t *sockets[],
                                         unsigned int max_sockets,
                                         unsigned int *num_sockets,
                                         coap_tick_t now
                                        );

/**
 * Processes any outstanding read, write, accept or connect I/O as indicated
 * in the coap_socket_t structures (COAP_SOCKET_CAN_xxx set) embedded in
 * endpoints or sessions associated with @p ctx.
 *
 * Note: If epoll support is compiled into libcoap, coap_io_do_epoll() must
 * be used instead of coap_io_do_io().
 *
 * Internal function.
 *
 * @param ctx The CoAP context
 * @param now Current time
 */
COAP_API void coap_io_do_io(coap_context_t *ctx, coap_tick_t now);

/**
 * Any now timed out delayed packet is transmitted, along with any packets
 * associated with requested observable response.
 *
 * In addition, it returns when the next expected I/O is expected to take place
 * (e.g. a packet retransmit).
 *
 * Note: If epoll support is compiled into libcoap, coap_io_prepare_epoll() must
 * be used instead of coap_io_prepare_io().
 *
 * Internal function.
 *
 * @param ctx The CoAP context
 * @param now Current time.
 *
 * @return timeout Maxmimum number of milliseconds that can be used by a
 *                 epoll_wait() to wait for network events or 0 if wait should be
 *                 forever.
 */
COAP_API unsigned int coap_io_prepare_epoll(coap_context_t *ctx, coap_tick_t now);

struct epoll_event;

/**
 * Process all the epoll events
 *
 * Note: If epoll support is compiled into libcoap, coap_io_do_epoll() must
 * be used instead of coap_io_do_io().
 *
 * Internal function
 *
 * @param ctx    The current CoAP context.
 * @param events The list of events returned from an epoll_wait() call.
 * @param nevents The number of events.
 *
 */
COAP_API void coap_io_do_epoll(coap_context_t *ctx, struct epoll_event *events,
                               size_t nevents);

/**
 * Main thread coap_io_process_loop activity.
 *
 * This function should not do any blocking.
 *
 * @param arg The value of main_loop_code_arg passed into coap_io_process_loop().
 *
 */
typedef void (*coap_io_process_thread_t)(void *arg);

/**
 * Do the coap_io_process() across @p thread_count threads.
 * The main thread will invoke @p main_loop_code (if defined) at least
 * every @p timeout_ms.
 *
 * Note: If multi-threading protection is not in place, then @p thread_count
 * is ignored and only a single thread runs (but still executes
 * @p main_loop_code)
 *
 * Note: To stop the threads and continual looping,
 * coap_io_process_terminate_loop() should be called.
 *
 * @param context The current CoAP context.
 * @param main_loop_code The name of the function to execute in the main
 *                       thread or NULL if not required. This function should
 *                       not do any blocking.
 * @param main_loop_code_arg The argument to pass to @p main_loop_code.
 * @param timeout_ms The maximum amount of time the main thread should delay up
 *                   to (i.e. timeout parameter for coap_io_process()) before
 *                   the loop starts again.
 * @param thread_count The number of threads to run.
 *
 */
COAP_API int coap_io_process_loop(coap_context_t *context,
                                  coap_io_process_thread_t main_loop_code,
                                  void *main_loop_code_arg, uint32_t timeout_ms,
                                  uint32_t thread_count);

/**
 * Terminate all the additional threads created by coap_io_process_loop()
 * and break out of the main thread loop to return from coap_io_process_loop().
 *
 * Typically this would be called from within a SIGQUIT handler.
 *
 */
void coap_io_process_terminate_loop(void);

/**
 * Configure a defined number of threads to do the alternate coap_io_process()
 * work with traffic load balanced across the threads based on inactive
 * threads.
 *
 * @param context Context.
 * @param thread_count The number of threads to configure.
 *
 * @return 1 success or 0 on failure.
 */
int coap_io_process_configure_threads(coap_context_t *context,
                                      uint32_t thread_count);

/**
 * Release the coap_io_process() worker threads.
 *
 * @param context Context.
 */
void coap_io_process_remove_threads(coap_context_t *context);

/**
 * Get the libcoap internal file descriptor for a socket. This can be used to
 * integrate libcoap in an external event loop instead of using one of its
 * builtin event loops.
 *
 * @param socket The CoAP socket
 *
 * @return The libcoap file descriptor or @c COAP_INVALID_SOCKET if the platform
 *         is not using file descriptors.
 */
COAP_API coap_fd_t coap_socket_get_fd(coap_socket_t *socket);

/*
 * Get the current libcoap usage of file descriptors that are in a read or write pending state.
 *
 * @param context The current CoAP context.
 * @param read_fds Array to populate with file descriptors in the read pending state.
 * @param have_read_fds Updated wth the number of fds found in read pending state.
 * @param max_read_fds Maximum size of read_fds[] array.
 * @param write_fds Array to populate with file descriptors in the write pending state.
 * @param have_write_fds Updated wth the number of fds found in write pending state.
 * @param max_write_fds Maximum size of write_fds[] array.
 * @param rem_timeout_ms Remaining timeout time to next libcoap activity in milli-secs.
 *
 * @return @c 1 if successful, else @c 0 if error.
 */
COAP_API unsigned int coap_io_get_fds(coap_context_t *context, coap_fd_t read_fds[],
                                      unsigned int *have_read_fds,
                                      unsigned int max_read_fds,
                                      coap_fd_t write_fds[],
                                      unsigned int *have_write_fds,
                                      unsigned int max_write_fds,
                                      unsigned int *rem_timeout_ms);

/**
 * Get the libcoap internal flags for a socket. This can be used to
 * integrate libcoap in an external event loop instead of using one of its
 * builtin event loops.
 *
 * @param socket The CoAP socket
 *
 * @return the OR-ed COAP_SOCKET* flags for this socket
 */
COAP_API coap_socket_flags_t coap_socket_get_flags(coap_socket_t *socket);

/**
 * Set the libcoap internal flags for a socket. This can be used to
 * integrate libcoap in an external event loop instead of using one of its
 * builtin event loops.
 *
 * @param socket The CoAP socket
 * @param flags The new flags for this socket
 */
COAP_API void coap_socket_set_flags(coap_socket_t *socket, coap_socket_flags_t flags);

/**@}*/

#if defined(WITH_LWIP) || defined(WITH_LWIP_MAN_CHECK) || defined(__DOXYGEN__)
/**
 * @ingroup application_api
 * @defgroup lwip LwIP specific API
 * API for LwIP interface
 * @{
 */

/**
 * Dump the current state of the LwIP memory pools.
 *
 * Requires both MEMP_STATS and LWIP_STATS_DISPLAY to be defined as 1
 * in lwipopts.h
 *
 * @param log_level The logging level to use.
 *
 */
void coap_lwip_dump_memory_pools(coap_log_t log_level);

/**
 * LwIP callback handler that can be used to wait / timeout for the
 * next input packet.
 *
 * @param arg The argument passed to the coap_lwip_set_input_wait_handler()
 *            function.
 * @param milli_secs Suggested number of milli secs to wait before returning
 *                   if no input.
 *
 * @return @c 1 if packet received, @c 0 for timeout, else @c -1 on error.
 */
typedef int (*coap_lwip_input_wait_handler_t)(void *arg, uint32_t milli_secs);

/**
 * Set up a wait / timeout callback handler for use when
 * the application calls coap_io_process().
 *
 * @param context   The coap context to associate this handler with.
 * @param handler   The handler to call while waiting for input.
 * @param input_arg The argument to pass into handler().
 *
 */
void coap_lwip_set_input_wait_handler(coap_context_t *context,
                                      coap_lwip_input_wait_handler_t handler,
                                      void *input_arg);

/**@}*/
#endif /* WITH_LWIP || WITH_LWIP_MAN_CHECK || defined(__DOXYGEN__) */

/**
 * @deprecated Use coap_io_process() instead.
 *
 * This function just calls coap_io_process().
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
#define coap_run_once(ctx, timeout_ms) coap_io_process(ctx, timeout_ms)

/**
* @deprecated Use coap_io_prepare_io() instead.
*
* This function just calls coap_io_prepare_io().
*
* Internal function.
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
#define coap_write(ctx, sockets, max_sockets, num_sockets, now) \
  coap_io_prepare_io(ctx, sockets, max_sockets, num_sockets, now)

/**
 * @deprecated Use coap_io_do_io() instead.
 *
 * This function just calls coap_io_do_io().
 *
 * Internal function.
 *
 * @param ctx The CoAP context
 * @param now Current time
 */
#define coap_read(ctx, now) coap_io_do_io(ctx, now)

/* Old definitions which may be hanging around in old code - be helpful! */
#define COAP_RUN_NONBLOCK COAP_RUN_NONBLOCK_deprecated_use_COAP_IO_NO_WAIT
#define COAP_RUN_BLOCK COAP_RUN_BLOCK_deprecated_use_COAP_IO_WAIT

#ifdef __cplusplus
}
#endif

#endif /* COAP_NET_H_ */
