/*
 * subscribe.h -- subscription handling for CoAP
 *                see RFC7641
 *
 * Copyright (C) 2010-2012,2014-2015 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file subscribe.h
 * @brief Defines the application visible subscribe information
 */

#ifndef COAP_SUBSCRIBE_H_
#define COAP_SUBSCRIBE_H_

/**
 * @defgroup observe Resource observation
 * API functions for interfacing with the observe handling (RFC7641)
 * @{
 */

/**
 * The value COAP_OBSERVE_ESTABLISH in a GET request indicates a new observe
 * relationship for (sender address, token) is requested.
 */
#define COAP_OBSERVE_ESTABLISH 0

/**
 * The value COAP_OBSERVE_CANCEL in a GET request indicates that the observe
 * relationship for (sender address, token) must be cancelled.
 */
#define COAP_OBSERVE_CANCEL 1

/** @} */

#endif /* COAP_SUBSCRIBE_H_ */
