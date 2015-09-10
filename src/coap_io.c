/* coap_io.h -- Default network I/O functions for libcoap
 *
 * Copyright (C) 2012,2014 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

#include "coap_config.h"

#include "debug.h"
#include "mem.h"
#include "coap_io.h"

#include "platform_io.h"

size_t
coap_get_max_packetlength(const coap_packet_t *packet UNUSED_PARAM) {
  return COAP_MAX_PDU_SIZE;
}

void
coap_packet_populate_endpoint(coap_packet_t *packet, coap_endpoint_t *target)
{
  target->handle = packet->interface->handle;
  memcpy(&target->addr, &packet->dst, sizeof(target->addr));
  target->ifindex = packet->ifindex;
  target->flags = 0; /* FIXME */
}

void
coap_packet_get_memmapped(coap_packet_t *packet, unsigned char **address, size_t *length)
{
	*address = packet->payload;
	*length = packet->length;
}

int
coap_is_local_if(const coap_address_t *local, const coap_address_t *dst) {
  return coap_address_isany(local) || coap_address_equals(dst, local) ||
    coap_is_mcast(dst);
}

void coap_free_packet(coap_packet_t *packet)
{
  coap_free_type(COAP_PACKET, packet);
}


