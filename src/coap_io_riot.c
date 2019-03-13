/* coap_io_riot.c -- Default network I/O functions for libcoap on RIOT
 *
 * Copyright (C) 2019 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#include "coap_config.h"

#ifdef HAVE_STDIO_H
#  include <stdio.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
# define OPTVAL_T(t)         (t)
# define OPTVAL_GT(t)        (t)
#endif
#ifdef HAVE_SYS_IOCTL_H
 #include <sys/ioctl.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_SYS_UIO_H
# include <sys/uio.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <errno.h>

#include "net/gnrc.h"
#include "net/gnrc/ipv6.h"
#include "net/gnrc/netreg.h"
#include "net/udp.h"

#include "libcoap.h"
#include "coap_debug.h"
#include "mem.h"
#include "net.h"
#include "coap_io.h"
#include "pdu.h"
#include "utlist.h"
#include "resource.h"

ssize_t
coap_network_read(coap_socket_t *sock, struct coap_packet_t *packet) {
  size_t len;
  ipv6_hdr_t *ipv6_hdr;
  /* The GNRC API currently only supports UDP. */
  gnrc_pktsnip_t *udp;
  udp_hdr_t *udp_hdr;
  const gnrc_nettype_t type = GNRC_NETTYPE_UDP;

  assert(sock);
  assert(packet);

  if ((sock->flags & COAP_SOCKET_CAN_READ) == 0) {
    coap_log(LOG_DEBUG, "coap_network_read: COAP_SOCKET_CAN_READ not set\n");
    return -1;
  } else {
    /* clear has-data flag */
    sock->flags &= ~COAP_SOCKET_CAN_READ;
  }

  coap_log(LOG_DEBUG, "libcoap_read_pkt called with pkt:\n");
  /* Search for the transport header in the packet received from the
   * network interface driver. */
  udp = gnrc_pktsnip_search_type(sock->pkt, type);
  ipv6_hdr = gnrc_ipv6_get_header(sock->pkt);

  if (!ipv6_hdr || !udp || !(udp_hdr = (udp_hdr_t *)udp->data)) {
    coap_log(LOG_DEBUG, "no UDP header found in packet\n");
    return -EFAULT;
  }
  udp_hdr_print(udp_hdr);

  len = (size_t)gnrc_pkt_len_upto(sock->pkt, type) - sizeof(udp_hdr_t);
  coap_log(LOG_DEBUG, "coap_network_read: recvfrom got %zd bytes\n", len);
  if (len > COAP_RXBUFFER_SIZE) {
    coap_log(LOG_WARNING, "packet exceeds buffer size, truncated\n");
    len = COAP_RXBUFFER_SIZE;
  }
  packet->ifindex = sock->fd;

  assert(sizeof(struct in6_addr) == sizeof(ipv6_addr_t));
  packet->src.size = sizeof(struct sockaddr_in6);
  memset(&packet->src.addr, 0, sizeof(packet->src.addr));
  packet->src.addr.sin6.sin6_family = AF_INET6;
  memcpy(&packet->src.addr.sin6.sin6_addr, &ipv6_hdr->src, sizeof(ipv6_addr_t));
  memcpy(&packet->src.addr.sin6.sin6_port, &udp_hdr->src_port, sizeof(udp_hdr->src_port));

  packet->dst.size = sizeof(struct sockaddr_in6);
  memset(&packet->dst.addr, 0, sizeof(packet->dst.addr));
  packet->dst.addr.sin6.sin6_family = AF_INET6;
  memcpy(&packet->dst.addr.sin6.sin6_addr, &ipv6_hdr->dst, sizeof(ipv6_addr_t));
  memcpy(&packet->dst.addr.sin6.sin6_port, &udp_hdr->dst_port, sizeof(udp_hdr->src_port));

  packet->ifindex = sock->fd;
  packet->length = (len > 0) ? len : 0;
  memcpy(packet->payload, (uint8_t*)udp_hdr + sizeof(udp_hdr_t), len);
  if (LOG_DEBUG <= coap_get_log_level()) {
    unsigned char addr_str[INET6_ADDRSTRLEN + 8];

    if (coap_print_addr(&packet->src, addr_str, INET6_ADDRSTRLEN + 8)) {
      coap_log(LOG_DEBUG, "received %zd bytes from %s\n", len, addr_str);
    }
  }

  return len;
}
