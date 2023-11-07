/*
 * Demo for libcoap on lwIP
 *
 * partially copied from lwip-contrib/ports/unix/proj/minimal/main.c
 *
 *
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * Author: Adam Dunkels <adam@sics.se>
 * RT timer modifications by Christiaan Simons
 * lwip adaptions: chrysn <chrysn@fsfe.org>
 * also, https://savannah.nongnu.org/bugs/?40245 was applied */

#include "server-coap.h"

#include <lwip/init.h>
#include <lwip/timeouts.h>

#include <netif/etharp.h>
#include <netif/tapif.h>

#include <signal.h>

#if LWIP_IPV4
static ip4_addr_t ipaddr, netmask, gw;
#endif /* LWIP_IPV4 */

static int quit = 0;

void
handle_sigint(int signum) {
  (void)signum;

  quit = 1;
}

/*
 * This function is called internally by coap_io_process() to check
 * for input.
 */
static int
wait_for_input(void *arg, uint32_t milli_secs) {
  struct netif *netif = (struct netif *)arg;
  int ret;

  (void)milli_secs;
  ret = tapif_select(netif);

  sys_check_timeouts();
  return ret;
}

int
main(int argc, char **argv) {
  struct netif netif;
#ifndef _WIN32
  struct sigaction sa;
#endif

  /* startup defaults (may be overridden by one or more opts). this is
   * hard-coded v4 even in presence of v6, which does auto-discovery and
   * should thus wind up with an address of fe80::12:34ff:fe56:78ab%tap0
   * */
#if LWIP_IPV4
  IP4_ADDR(&gw, 192,168,113,1);
  IP4_ADDR(&ipaddr, 192,168,113,2);
  IP4_ADDR(&netmask, 255,255,255,0);
#endif /* LWIP_IPV4 */

  lwip_init();

  printf("TCP/IP initialized.\n");

#if LWIP_IPV4
  netif_add(&netif, &ipaddr, &netmask, &gw, NULL, tapif_init, ethernet_input);
#endif /* LWIP_IPV4 */
  netif.flags |= NETIF_FLAG_ETHARP;
  netif_set_default(&netif);
  netif_set_up(&netif);
#if LWIP_IPV4
  printf("IP4 %s\n", ip4addr_ntoa(ip_2_ip4(&netif.ip_addr)));
#endif /* LWIP_IPV4 */
#if LWIP_IPV6
  netif_create_ip6_linklocal_address(&netif, 1);
#if LWIP_IPV4
  printf("IP6 [%s]\n", ip6addr_ntoa(&netif.ip6_addr[0].u_addr.ip6));
#else /* ! LWIP_IPV4 */
  printf("IP6 [%s]\n", ip6addr_ntoa(&netif.ip6_addr[0].addr));
#endif /* ! LWIP_IPV4 */
#endif /* LWIP_IPV6 */

  /* start applications here */

#ifdef _WIN32
  signal(SIGINT, handle_sigint);
#else
  memset(&sa, 0, sizeof(sa));
  sigemptyset(&sa.sa_mask);
  sa.sa_handler = handle_sigint;
  sa.sa_flags = 0;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  /* So we do not exit on a SIGPIPE */
  sa.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &sa, NULL);
#endif

  server_coap_init(wait_for_input, &netif, argc, argv);

  printf("Server Application started.\n");

  while (!quit) {
    /*
     * Poll netif, pass any read packet to lwIP
     * Has internal timeout of 100 msec (sometimes less) based on
     * sys_timeouts_sleeptime().
     */
    tapif_select(&netif);

    sys_check_timeouts();

    server_coap_poll();
  }
  server_coap_finished();
  printf("Server Application finished.\n");
  exit(0);

  return 0;
}
