NODE_ADDR?=0x1000

all: server

contiki:
	git clone https://github.com/contiki-os/contiki.git

# contiki and coap opts
CONTIKI=contiki

CFLAGS += -I.

# contiki library

PLATFORM_VPATH = $(CONTIKI)/cpu/native $(CONTIKI)/cpu/native/net $(CONTIKI)/platform/minimal-net
#PLATFORM_CPPFLAGS =
PLATFORM_CFLAGS = -I$(CONTIKI)/cpu/native/ -I$(CONTIKI)/platform/minimal-net
PLATFORM_OBJS = contiki-main.o tapdev6.o tapdev-drv.o clock.o serial-line.o

CONTIKIOBJS = $(PLATFORM_OBJS) ringbuf.o autostart.o list.o memb.o uiplib.o uip-nd6.o uip-neighbor.o uip-ds6.o uip-ds6-nbr.o linkaddr.o uip.o uip-udp-packet.o random.o ctimer.o timer.o etimer.o stimer.o procinit.o process.o udp-socket.o uip-icmp6.o tcpip.o uip-packetqueue.o uip-ds6-route.o nbr-table.o uip6.o uip.o uip-debug.o packetbuf.o
vpath %.c $(CONTIKI)/core $(CONTIKI)/core/lib $(CONTIKI)/core/sys $(CONTIKI)/core/dev $(CONTIKI)/core/net $(CONTIKI)/core/net/ip $(CONTIKI)/core/net/ipv4 $(CONTIKI)/core/net/ipv6 $(CONTIKI)/core/loader $(CONTIKI)/core/cfs $(PLATFORM_VPATH)

CFLAGS += -DCONTIKI_TARGET_MINIMAL_NET=1 -DWITH_UIP6=1 -DUIP6_CONF_IPV6=1 -DNETSTACK_CONF_WITH_IPV6=1 -DUIP_CONF_IPV6_RPL=0 -URPL_BORDER_ROUTER -DAUTOSTART_ENABLE -DNODE_ADDR=$(NODE_ADDR)

CFLAGS += -g3 -Wall -pedantic -O0

include Makefile.common
