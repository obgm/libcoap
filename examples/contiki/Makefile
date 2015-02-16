NODE_ADDR?=0x1000

all: server

contiki:
	git clone https://github.com/contiki-os/contiki.git

# contiki and coap opts
CONTIKI=contiki

CFLAGS += -I.

# contiki library

CONTIKIOBJS = contiki-main.o tapdev6.o tapdev-drv.o clock.o serial-line.o ringbuf.o autostart.o list.o memb.o uiplib.o uip-nd6.o uip-neighbor.o uip-ds6.o uip-ds6-nbr.o linkaddr.o uip.o uip-udp-packet.o random.o ctimer.o timer.o etimer.o stimer.o procinit.o process.o udp-socket.o uip-icmp6.o tcpip.o uip-packetqueue.o uip-ds6-route.o nbr-table.o uip6.o uip.o uip-debug.o packetbuf.o
vpath %.c $(CONTIKI)/core $(CONTIKI)/core/lib $(CONTIKI)/core/sys $(CONTIKI)/core/dev $(CONTIKI)/core/net $(CONTIKI)/core/net/ip $(CONTIKI)/core/net/ipv4 $(CONTIKI)/core/net/ipv6 $(CONTIKI)/core/loader $(CONTIKI)/core/cfs $(CONTIKI)/cpu/native $(CONTIKI)/cpu/native/net $(CONTIKI)/platform/minimal-net

CFLAGS += -DCONTIKI_TARGET_MINIMAL_NET=1 -DWITH_UIP6=1 -DUIP6_CONF_IPV6=1 -DNETSTACK_CONF_WITH_IPV6=1 -DUIP_CONF_IPV6_RPL=0 -URPL_BORDER_ROUTER -DAUTOSTART_ENABLE -DNODE_ADDR=$(NODE_ADDR)

# coap library

CFLAGS += -std=gnu99

CFLAGS += -I../..

vpath %.c ../..

COAPOBJS = net.o debug.o option.o resource.o hashkey.o pdu.o encode.o subscribe.o coap_io.o block.o uri.o mem.o

CFLAGS += -g3 -Wall -pedantic -O0
CFLAGS += -I$(CONTIKI)/core/ -I$(CONTIKI)/core/sys/ -I$(CONTIKI)/core/net/ip/ -I$(CONTIKI)/core/lib/ -I$(CONTIKI)/cpu/native/ -I$(CONTIKI)/platform/minimal-net

# making an executable out of all of it

OBJS = server.o ${CONTIKIOBJS} ${COAPOBJS}

server: ${OBJS}

symbols.h:	$(CONTIKI)/tools/empty-symbols.h
	cp -p $< $@

symbols.c:	$(CONTIKI)/tools/empty-symbols.c
	cp -p $< $@

symbols.o:	symbols.c symbols.h

clean:
	rm -f core server ${OBJS} symbols.c symbols.h

distclean: clean
	rm -rf *~ *.o contiki

.PHONY: clean distclean contiki
