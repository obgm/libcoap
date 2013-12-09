all: server

lwip:
	git clone git://git.savannah.nongnu.org/lwip.git -b DEVEL-1_4_1

lwip-contrib:
	git clone git://git.savannah.nongnu.org/lwip/lwip-contrib.git -b master

LWIPOBJS = def.o init.o mintapif.o etharp.o netif.o timer.o timers.o stats.o mem.o memp.o udp.o tcp.o pbuf.o ip_addr.o ip.o inet_chksum.o tcp_in.o tcp_out.o icmp.o raw.o ip_frag.o sys_arch.o
vpath %.c lwip/src/core/ lwip-contrib/ports/unix/proj/minimal/ lwip/src/netif/ lwip/src/core/ipv4/ lwip-contrib/ports/unix/

# flags from lwip
CFLAGS += -g -Wall -pedantic -Dopenbsd -DIPv4 -Os -fpack-struct -DLWIP_DEBUG

# lwip opts (include early to shadow the
# lwip-contrib/ports/unix/proj/minimal/ file)
CFLAGS += -I.

# lwip library
CFLAGS += -Ilwip/src/include/ -Ilwip/src/include/ipv4/ -Ilwip-contrib/ports/unix/include/ -Ilwip-contrib/ports/unix/proj/minimal/

${LWIPOBJS}: lwip lwip-contrib

OBJS = server.o ${LWIPOBJS}

server: ${OBJS}

clean:
	rm -f ${OBJS}

.PHONY: clean
