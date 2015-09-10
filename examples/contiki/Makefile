NODE_ADDR?=0x1000

all: server

contiki:
	git clone https://github.com/contiki-os/contiki.git


CFLAGS += -g3 -Wall -pedantic -O0

CFLAGS += -I.

# contiki library
CONTIKI = contiki

CFLAGS += -DCONTIKI_TARGET_MINIMAL_NET=1 \
          -DWITH_UIP6=1 \
          -DUIP6_CONF_IPV6=1 \
          -DNETSTACK_CONF_WITH_IPV6=1 \
          -URPL_BORDER_ROUTER \
          -DAUTOSTART_ENABLE \
          -DNODE_ADDR=$(NODE_ADDR) \
          -DCONTIKI_WITH_RPL=0

include $(CONTIKI)/Makefile.include

include Makefile.common
