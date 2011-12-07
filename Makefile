all: coap-server #coap-client
	$(MAKE) $(MAKEFLAGS) ROLE=server coap-server
# 	$(MAKE) $(MAKEFLAGS) clean
# 	$(MAKE) $(MAKEFLAGS) ROLE=client coap-client

CONTIKI=../..
#CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\"

WITH_UIP6=1
UIP_CONF_IPV6=1

ifneq ($(TARGET), minimal-net)
CFLAGS += -DUIP_CONF_IPV6_RPL=1
endif

ifneq ($(ROLE),client)
	UIP_LLADDR="{0x00,0x06,0x98,0x00,0x02,0x32}"
	CFLAGS+= -DUIP_CONF_LLADDR=$(UIP_LLADDR)
else
	UIP_LLADDR="{0x00,0x06,0x98,0x00,0x02,0x30}"
	CFLAGS+= -DUDP_CONNECTION_ADDR="fe80::206:98ff:fe00:232" \
		 -DUIP_CONF_LLADDR=$(UIP_LLADDR)
endif

CFLAGS += -ffunction-sections
LDFLAGS += -Wl,--gc-sections,--undefined=_reset_vector__,--undefined=InterruptVectors,--undefined=_copy_data_init__,--undefined=_clear_bss_init__,--undefined=_end_of_init__

CFLAGS += -DUIP_CONF_TCP=0 -DUIP_CONF_BYTE_ORDER=1234

APPS += libcoap 

PROJECT_SOURCEFILES = pdu.c net.c debug.c encode.c uri.c coap_list.c resource.c hashkey.c str.c option.c async.c

include $(CONTIKI)/Makefile.include
