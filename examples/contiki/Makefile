CONTIKI=contiki-ng
TARGET?=native

all: server

$(CONTIKI):
	git clone --depth 1 https://github.com/contiki-ng/contiki-ng.git $@
	cd $(CONTIKI)/os/net/app-layer && rm -rf libcoap && ln -s ../../../../../.. libcoap

server:	$(CONTIKI)
	$(MAKE) -f Makefile.contiki CONTIKI=$(CONTIKI) TARGET=$(TARGET) server

clean:
	$(MAKE) -f Makefile.contiki CONTIKI=$(CONTIKI) TARGET=$(TARGET) clean
	rm -rf build
