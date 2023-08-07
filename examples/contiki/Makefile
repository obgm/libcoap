CONTIKI=contiki-ng
TARGET?=native

WITH_CONTIKI_NG_BRANCH=release/v4.9

all: $(CONTIKI) check-version server

$(CONTIKI):
	git clone --depth 1 https://github.com/contiki-ng/contiki-ng.git $@
	echo "Updating $(CONTIKI) to ${WITH_CONTIKI_NG_BRANCH}"
	(cd ${CONTIKI} ; git pull --tags 2> /dev/null ; git checkout ${WITH_CONTIKI_NG_BRANCH})
	cd $(CONTIKI)/os/net/app-layer && rm -rf libcoap && ln -s ../../../../../.. libcoap

check-version:
	@(if [ -d $(CONTIKI) ] ; then \
		cd $(CONTIKI) ; \
		TAG=`git describe --tags --all`; \
		if [ "$$TAG" != ${WITH_CONTIKI_NG_BRANCH} ] ; then \
			if [ "$$TAG" != "tags/${WITH_CONTIKI_NG_BRANCH}" ] ; then \
				git pull --tags 2> /dev/null ; \
				echo "Updating $(CONTIKI) to ${WITH_CONTIKI_NG_BRANCH}" ; \
				git checkout ${WITH_CONTIKI_NG_BRANCH} ; \
				cd os/net/app-layer && rm -rf libcoap && ln -s ../../../../../.. libcoap ; \
			fi ; \
		fi ; \
	fi)

server:	$(CONTIKI)
	$(MAKE) -f Makefile.contiki CONTIKI=$(CONTIKI) TARGET=$(TARGET) server

clean:
	$(MAKE) -f Makefile.contiki CONTIKI=$(CONTIKI) TARGET=$(TARGET) clean
	rm -rf build
