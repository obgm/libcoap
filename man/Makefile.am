# man/Makefile.am
#
# Copyright (C)      2018 Jon Shallow <supjps-libcoap@jpshallow.com>
#
# This file is part of the CoAP C library libcoap. Please see README and
# COPYING for terms of use.

# build manuals only if 'BUILD_MANPAGES' is defined
if BUILD_MANPAGES

# building the manpages

TXT3 = coap_attribute.txt \
	coap_context.txt \
	coap_handler.txt \
	coap_observe.txt \
	coap_recovery.txt \
	coap_resource.txt \
	coap_tls_library.txt

MAN3 = $(TXT3:%.txt=%.3)

man3_MANS = $(MAN3)

TXT5 = coap-client.txt \
       coap-rd.txt \
       coap-server.txt

MAN5 = $(TXT5:%.txt=%.5)

man5_MANS = $(MAN5)

TXT7 = coap.txt

MAN7 = $(TXT7:%.txt=%.7)

man7_MANS = $(MAN7)

.txt.3:
	$(A2X) --doctype manpage --format manpage $<

.txt.5:
	$(A2X) --doctype manpage --format manpage $<

.txt.7:
	$(A2X) --doctype manpage --format manpage $<

install-man: install-man3 install-man5 install-man7
	$(INSTALL_DATA) *.3 "$(DESTDIR)$(man3dir)"

CLEANFILES = *.3 *.5 *.7 *.xml

endif # BUILD_MANPAGES
