# Makefile for libcoap
#
# Copyright (C) 2012 Olaf Bergmann <bergmann@tzi.org>
#
# This file is part of the CoAP library libcoap. Please see
# README for terms of use. 

# the library's version
VERSION:=4.0.0

# tools

SHELL = /bin/sh
MKDIR = mkdir

abs_builddir = /home/bergmann/develop/libcoap/tests
top_builddir = ..
top_srcdir = ..
# files and flags
PROGRAMS:=testdriver
SOURCES:= test_uri.c test_options.c test_pdu.c
OBJECTS:= $(patsubst %.c, %.o, $(SOURCES))
CFLAGS:=-g -Wall -g -O2
CPPFLAGS:=-I$(top_srcdir) 
DISTDIR?=$(top_builddir)/libcoap-4.0.0
FILES:=Makefile.in test_uri.h test_options.h test_pdu.h $(SOURCES)
LDFLAGS:=-L$(top_builddir)
LDLIBS:=-lcunit 
libcoap =$(top_builddir)/libcoap.a

.PHONY: clean distclean

.SUFFIXES:
.SUFFIXES:      .c .o

all:	$(PROGRAMS)

check:	
	echo DISTDIR: $(DISTDIR)
	echo top_builddir: $(top_builddir)

testdriver:	$(OBJECTS) $(libcoap)

clean:
	@rm -f $(PROGRAMS) $(OBJECTS)

distclean:	clean
	@rm -rf $(DISTDIR)
	@rm -f *~ 

dist:	$(FILES)
	test -d $(DISTDIR)/tests || mkdir $(DISTDIR)/tests
	cp $(FILES) $(DISTDIR)/tests
