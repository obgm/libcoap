PROGRAMS:=tiny coap-client
SOURCES:= tiny.c client.c
OBJECTS:= $(patsubst %.c, %.o, $(SOURCES))
#CFLAGS:=-g -Wall -ansi -pedantic -I..
CFLAGS:=-g -Wall -I..
DISTDIR?=something
FILES:=Makefile $(SOURCES)
LDFLAGS:=-L.. -lcoap

# add this for Solaris
#LDFLAGS+=-lsocket -lnsl

.PHONY: clean distclean

all:	$(PROGRAMS)

tiny:	tiny.o
	$(CC) -o $@ $< $(LDFLAGS)

coap-client: client.o
	$(CC) -o $@ $< $(LDFLAGS)

clean:
	@rm -f tiny $(OBJECTS)

distclean:	clean
	@rm -rf $(DISTDIR)
	@rm -f *~ 

dist:
	cp $(FILES) $(DISTDIR)
