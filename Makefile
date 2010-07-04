PROGRAM:=coap
VERSION:=0.01

SOURCES:= pdu.c net.c
OBJECTS:= $(patsubst %.c, %.o, $(SOURCES))
HEADERS:=coap.h debug.h pdu.h net.h
CFLAGS:=-g -Wall -std=c99 # -pedantic  # FIXME: pdu.h contains GCC extensions
DISTDIR=$(PROGRAM)-$(VERSION)
FILES:=main.c Makefile $(SOURCES) $(HEADERS) 
LIB:=libcoap.a
LDFLAGS:=-L. -l$(patsubst lib%.a,%,$(LIB))
ARFLAGS:=cru

# add this for Solaris
#LDFLAGS+=-lsocket -lnsl

.PHONY: clean distclean

$(PROGRAM):	main.o $(LIB)
	$(CC) -o $@ $< $(LDFLAGS)

$(LIB):	$(OBJECTS)
	$(AR) $(ARFLAGS) $@ $^ 
	ranlib $@

# build main.o separately as c99 has no getaddrinfo, so CC will complain
main.o:	main.c
	$(CC) -DVERSION=\"$(VERSION)\" -g -Wall -c -o main.o main.c 

clean:
	@rm -f $(PROGRAM) main.o $(LIB) $(OBJECTS)

distclean:	clean
	@rm -rf $(DISTDIR)
	@rm -f *~ $(DISTDIR).tar.gz

dist:
	test -d $(DISTDIR) || mkdir $(DISTDIR)
	cp $(FILES) $(DISTDIR)
	tar czf $(DISTDIR).tar.gz $(DISTDIR)
