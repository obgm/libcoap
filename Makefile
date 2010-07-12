PROGRAM:=coap-server
VERSION:=0.03

SOURCES:= pdu.c net.c encode.c uri.c list.c
OBJECTS:= $(patsubst %.c, %.o, $(SOURCES))
HEADERS:=coap.h debug.h pdu.h net.h encode.h uri.h list.h mem.h
CFLAGS:=-g -Wall -ansi -pedantic
DISTDIR=$(PROGRAM)-$(VERSION)
FILES:=main.c Makefile $(SOURCES) $(HEADERS) 
LIB:=libcoap.a
LDFLAGS:=-L. -l$(patsubst lib%.a,%,$(LIB))
ARFLAGS:=cru
examples:=examples

# add this for Solaris
#LDFLAGS+=-lsocket -lnsl

.PHONY: clean distclean .gitignore

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
	test -d $(DISTDIR)/$(examples) || mkdir $(DISTDIR)/$(examples)
	cp $(FILES) $(DISTDIR)
	$(MAKE) -C $(examples) dist DISTDIR=../$(DISTDIR)/$(examples)
	tar czf $(DISTDIR).tar.gz $(DISTDIR)

.gitignore:
	echo "core\n*~\n*.[oa]\n*.gz\n*.cap\n$(PROGRAM)\n$(DISTDIR)\n.gitignore" >$@
