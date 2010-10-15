VERSION:=0.05

SOURCES:= pdu.c net.c debug.c encode.c uri.c list.c subscribe.c str.c
OBJECTS:= $(patsubst %.c, %.o, $(SOURCES))
HEADERS:=coap.h debug.h pdu.h net.h encode.h uri.h list.h mem.h subscribe.h str.h $(prg_headers)
CFLAGS:=-g -Wall -ansi -pedantic
DISTDIR=coap-$(VERSION)
SUBDIRS:=examples
FILES:=Makefile $(SOURCES) $(HEADERS)
LIB:=libcoap.a
LDFLAGS:=-L. -l$(patsubst lib%.a,%,$(LIB))
ARFLAGS:=cru
examples:=examples
doc:=doc

# add this for Solaris
#LDFLAGS+=-lsocket -lnsl

.PHONY: all dirs clean distclean .gitignore doc

all:	$(LIB) dirs

dirs:	$(SUBDIRS)
	for dir in $^; do \
		$(MAKE) -C $$dir ; \
	done

$(LIB):	$(OBJECTS)
	$(AR) $(ARFLAGS) $@ $^ 
	ranlib $@

# build main.o separately as c99 has no getaddrinfo, so CC will complain
main.o:	main.c
	$(CC) -DVERSION=\"$(VERSION)\" -g -Wall -c -o main.o main.c 

clean:
	@rm -f $(PROGRAM) main.o $(LIB) $(OBJECTS)
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir clean ; \
	done

doc:	
	$(MAKE) -C doc

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
