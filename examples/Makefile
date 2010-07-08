SOURCES:= tiny.c
OBJECTS:= $(patsubst %.c, %.o, $(SOURCES))
CFLAGS:=-g -Wall -ansi -pedantic
DISTDIR?=something
FILES:=Makefile $(SOURCES)
LDFLAGS:=-L.. -lcoap

# add this for Solaris
#LDFLAGS+=-lsocket -lnsl

.PHONY: clean distclean

all:	tiny

tiny:	tiny.o
	$(CC) -o $@ $< $(LDFLAGS)

clean:
	@rm -f tiny $(OBJECTS)

distclean:	clean
	@rm -rf $(DISTDIR)
	@rm -f *~ 

dist:
	cp $(FILES) $(DISTDIR)
