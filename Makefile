SOURCES:= main.c pdu.c net.c
HEADERS:=coap.h debug.h pdu.h net.h
CFLAGS:=-g 

coap:	$(SOURCES)
	$(CC) $(CFLAGS) -o $@ $^
