SOURCES:= main.c pdu.c net.c
HEADERS:=pdu.h net.h
CFLAGS:=-g

coap:	$(SOURCES)
	$(CC) $(CFLAGS) -o $@ $^
