/* coap.h -- CoAP message structure
 *
 * (c) 2010 Olaf Bergmann <bergmann@tzi.org>
 */

#ifndef _COAP_H_
#define _COAP_H_

/* pre-defined constants that reflect defaults for CoAP */

#define COAP_DEFAULT_RESPONSE_TIMEOUT 32 /* response timeout in seconds */
#define COAP_DEFAULT_MAX_RETRANSMIT    7 /* max number of retransmissions */
#define COAP_DEFAULT_PORT          61616 /* CoAP default UDP port */
#define COAP_DEFAULT_MAX_AGE          60 /* default maximum object lifetime in seconds */
#define COAP_MAX_PDU_SIZE          1400	 /* maximum size of a CoAP PDU */

/* CoAP request methods */

#define COAP_REQUEST_GET       0
#define COAP_REQUEST_POST      1
#define COAP_REQUEST_PUT       2
#define COAP_REQUEST_DELETE    3
#define COAP_REQUEST_SUBSCRIBE 4

/* CoAP option types */

#define COAP_OPTION_CONTENTTYPE  0
#define COAP_OPTION_URI          1
#define COAP_OPTION_MAXAGE       3
#define COAP_OPTION_ETAG         4
#define COAP_OPTION_DATE         5
#define COAP_OPTION_SUBLIFETIME  6
#define COAP_OPTION_ACCEPT       7
#define COAP_OPTION_BLOCK        8

/* CoAP result codes */

#define COAP_RESPONSE_200        0   /* 200 OK */
#define COAP_RESPONSE_201        1   /* 201 Created */
#define COAP_RESPONSE_304       14   /* 304 Not Modified */
#define COAP_RESPONSE_400       20   /* 400 Bad Request */
#define COAP_RESPONSE_401       21   /* 401 Unauthorized */
#define COAP_RESPONSE_403       23   /* 403 Forbidden */
#define COAP_RESPONSE_404       24   /* 404 Not Found */
#define COAP_RESPONSE_405       25   /* 405 Method Not Allowed */
#define COAP_RESPONSE_409       29   /* 409 Conflict */
#define COAP_RESPONSE_415       35   /* 415 Unsupported Media Type */
#define COAP_RESPONSE_500       40   /* 500 Internal Server Error */
#define COAP_RESPONSE_503       43   /* 503 Service Unavailable */
#define COAP_RESPONSE_504       44   /* 504 Gateway Timeout */

/* CoAP media type encoding */

#define COAP_MEDIATYPE_TEXT          (1 << 5) /* text */
#define COAP_MEDIATYPE_IMAGE         (2 << 5) /* image */
#define COAP_MEDIATYPE_AUDIO         (3 << 5) /* audio */
#define COAP_MEDIATYPE_VIDEO         (4 << 5) /* video */
#define COAP_MEDIATYPE_APPLICATION   (5 << 5) /* application */

/* TODO: sub-types */

#define COAP_MEDIA_TEXT_XML    (COAP_MEDIATYPE_TEXT | 0) /* text/xml */
#define COAP_MEDIA_TEXT_PLAIN  (COAP_MEDIATYPE_TEXT | 1) /* text/plain */
#define COAP_MEDIA_TEXT_CSV    (COAP_MEDIATYPE_TEXT | 2) /* text/csv */
#define COAP_MEDIA_TEXT_HTML   (COAP_MEDIATYPE_TEXT | 3) /* text/html */

typedef struct {
  unsigned short length;	/* length of string */
  char *str;
} coap_str_t;

typedef struct {
  unsigned char version:2;	/* protocol version, usually zero */
  unsigned char type:2;		/* type flag */
  unsigned char optcnt:4;	/* number of options following the header */
  union {
    struct {
      unsigned char method:4;	/* request method */
      unsigned char unused:3;	/* ____ */
      unsigned char ack:1;	/* acknowledgement flag */
    } req;
    struct {
      unsigned char code:6;	/* response code */
      unsigned char unused:2;	/* ____ */
    } res;
    struct {
      unsigned char code:6;	/* notify code */
      unsigned char unused:1;	/* ____ */
      unsigned char ack:1;	/* acknowledgement flag */
    } not;
  } msg;
  unsigned short id;		/* transaction id */
} coap_hdr_t;

typedef struct {
  unsigned char delta:4;        /* option type (expressed as delta) */
  unsigned char length:4;	/* number of option bytes (15 indicates extended form) */
  union {
    struct {			/* short form, to be used when length < 15 */
      unsigned char value[1];	/* 0--14 bytes options */
    } shortopt;
    struct {			/* extended form, to be used when lengt==15 */
      unsigned char length:8;	/* length - 15 */
      unsigned char value[1];	/* 15--270 bytes options */
    } longopt;
  };
} coap_opt_t;

typedef struct {
  coap_hdr_t *hdr;
  unsigned char *data;
} coap_pdu_t;

/** 
 * Creates a new CoAP PDU. The object is created on the heap and must be released
 * using delete_pdu();
 */

coap_pdu_t *coap_new_pdu();
void coap_delete_pdu(coap_pdu_t *);

/** 
 * Adds option of given type to pdu that is passed as first parameter. 
 */

int coap_add_option(coap_pdu_t *pdu, unsigned char type, unsigned int len, const unsigned char *data);

#endif /* _COAP_H_ */
