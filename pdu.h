/* pdu.h -- CoAP message structure
 *
 * (c) 2010 Olaf Bergmann <bergmann@tzi.org>
 */

#ifndef _PDU_H_
#define _PDU_H_

/* pre-defined constants that reflect defaults for CoAP */

#define COAP_DEFAULT_RESPONSE_TIMEOUT  1 /* response timeout in seconds */
#define COAP_DEFAULT_MAX_RETRANSMIT    5 /* max number of retransmissions */
#define COAP_DEFAULT_PORT          61616 /* CoAP default UDP port */
#define COAP_DEFAULT_MAX_AGE          60 /* default maximum object lifetime in seconds */
#define COAP_MAX_PDU_SIZE           1400 /* maximum size of a CoAP PDU */

#define COAP_DEFAULT_VERSION           1 /* version of CoAP supported */
#define COAP_DEFAULT_URI_WELLKNOWN "/.wk/r" /* compact form of well-known resources URI */

/* CoAP message types */

#define COAP_MESSAGE_CON               0 /* confirmable message (requires ACK/RST) */
#define COAP_MESSAGE_NON               1 /* non-confirmable message (one-shot message) */
#define COAP_MESSAGE_ACK               2 /* used to acknowledge confirmable messages */
#define COAP_MESSAGE_RST               3 /* indicates error in received messages */

/* CoAP request methods */

#define COAP_REQUEST_GET       1
#define COAP_REQUEST_POST      2
#define COAP_REQUEST_PUT       3
#define COAP_REQUEST_DELETE    4

/* CoAP option types */

#define COAP_OPTION_URI_PATH     1 /* C, String, 1-270 B, "/" */
#define COAP_OPTION_MAXAGE       2 /* E, Duration, 1 B, 60 Seconds */
#define COAP_OPTION_URI_FULL     3 /* C, String, 1-270 B, "/" */
#define COAP_OPTION_ETAG         4 /* E, variable length, 1-4 B, - */
#define COAP_OPTION_CONTENT_TYPE 5 /* C, 8-bit uint, 1 B, 8 (text/plain) */

/* CoAP result codes */

#define COAP_RESPONSE_100       40   /* 100 Continue */
#define COAP_RESPONSE_200       80   /* 200 OK */
#define COAP_RESPONSE_201       81   /* 201 Created */
#define COAP_RESPONSE_304      124   /* 304 Not Modified */
#define COAP_RESPONSE_400      160   /* 400 Bad Request */
#define COAP_RESPONSE_404      164   /* 404 Not Found */
#define COAP_RESPONSE_405      165   /* 405 Method Not Allowed */
#define COAP_RESPONSE_415      175   /* 415 Unsupported Media Type */
#define COAP_RESPONSE_500      200   /* 500 Internal Server Error */
#define COAP_RESPONSE_504      204   /* 504 Gateway Timeout */

/* CoAP media type encoding */

#define COAP_MEDIATYPE_TEXT_XML                       0 /* text/xml */
#define COAP_MEDIATYPE_TEXT_CSV                       1 /* text/csv */
#define COAP_MEDIATYPE_TEXT_HTML                      3 /* text/html */
#define COAP_MEDIATYPE_IMAGE_GIF                     21 /* image/gif */
#define COAP_MEDIATYPE_IMAGE_JPEG                    22 /* image/jpeg */
#define COAP_MEDIATYPE_IMAGE_PNG                     23 /* image/png */
#define COAP_MEDIATYPE_IMAGE_TIFF                    24 /* image/tiff */
#define COAP_MEDIATYPE_AUDIO_RAW                     25 /* audio/raw */
#define COAP_MEDIATYPE_VIDEO_RAW                     26 /* video/raw */
#define COAP_MEDIATYPE_APPLICATION_LINK_FORMAT       40 /* application/link-format */
#define COAP_MEDIATYPE_APPLICATION_XML               41 /* application/xml */
#define COAP_MEDIATYPE_APPLICATION_OCTET_STREAM      42 /* application/octet-stream */
#define COAP_MEDIATYPE_APPLICATION_RDF_XML           43 /* application/rdf+xml */
#define COAP_MEDIATYPE_APPLICATION_SOAP_XML          44 /* application/soap+xml  */
#define COAP_MEDIATYPE_APPLICATION_ATOM_XML          45 /* application/atom+xml  */
#define COAP_MEDIATYPE_APPLICATION_XMPP_XML          46 /* application/xmpp+xml  */
#define COAP_MEDIATYPE_APPLICATION_EXI               47 /* application/exi  */
#define COAP_MEDIATYPE_APPLICATION_X_BXML            48 /* application/x-bxml  */
#define COAP_MEDIATYPE_APPLICATION_FASTINFOSET       49 /* application/fastinfoset  */
#define COAP_MEDIATYPE_APPLICATION_SOAP_FASTINFOSET  50 /* application/soap+fastinfoset  */
#define COAP_MEDIATYPE_APPLICATION_JSON              51 /* application/json  */


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

/* CoAP transaction id */
typedef unsigned short coap_tid_t; 
#define COAP_INVALID_TID 0

typedef struct {
  unsigned char version:2;	/* protocol version */
  unsigned char type:2;		/* type flag */
  unsigned char optcnt:4;	/* number of options following the header */
  unsigned char code:8;	        /* request method (value 1--10) or response code (value 40-255) */
  coap_tid_t id;		/* transaction id */
} coap_hdr_t;

typedef struct {
  unsigned char delta:4;        /* option type (expressed as delta) */
  unsigned char length:4;	/* number of option bytes (15 indicates extended form) */
  union {
    struct {			/* short form, to be used when length < 15 */
      unsigned char value[0];	/* 0--14 bytes options */
    } shortopt;
    struct {			/* extended form, to be used when lengt==15 */
      unsigned char length:8;	/* length - 15 */
      unsigned char value[0];	/* 15--270 bytes options */
    } longopt;
  } optval;
} coap_opt_t;

typedef struct {
  coap_hdr_t *hdr;
  unsigned short length;	/* PDU length (including header, options, data)  */
  unsigned char *data;		/* payload */
} coap_pdu_t;

/** 
 * Creates a new CoAP PDU. The object is created on the heap and must be released
 * using delete_pdu();
 */

coap_pdu_t *coap_new_pdu();
void coap_delete_pdu(coap_pdu_t *);

/** 
 * Adds option of given type to pdu that is passed as first parameter. coap_add_option() 
 * destroys the PDU's data, so coap_add_data must be called after all options have been
 * added.
 */

int coap_add_option(coap_pdu_t *pdu, unsigned char type, unsigned int len, const unsigned char *data);

/** 
 * Adds given data to the pdu that is passed as first parameter. Note that the PDU's 
 * data is destroyed by coap_add_option().
 */

int coap_add_data(coap_pdu_t *pdu, unsigned int len, const unsigned char *data);

#endif /* _PDU_H_ */
