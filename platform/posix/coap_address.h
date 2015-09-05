#include <assert.h>
#include <netinet/in.h>
#include <sys/socket.h>

struct coap_address_t {
  socklen_t size;           /**< size of addr */
  union {
    struct sockaddr         sa;
    struct sockaddr_storage st;
    struct sockaddr_in      sin;
    struct sockaddr_in6     sin6;
  } addr;
};


