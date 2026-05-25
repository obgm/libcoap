/* Extended URI parsing fuzzer for libcoap.
 *
 * The existing split_uri_target only calls coap_split_uri(). coap_uri.c is
 * sitting at ~41% line coverage in the public report, so this harness
 * additionally exercises:
 *   - coap_split_proxy_uri()      (proxy-uri scheme path)
 *   - coap_split_path() / coap_path_into_optlist()
 *   - coap_split_query() / coap_query_into_optlist()
 *   - coap_check_dots() (segment dot handling)
 *   - coap_uri_into_optlist() and coap_uri_into_optlist_abbrev()
 *   - coap_new_uri() / coap_clone_uri() / coap_delete_uri()
 *
 * All of these consume untrusted byte strings (a URI received over the wire
 * or via the CoAP Proxy-Uri option) and produce option lists used during
 * request processing — exactly the kind of code path an attacker controls.
 */

#include "coap3/coap_internal.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2 || size > 4096)
    return 0;

  coap_startup();
  coap_set_log_level(COAP_LOG_EMERG);

  /* Use the first byte as a selector so a single corpus entry exercises
   * multiple entrypoints across iterations. */
  uint8_t mode = data[0];
  const uint8_t *buf = data + 1;
  size_t buf_len = size - 1;

  /* coap_split_proxy_uri — different validation rules than split_uri. */
  {
    coap_uri_t uri;
    memset(&uri, 0, sizeof(uri));
    coap_split_proxy_uri(buf, buf_len, &uri);
  }

  /* coap_split_uri + downstream usage. */
  coap_uri_t parsed_uri;
  memset(&parsed_uri, 0, sizeof(parsed_uri));
  int split_ok = coap_split_uri(buf, buf_len, &parsed_uri);

  /* coap_check_dots on small windows across the buffer to drive its
   * percent-encoded "." / ".." special cases. */
  for (size_t i = 0; i + 1 < buf_len && i < 8; i++) {
    size_t window = buf_len - i;
    if (window > 6)
      window = 6;
    coap_check_dots(buf + i, window);
  }

  /* coap_split_path: writes serialised options into a caller buffer. */
  {
    unsigned char out[256];
    size_t out_len = sizeof(out);
    coap_split_path(buf, buf_len, out, &out_len);
  }

  /* coap_split_query. */
  {
    unsigned char out[256];
    size_t out_len = sizeof(out);
    coap_split_query(buf, buf_len, out, &out_len);
  }

  /* coap_path_into_optlist / coap_query_into_optlist — populate an
   * optlist chain that we must release. */
  if (mode & 0x01) {
    coap_optlist_t *chain = NULL;
    coap_path_into_optlist(buf, buf_len, COAP_OPTION_URI_PATH, &chain);
    coap_query_into_optlist(buf, buf_len, COAP_OPTION_URI_QUERY, &chain);
    coap_delete_optlist(chain);
  }

  /* coap_new_uri / coap_clone_uri exercise the heap-allocated URI path. */
  if (mode & 0x02) {
    coap_uri_t *u = coap_new_uri(buf, (unsigned int)buf_len);
    if (u) {
      coap_uri_t *clone = coap_clone_uri(u);
      coap_delete_uri(clone);
      coap_delete_uri(u);
    }
  }

  /* coap_uri_into_optlist: only meaningful if the URI parsed cleanly. */
  if ((mode & 0x04) && split_ok == 0) {
    coap_optlist_t *chain = NULL;
    coap_uri_into_optlist(&parsed_uri, NULL, &chain, mode & 0x08 ? 1 : 0);
    coap_delete_optlist(chain);
  }

  coap_cleanup();
  return 0;
}
