#define _POSIX_C_SOURCE 200809L
#include "coap3/coap_internal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
fuzz_handler(coap_resource_t *resource, coap_session_t *session,
             const coap_pdu_t *request, const coap_string_t *query,
             coap_pdu_t *response) {
  (void)resource;
  (void)session;
  (void)request;
  (void)query;
  response->code = COAP_RESPONSE_CODE(205);
}

static void
fuzz_put_handler(coap_resource_t *resource, coap_session_t *session,
                 const coap_pdu_t *request, const coap_string_t *query,
                 coap_pdu_t *response) {
  (void)resource;
  (void)session;
  (void)request;
  (void)query;
  response->code = COAP_RESPONSE_CODE(201);
}

/* Write fuzz data to a temporary file */
static int
write_fuzz_tmp(char *path_tmpl, const uint8_t *data, size_t size) {
  int fd = mkstemp(path_tmpl);
  if (fd < 0)
    return -1;
  if (size > 0) {
    ssize_t written = write(fd, data, size);
    (void)written;
  }
  close(fd);
  return 0;
}

/* Remove a file and its working copy */
static void
remove_tmp_pair(const char *path) {
  char tmp[256];
  remove(path);
  if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) < (int)sizeof(tmp))
    remove(tmp);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 4)
    return 0;

  if (!coap_observe_persist_is_supported())
    return 0;

  /* Split fuzz input across the three persist files */
  size_t obs_len = size / 3;
  size_t cnt_len = size / 3;
  size_t dyn_len = size - obs_len - cnt_len;

  char obs_path[] = "/tmp/fuzz_obs_XXXXXX";
  char cnt_path[] = "/tmp/fuzz_cnt_XXXXXX";
  char dyn_path[] = "/tmp/fuzz_dyn_XXXXXX";

  /* Write fuzz data to each persist file */
  if (write_fuzz_tmp(obs_path, data,           obs_len) < 0)
    return 0;
  if (write_fuzz_tmp(cnt_path, data + obs_len, cnt_len) < 0) {
    remove_tmp_pair(obs_path);
    return 0;
  }
  if (write_fuzz_tmp(dyn_path, data + obs_len + cnt_len, dyn_len) < 0) {
    remove_tmp_pair(obs_path);
    remove_tmp_pair(cnt_path);
    return 0;
  }

  coap_startup();
  coap_set_log_level(COAP_LOG_EMERG);

  coap_context_t *ctx = coap_new_context(NULL);
  if (!ctx)
    goto cleanup_files;

  /* Create a UDP endpoint for session lookup */
  coap_address_t addr;
  coap_address_init(&addr);
  addr.addr.sa.sa_family = AF_INET;
  coap_endpoint_t *ep = coap_new_endpoint(ctx, &addr, COAP_PROTO_UDP);
  if (!ep)
    goto cleanup_ctx;

  /* Create an observable resource */
  coap_resource_t *res = coap_resource_init(coap_make_str_const("obs"), 0);
  if (!res)
    goto cleanup_ctx;
  res->observable = 1;
  coap_register_request_handler(res, COAP_REQUEST_GET, fuzz_handler);
  coap_add_resource(ctx, res);

  /* Register an unknown resource handler */
  coap_resource_t *unknown = coap_resource_unknown_init(fuzz_put_handler);
  if (unknown)
    coap_add_resource(ctx, unknown);

  /* Load persisted state from the three files */
  coap_persist_startup(ctx, dyn_path, obs_path, cnt_path, 1);

  /* Create a client session for write-back callback exercises */
  coap_session_t *sess = coap_new_client_session(ctx, NULL, &addr,
                                                 COAP_PROTO_UDP);
  if (!sess)
    goto cleanup_persist;
  sess->endpoint = ep;

  /* Build a GET+OBSERVE PDU */
  coap_pdu_t *pdu = coap_pdu_init(COAP_MESSAGE_CON, COAP_REQUEST_CODE_GET,
                                  coap_new_message_id(sess), 256);
  if (pdu) {
    uint8_t obs_val = 0;
    coap_insert_option(pdu, COAP_OPTION_OBSERVE, 1, &obs_val);
    coap_add_option(pdu, COAP_OPTION_URI_PATH, 3, (const uint8_t *)"obs");

    size_t tok_len = (data[0] % 8) + 1;
    if (tok_len > size)
      tok_len = 1;
    coap_add_token(pdu, tok_len, data);

    /* Register a subscription and trigger the observe added callback */
    coap_lock_lock(goto cleanup_persist);
    coap_subscription_t *sub = coap_add_observer(res, sess, &pdu->actual_token,
                                                 pdu);
    coap_lock_unlock();
    if (sub) {
      coap_find_observer(res, sess, &pdu->actual_token);
      coap_touch_observer(ctx, sess, &pdu->actual_token);

      /* Trigger the counter tracking callback */
      coap_resource_notify_observers(res, NULL);

      if (data[1] & 0x01) {
        /* Delete the subscription and trigger the observe deleted callback */
        coap_lock_lock(return 0);
        coap_delete_observer(res, sess, &pdu->actual_token);
        coap_lock_unlock();
      }
    }

    /* Set the observe sequence number */
    coap_persist_set_observe_num(res, (uint32_t)data[2] << 8 | data[3]);

    coap_delete_pdu(pdu);
  }

cleanup_persist:
  /* Stop persist and disable callbacks */
  coap_persist_stop(ctx);

  /* Clear the endpoint pointer before context teardown */
  if (sess)
    sess->endpoint = NULL;

cleanup_ctx:
  coap_free_context(ctx);
  coap_cleanup();

cleanup_files:
  remove_tmp_pair(obs_path);
  remove_tmp_pair(cnt_path);
  remove_tmp_pair(dyn_path);

  return 0;
}
