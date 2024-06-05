/* coap_resource.c -- generic resource handling
 *
 * Copyright (C) 2010--2024 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file coap_resource.c
 * @brief Server resource handling functions
 */

#include "coap3/coap_libcoap_build.h"

#if COAP_SERVER_SUPPORT
#include <stdio.h>

#ifdef COAP_EPOLL_SUPPORT
#include <sys/epoll.h>
#include <sys/timerfd.h>
#endif /* COAP_EPOLL_SUPPORT */

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

/* Helper functions for conditional output of character sequences into
 * a given buffer. The first Offset characters are skipped.
 */

/**
 * Adds Char to Buf if Offset is zero. Otherwise, Char is not written
 * and Offset is decremented.
 */
#define PRINT_WITH_OFFSET(Buf,Offset,Char)                \
  if ((Offset) == 0) {                                        \
    (*(Buf)++) = (Char);                                \
  } else {                                                \
    (Offset)--;                                                \
  }                                                        \

/**
 * Adds Char to Buf if Offset is zero and Buf is less than Bufend.
 */
#define PRINT_COND_WITH_OFFSET(Buf,Bufend,Offset,Char,Result) {                \
    if ((Buf) < (Bufend)) {                                                \
      PRINT_WITH_OFFSET(Buf,Offset,Char);                                \
    }                                                                        \
    (Result)++;                                                                \
  }

/**
 * Copies at most Length characters of Str to Buf. The first Offset
 * characters are skipped. Output may be truncated to Bufend - Buf
 * characters.
 */
#define COPY_COND_WITH_OFFSET(Buf,Bufend,Offset,Str,Length,Result) {        \
    size_t i;                                                                \
    for (i = 0; i < (Length); i++) {                                        \
      PRINT_COND_WITH_OFFSET((Buf), (Bufend), (Offset), (Str)[i], (Result)); \
    }                                                                        \
  }

static int
match(const coap_str_const_t *text, const coap_str_const_t *pattern,
      int match_prefix, int match_substring) {
  assert(text);
  assert(pattern);

  if (text->length < pattern->length || !pattern->s)
    return 0;

  if (match_substring) {
    const uint8_t *next_token = text->s;
    size_t remaining_length = text->length;
    while (remaining_length) {
      size_t token_length;
      const uint8_t *token = next_token;
      next_token = (unsigned char *)memchr(token, ' ', remaining_length);

      if (next_token) {
        token_length = next_token - token;
        remaining_length -= (token_length + 1);
        next_token++;
      } else {
        token_length = remaining_length;
        remaining_length = 0;
      }

      if ((match_prefix || pattern->length == token_length) &&
          memcmp(token, pattern->s, pattern->length) == 0)
        return 1;
    }
    return 0;
  }

  return (match_prefix || pattern->length == text->length) &&
         memcmp(text->s, pattern->s, pattern->length) == 0;
}

COAP_API coap_print_status_t
coap_print_wellknown(coap_context_t *context, unsigned char *buf,
                     size_t *buflen, size_t offset,
                     const coap_string_t *query_filter) {
  coap_print_status_t result;
  coap_lock_lock(context, return COAP_PRINT_STATUS_ERROR);
  result = coap_print_wellknown_lkd(context, buf, buflen, offset, query_filter);
  coap_lock_unlock(context);
  return result;
}

static coap_str_const_t coap_default_uri_wellknown = {
  sizeof(COAP_DEFAULT_URI_WELLKNOWN)-1,
  (const uint8_t *)COAP_DEFAULT_URI_WELLKNOWN
};

coap_print_status_t
coap_print_wellknown_lkd(coap_context_t *context, unsigned char *buf,
                         size_t *buflen, size_t offset,
                         const coap_string_t *query_filter) {
  coap_print_status_t output_length = 0;
  unsigned char *p = buf;
  const uint8_t *bufend = buf + *buflen;
  size_t left, written = 0;
  coap_print_status_t result;
  const size_t old_offset = offset;
  int subsequent_resource = 0;
#ifdef WITHOUT_QUERY_FILTER
  (void)query_filter;
#else
  coap_str_const_t resource_param = { 0, NULL }, query_pattern = { 0, NULL };
  int flags = 0; /* MATCH_SUBSTRING, MATCH_PREFIX, MATCH_URI */
#define MATCH_URI       0x01
#define MATCH_PREFIX    0x02
#define MATCH_SUBSTRING 0x04
  static const coap_str_const_t _rt_attributes[] = {
    {2, (const uint8_t *)"rt"},
    {2, (const uint8_t *)"if"},
    {3, (const uint8_t *)"rel"},
    {0, NULL}
  };
#endif /* WITHOUT_QUERY_FILTER */

  coap_lock_check_locked(context);
#ifndef WITHOUT_QUERY_FILTER
  /* split query filter, if any */
  if (query_filter) {
    resource_param.s = query_filter->s;
    while (resource_param.length < query_filter->length &&
           resource_param.s[resource_param.length] != '=')
      resource_param.length++;

    if (resource_param.length < query_filter->length) {
      const coap_str_const_t *rt_attributes;
      if (resource_param.length == 4 &&
          memcmp(resource_param.s, "href", 4) == 0)
        flags |= MATCH_URI;

      for (rt_attributes = _rt_attributes; rt_attributes->s; rt_attributes++) {
        if (resource_param.length == rt_attributes->length &&
            memcmp(resource_param.s, rt_attributes->s, rt_attributes->length) == 0) {
          flags |= MATCH_SUBSTRING;
          break;
        }
      }

      /* rest is query-pattern */
      query_pattern.s =
          query_filter->s + resource_param.length + 1;

      assert((resource_param.length + 1) <= query_filter->length);
      query_pattern.length =
          query_filter->length - (resource_param.length + 1);

      if ((query_pattern.s[0] == '/') && ((flags & MATCH_URI) == MATCH_URI)) {
        query_pattern.s++;
        query_pattern.length--;
      }

      if (query_pattern.length &&
          query_pattern.s[query_pattern.length-1] == '*') {
        query_pattern.length--;
        flags |= MATCH_PREFIX;
      }
    }
  }
#endif /* WITHOUT_QUERY_FILTER */

  RESOURCES_ITER(context->resources, r) {

    if (coap_string_equal(r->uri_path, &coap_default_uri_wellknown)) {
      /* server app has defined a resource for .well-known/core - ignore */
      continue;
    }
#ifndef WITHOUT_QUERY_FILTER
    if (resource_param.length) { /* there is a query filter */

      if (flags & MATCH_URI) {        /* match resource URI */
        if (!match(r->uri_path, &query_pattern, (flags & MATCH_PREFIX) != 0,
                   (flags & MATCH_SUBSTRING) != 0))
          continue;
      } else {                        /* match attribute */
        coap_attr_t *attr;
        coap_str_const_t unquoted_val;
        attr = coap_find_attr(r, &resource_param);
        if (!attr || !attr->value)
          continue;
        unquoted_val = *attr->value;
        if (attr->value->s[0] == '"') {          /* if attribute has a quoted value, remove double quotes */
          unquoted_val.length -= 2;
          unquoted_val.s += 1;
        }
        if (!(match(&unquoted_val, &query_pattern,
                    (flags & MATCH_PREFIX) != 0,
                    (flags & MATCH_SUBSTRING) != 0)))
          continue;
      }
    }
#endif /* WITHOUT_QUERY_FILTER */

    if (!subsequent_resource) {        /* this is the first resource  */
      subsequent_resource = 1;
    } else {
      PRINT_COND_WITH_OFFSET(p, bufend, offset, ',', written);
    }

    left = bufend - p; /* calculate available space */
    result = coap_print_link(r, p, &left, &offset);

    if (result & COAP_PRINT_STATUS_ERROR) {
      break;
    }

    /* coap_print_link() returns the number of characters that
     * where actually written to p. Now advance to its end. */
    p += COAP_PRINT_OUTPUT_LENGTH(result);
    written += left;
  }

  *buflen = written;
  output_length = (coap_print_status_t)(p - buf);

  if (output_length > COAP_PRINT_STATUS_MAX) {
    return COAP_PRINT_STATUS_ERROR;
  }

  result = (coap_print_status_t)output_length;

  if (result + old_offset - offset < *buflen) {
    result |= COAP_PRINT_STATUS_TRUNC;
  }
  return result;
}

static coap_str_const_t null_path_value = {0, (const uint8_t *)""};
static coap_str_const_t *null_path = &null_path_value;

coap_resource_t *
coap_resource_init(coap_str_const_t *uri_path, int flags) {
  coap_resource_t *r;

  r = (coap_resource_t *)coap_malloc_type(COAP_RESOURCE, sizeof(coap_resource_t));
  if (r) {
    memset(r, 0, sizeof(coap_resource_t));

    if (!(flags & COAP_RESOURCE_FLAGS_RELEASE_URI)) {
      /* Need to take a copy if caller is not providing a release request */
      if (uri_path)
        uri_path = coap_new_str_const(uri_path->s, uri_path->length);
      else
        uri_path = coap_new_str_const(null_path->s, null_path->length);
    } else if (!uri_path) {
      /* Do not expect this, but ... */
      uri_path = coap_new_str_const(null_path->s, null_path->length);
    }

    if (uri_path)
      r->uri_path = uri_path;

    r->flags = flags;
    r->observe = 2;
  } else {
    coap_log_debug("coap_resource_init: no memory left\n");
  }

  return r;
}

static const uint8_t coap_unknown_resource_uri[] =
    "- Unknown -";

coap_resource_t *
coap_resource_unknown_init2(coap_method_handler_t put_handler, int flags) {
  coap_resource_t *r;

  r = (coap_resource_t *)coap_malloc_type(COAP_RESOURCE, sizeof(coap_resource_t));
  if (r) {
    memset(r, 0, sizeof(coap_resource_t));
    r->is_unknown = 1;
    /* Something unlikely to be used, but it shows up in the logs */
    r->uri_path = coap_new_str_const(coap_unknown_resource_uri, sizeof(coap_unknown_resource_uri)-1);
    r->flags = flags & ~COAP_RESOURCE_FLAGS_RELEASE_URI;
    coap_register_handler(r, COAP_REQUEST_PUT, put_handler);
  } else {
    coap_log_debug("coap_resource_unknown_init: no memory left\n");
  }

  return r;
}

coap_resource_t *
coap_resource_unknown_init(coap_method_handler_t put_handler) {
  return coap_resource_unknown_init2(put_handler, 0);
}

static const uint8_t coap_proxy_resource_uri[] =
    "- Proxy URI -";

coap_resource_t *
coap_resource_proxy_uri_init2(coap_method_handler_t handler,
                              size_t host_name_count,
                              const char *host_name_list[], int flags) {
  coap_resource_t *r;

  if (host_name_count == 0) {
    coap_log_err("coap_resource_proxy_uri_init: Must have one or more host names defined\n");
    return NULL;
  }
  r = (coap_resource_t *)coap_malloc_type(COAP_RESOURCE, sizeof(coap_resource_t));
  if (r) {
    size_t i;
    memset(r, 0, sizeof(coap_resource_t));
    r->is_proxy_uri = 1;
    /* Something unlikely to be used, but it shows up in the logs */
    r->uri_path = coap_new_str_const(coap_proxy_resource_uri, sizeof(coap_proxy_resource_uri)-1);
    /* Preset all the handlers */
    for (i = 0; i < (sizeof(r->handler) / sizeof(r->handler[0])); i++) {
      r->handler[i] = handler;
    }
    if (host_name_count) {
      r->proxy_name_list = coap_malloc_type(COAP_STRING, host_name_count *
                                            sizeof(coap_str_const_t *));
      if (r->proxy_name_list) {
        for (i = 0; i < host_name_count; i++) {
          r->proxy_name_list[i] =
              coap_new_str_const((const uint8_t *)host_name_list[i],
                                 strlen(host_name_list[i]));
          if (!r->proxy_name_list[i]) {
            coap_log_err("coap_resource_proxy_uri_init: unable to add host name\n");
            if (i == 0) {
              coap_free_type(COAP_STRING, r->proxy_name_list);
              r->proxy_name_list = NULL;
            }
            break;
          }
        }
        r->proxy_name_count = i;
      }
    }
    r->flags = flags & ~COAP_RESOURCE_FLAGS_RELEASE_URI;
  } else {
    coap_log_debug("coap_resource_proxy_uri_init2: no memory left\n");
  }

  return r;
}

coap_resource_t *
coap_resource_proxy_uri_init(coap_method_handler_t handler,
                             size_t host_name_count, const char *host_name_list[]) {
  return coap_resource_proxy_uri_init2(handler, host_name_count,
                                       host_name_list, 0);
}

coap_attr_t *
coap_add_attr(coap_resource_t *resource,
              coap_str_const_t *name,
              coap_str_const_t *val,
              int flags) {
  coap_attr_t *attr;

  if (!resource || !name)
    return NULL;
  attr = (coap_attr_t *)coap_malloc_type(COAP_RESOURCEATTR, sizeof(coap_attr_t));

  if (attr) {
    if (!(flags & COAP_ATTR_FLAGS_RELEASE_NAME)) {
      /* Need to take a copy if caller is not providing a release request */
      name = coap_new_str_const(name->s, name->length);
    }
    attr->name = name;
    if (val) {
      if (!(flags & COAP_ATTR_FLAGS_RELEASE_VALUE)) {
        /* Need to take a copy if caller is not providing a release request */
        val = coap_new_str_const(val->s, val->length);
      }
    }
    attr->value = val;

    attr->flags = flags;

    /* add attribute to resource list */
    LL_PREPEND(resource->link_attr, attr);
  } else {
    coap_log_debug("coap_add_attr: no memory left\n");
  }

  return attr;
}

coap_attr_t *
coap_find_attr(coap_resource_t *resource,
               coap_str_const_t *name) {
  coap_attr_t *attr;

  if (!resource || !name)
    return NULL;

  LL_FOREACH(resource->link_attr, attr) {
    if (attr->name->length == name->length &&
        memcmp(attr->name->s, name->s, name->length) == 0)
      return attr;
  }

  return NULL;
}

coap_str_const_t *
coap_attr_get_value(coap_attr_t *attr) {
  if (attr)
    return attr->value;
  return NULL;
}

void
coap_delete_attr(coap_attr_t *attr) {
  if (!attr)
    return;
  coap_delete_str_const(attr->name);
  if (attr->value) {
    coap_delete_str_const(attr->value);
  }

  coap_free_type(COAP_RESOURCEATTR, attr);
}

typedef enum coap_deleting_resource_t {
  COAP_DELETING_RESOURCE,
  COAP_NOT_DELETING_RESOURCE
} coap_deleting_resource_t;

static void coap_notify_observers(coap_context_t *context, coap_resource_t *r,
                                  coap_deleting_resource_t deleting);

static void
coap_free_resource(coap_resource_t *resource) {
  coap_attr_t *attr, *tmp;
  coap_subscription_t *obs, *otmp;

  assert(resource);

  if (!resource->context->observe_no_clear) {
    coap_resource_notify_observers_lkd(resource, NULL);
    coap_notify_observers(resource->context, resource, COAP_DELETING_RESOURCE);
  }

  if (resource->context->resource_deleted)
    resource->context->resource_deleted(resource->context, resource->uri_path,
                                        resource->context->observe_user_data);

  if (resource->context->release_userdata && resource->user_data)
    resource->context->release_userdata(resource->user_data);

  /* delete registered attributes */
  LL_FOREACH_SAFE(resource->link_attr, attr, tmp) coap_delete_attr(attr);

  /* Either the application provided or libcoap copied - need to delete it */
  coap_delete_str_const(resource->uri_path);

  /* free all elements from resource->subscribers */
  LL_FOREACH_SAFE(resource->subscribers, obs, otmp) {
    if (resource->context->observe_deleted)
      resource->context->observe_deleted(obs->session, obs,
                                         resource->context->observe_user_data);
    coap_session_release_lkd(obs->session);
    coap_delete_pdu(obs->pdu);
    coap_delete_cache_key(obs->cache_key);
    coap_free_type(COAP_SUBSCRIPTION, obs);
  }
  if (resource->proxy_name_count && resource->proxy_name_list) {
    size_t i;

    for (i = 0; i < resource->proxy_name_count; i++) {
      coap_delete_str_const(resource->proxy_name_list[i]);
    }
    coap_free_type(COAP_STRING, resource->proxy_name_list);
  }

  coap_free_type(COAP_RESOURCE, resource);
}

COAP_API void
coap_add_resource(coap_context_t *context, coap_resource_t *resource) {
  coap_lock_lock(context, return);
  coap_add_resource_lkd(context, resource);
  coap_lock_unlock(context);
}

void
coap_add_resource_lkd(coap_context_t *context, coap_resource_t *resource) {
  coap_lock_check_locked(context);
  if (resource->is_unknown) {
    if (context->unknown_resource)
      coap_free_resource(context->unknown_resource);
    context->unknown_resource = resource;
  } else if (resource->is_proxy_uri) {
    if (context->proxy_uri_resource)
      coap_free_resource(context->proxy_uri_resource);
    context->proxy_uri_resource = resource;
  } else {
    coap_resource_t *r = coap_get_resource_from_uri_path_lkd(context,
                                                             resource->uri_path);

    if (r) {
      coap_log_warn("coap_add_resource: Duplicate uri_path '%*.*s', old resource deleted\n",
                    (int)resource->uri_path->length, (int)resource->uri_path->length,
                    resource->uri_path->s);
      coap_delete_resource_lkd(context, r);
    }
    RESOURCES_ADD(context->resources, resource);
#if COAP_WITH_OBSERVE_PERSIST
    if (context->unknown_pdu && context->dyn_resource_save_file &&
        context->dyn_resource_added && resource->observable) {
      coap_bin_const_t raw_packet;

      raw_packet.s = context->unknown_pdu->token -
                     context->unknown_pdu->hdr_size;
      raw_packet.length = context->unknown_pdu->used_size +
                          context->unknown_pdu->hdr_size;
      context->dyn_resource_added(context->unknown_session, resource->uri_path,
                                  &raw_packet, context->observe_user_data);
    }
#endif /* COAP_WITH_OBSERVE_PERSIST */
  }
  assert(resource->context == NULL);
  resource->context = context;
}

COAP_API int
coap_delete_resource(coap_context_t *context, coap_resource_t *resource) {
  int ret;

  if (!resource)
    return 0;

  context = resource->context;
  if (context) {
    coap_lock_lock(context, return 0);
    ret = coap_delete_resource_lkd(context, resource);
    coap_lock_unlock(context);
  } else {
    ret = coap_delete_resource_lkd(context, resource);
  }
  return ret;
}

/*
 * Input context is ignored, but param left there to keep API consistent
 */
int
coap_delete_resource_lkd(coap_context_t *context, coap_resource_t *resource) {
  if (!resource)
    return 0;

  context = resource->context;
  if (context) {
    coap_lock_check_locked(context);
  }

  if (resource->is_unknown) {
    if (context && context->unknown_resource == resource) {
      context->unknown_resource = NULL;
    }
  } else if (resource->is_proxy_uri) {
    if (context && context->proxy_uri_resource == resource) {
      context->proxy_uri_resource = NULL;
    }
  } else if (context) {
    /* remove resource from list */
    RESOURCES_DELETE(context->resources, resource);
  }

  /* and free its allocated memory */
  coap_free_resource(resource);

  return 1;
}

void
coap_delete_all_resources(coap_context_t *context) {
  coap_resource_t *res;
  coap_resource_t *rtmp;

  /* Cannot call RESOURCES_ITER because coap_free_resource() releases
   * the allocated storage. */

  HASH_ITER(hh, context->resources, res, rtmp) {
    HASH_DELETE(hh, context->resources, res);
    coap_free_resource(res);
  }

  context->resources = NULL;

  if (context->unknown_resource) {
    coap_free_resource(context->unknown_resource);
    context->unknown_resource = NULL;
  }
  if (context->proxy_uri_resource) {
    coap_free_resource(context->proxy_uri_resource);
    context->proxy_uri_resource = NULL;
  }
}

COAP_API coap_resource_t *
coap_get_resource_from_uri_path(coap_context_t *context, coap_str_const_t *uri_path) {
  coap_resource_t *result;

  coap_lock_lock(context, return NULL);
  result = coap_get_resource_from_uri_path_lkd(context, uri_path);
  coap_lock_unlock(context);

  return result;
}

coap_resource_t *
coap_get_resource_from_uri_path_lkd(coap_context_t *context,
                                    coap_str_const_t *uri_path) {
  coap_resource_t *result;

  coap_lock_check_locked(context);

  RESOURCES_FIND(context->resources, uri_path, result);

  return result;
}

coap_print_status_t
coap_print_link(const coap_resource_t *resource,
                unsigned char *buf, size_t *len, size_t *offset) {
  unsigned char *p = buf;
  const uint8_t *bufend = buf + *len;
  coap_attr_t *attr;
  coap_print_status_t result = 0;
  coap_print_status_t output_length = 0;
  const size_t old_offset = *offset;

  *len = 0;
  PRINT_COND_WITH_OFFSET(p, bufend, *offset, '<', *len);
  PRINT_COND_WITH_OFFSET(p, bufend, *offset, '/', *len);

  COPY_COND_WITH_OFFSET(p, bufend, *offset,
                        resource->uri_path->s, resource->uri_path->length, *len);

  PRINT_COND_WITH_OFFSET(p, bufend, *offset, '>', *len);

  LL_FOREACH(resource->link_attr, attr) {

    PRINT_COND_WITH_OFFSET(p, bufend, *offset, ';', *len);

    COPY_COND_WITH_OFFSET(p, bufend, *offset,
                          attr->name->s, attr->name->length, *len);

    if (attr->value && attr->value->s) {
      PRINT_COND_WITH_OFFSET(p, bufend, *offset, '=', *len);

      COPY_COND_WITH_OFFSET(p, bufend, *offset,
                            attr->value->s, attr->value->length, *len);
    }

  }
  if (resource->observable) {
    COPY_COND_WITH_OFFSET(p, bufend, *offset, ";obs", 4, *len);
  }

#if COAP_OSCORE_SUPPORT
  /* If oscore is enabled */
  if (resource->flags & COAP_RESOURCE_FLAGS_OSCORE_ONLY)
    COPY_COND_WITH_OFFSET(p, bufend, *offset, ";osc", 4, *len);
#endif /* COAP_OSCORE_SUPPORT */

  output_length = (coap_print_status_t)(p - buf);

  if (output_length > COAP_PRINT_STATUS_MAX) {
    return COAP_PRINT_STATUS_ERROR;
  }

  result = (coap_print_status_t)output_length;

  if (result + old_offset - *offset < *len) {
    result |= COAP_PRINT_STATUS_TRUNC;
  }

  return result;
}

void
coap_register_handler(coap_resource_t *resource,
                      coap_request_t method,
                      coap_method_handler_t handler) {
  coap_register_request_handler(resource, method, handler);
}

void
coap_register_request_handler(coap_resource_t *resource,
                              coap_request_t method,
                              coap_method_handler_t handler) {
  assert(resource);
  assert(method > 0 && (size_t)(method-1) <
         sizeof(resource->handler)/sizeof(coap_method_handler_t));
  resource->handler[method-1] = handler;
}

coap_subscription_t *
coap_find_observer(coap_resource_t *resource, coap_session_t *session,
                   const coap_bin_const_t *token) {
  coap_subscription_t *s;

  assert(resource);
  assert(session);

  LL_FOREACH(resource->subscribers, s) {
    if (s->session == session &&
        (!token || coap_binary_equal(token, &s->pdu->actual_token)))
      return s;
  }

  return NULL;
}

static coap_subscription_t *
coap_find_observer_cache_key(coap_resource_t *resource, coap_session_t *session,
                             const coap_cache_key_t *cache_key) {
  coap_subscription_t *s;

  assert(resource);
  assert(session);

  LL_FOREACH(resource->subscribers, s) {
    if (s->session == session
        && (memcmp(cache_key, s->cache_key, sizeof(coap_cache_key_t)) == 0))
      return s;
  }

  return NULL;
}

/* https://rfc-editor.org/rfc/rfc7641#section-3.6 */
static const uint16_t cache_ignore_options[] = { COAP_OPTION_ETAG,
                                                 COAP_OPTION_OSCORE
                                               };
coap_subscription_t *
coap_add_observer(coap_resource_t *resource,
                  coap_session_t *session,
                  const coap_bin_const_t *token,
                  const coap_pdu_t *request) {
  coap_subscription_t *s;
  coap_cache_key_t *cache_key = NULL;
  size_t len;
  const uint8_t *data;

  assert(session);

  /* Check if there is already a subscription for this peer. */
  s = coap_find_observer(resource, session, token);
  if (!s) {
    /*
     * Cannot allow a duplicate to be created for the same query as application
     * may not be cleaning up duplicates.  If duplicate found, then original
     * observer is deleted and a new one created with the new token
     */
    cache_key = coap_cache_derive_key_w_ignore(session, request,
                                               COAP_CACHE_IS_SESSION_BASED,
                                               cache_ignore_options,
                                               sizeof(cache_ignore_options)/sizeof(cache_ignore_options[0]));
    if (cache_key) {
      s = coap_find_observer_cache_key(resource, session, cache_key);
      if (s) {
        /* Delete old entry with old token */
        coap_delete_observer(resource, session, &s->pdu->actual_token);
        s = NULL;
      }
    }
  }

  /* We are done if subscription was found. */
  if (s) {
    return s;
  }

  /* Check if there is already maximum number of subscribers present */
#if (COAP_RESOURCE_MAX_SUBSCRIBER > 0)
  uint32_t subscriber_count = 0;
  LL_COUNT(resource->subscribers, s, subscriber_count);
  if (subscriber_count >= COAP_RESOURCE_MAX_SUBSCRIBER) {
    return NULL; /* Signal error */
  }
#endif /* COAP_RESOURCE_MAX_SUBSCRIBER */

  /* Create a new subscription */
  s = coap_malloc_type(COAP_SUBSCRIPTION, sizeof(coap_subscription_t));

  if (!s) {
    coap_delete_cache_key(cache_key);
    return NULL;
  }

  coap_subscription_init(s);
  s->pdu = coap_pdu_duplicate_lkd(request, session, token->length,
                                  token->s, NULL);
  if (s->pdu == NULL) {
    coap_delete_cache_key(cache_key);
    coap_free_type(COAP_SUBSCRIPTION, s);
    return NULL;
  }
  if (coap_get_data(request, &len, &data)) {
    /* This could be a large bodied FETCH */
    s->pdu->max_size = 0;
    coap_add_data(s->pdu, len, data);
  }
  if (cache_key == NULL) {
    cache_key = coap_cache_derive_key_w_ignore(session, request,
                                               COAP_CACHE_IS_SESSION_BASED,
                                               cache_ignore_options,
                                               sizeof(cache_ignore_options)/sizeof(cache_ignore_options[0]));
    if (cache_key == NULL) {
      coap_delete_pdu(s->pdu);
      coap_delete_cache_key(cache_key);
      coap_free_type(COAP_SUBSCRIPTION, s);
      return NULL;
    }
  }
  s->cache_key = cache_key;
  s->session = coap_session_reference_lkd(session);

  /* add subscriber to resource */
  LL_PREPEND(resource->subscribers, s);

  coap_log_debug("create new subscription %p key 0x%02x%02x%02x%02x\n",
                 (void *)s, s->cache_key->key[0], s->cache_key->key[1],
                 s->cache_key->key[2], s->cache_key->key[3]);

  if (session->context->observe_added && session->proto == COAP_PROTO_UDP) {
    coap_bin_const_t raw_packet;
    coap_bin_const_t *oscore_info = NULL;
#if COAP_OSCORE_SUPPORT
    oscore_association_t *association;

    if (session->recipient_ctx && session->recipient_ctx->recipient_id) {
      /*
       * Need to track the association used for tracking this observe, done as
       * a CBOR array. Read in coap_persist_observe_add().
       *
       * If an entry is null, then use nil, else a set of bytes
       *
       * Currently tracking 5 items
       *  recipient_id
       *  id_context
       *  aad        (from oscore_association_t)
       *  partial_iv (from oscore_association_t)
       *  nonce      (from oscore_association_t)
       */
      uint8_t info_buffer[60];
      uint8_t *info_buf = info_buffer;
      size_t info_len = sizeof(info_buffer);
      size_t ret = 0;
      coap_bin_const_t ctoken = { token->length, token->s };

      ret += oscore_cbor_put_array(&info_buf, &info_len, 5);
      ret += oscore_cbor_put_bytes(&info_buf,
                                   &info_len,
                                   session->recipient_ctx->recipient_id->s,
                                   session->recipient_ctx->recipient_id->length);
      if (session->recipient_ctx->osc_ctx &&
          session->recipient_ctx->osc_ctx->id_context) {
        ret += oscore_cbor_put_bytes(&info_buf,
                                     &info_len,
                                     session->recipient_ctx->osc_ctx->id_context->s,
                                     session->recipient_ctx->osc_ctx->id_context->length);
      } else {
        ret += oscore_cbor_put_nil(&info_buf, &info_len);
      }
      association = oscore_find_association(session, &ctoken);
      if (association) {
        if (association->aad) {
          ret += oscore_cbor_put_bytes(&info_buf,
                                       &info_len,
                                       association->aad->s,
                                       association->aad->length);
        } else {
          ret += oscore_cbor_put_nil(&info_buf, &info_len);
        }
        if (association->partial_iv) {
          ret += oscore_cbor_put_bytes(&info_buf,
                                       &info_len,
                                       association->partial_iv->s,
                                       association->partial_iv->length);
        } else {
          ret += oscore_cbor_put_nil(&info_buf, &info_len);
        }
        if (association->nonce) {
          ret += oscore_cbor_put_bytes(&info_buf,
                                       &info_len,
                                       association->nonce->s,
                                       association->nonce->length);
        } else {
          ret += oscore_cbor_put_nil(&info_buf, &info_len);
        }
      } else {
        ret += oscore_cbor_put_nil(&info_buf, &info_len);
        ret += oscore_cbor_put_nil(&info_buf, &info_len);
      }
      oscore_info = coap_new_bin_const(info_buffer, ret);
    }
#endif /* COAP_OSCORE_SUPPORT */

    /* s->pdu header is not currently encoded */
    memcpy(s->pdu->token - request->hdr_size,
           request->token - request->hdr_size, request->hdr_size);
    raw_packet.s = s->pdu->token - request->hdr_size;
    raw_packet.length = s->pdu->used_size + request->hdr_size;
    session->context->observe_added(session, s, session->proto,
                                    &session->endpoint->bind_addr,
                                    &session->addr_info,
                                    &raw_packet,
                                    oscore_info,
                                    session->context->observe_user_data);
#if COAP_OSCORE_SUPPORT
    coap_delete_bin_const(oscore_info);
#endif /* COAP_OSCORE_SUPPORT */
  }
  if (resource->context->track_observe_value) {
    /* Track last used observe value (as app handler is called) */
    resource->context->track_observe_value(resource->context,resource->uri_path,
                                           resource->observe,
                                           resource->context->observe_user_data);
  }

  return s;
}

void
coap_touch_observer(coap_context_t *context, coap_session_t *session,
                    const coap_bin_const_t *token) {
  coap_subscription_t *s;

  RESOURCES_ITER(context->resources, r) {
    s = coap_find_observer(r, session, token);
    if (s) {
      s->fail_cnt = 0;
    }
  }
}

static void
coap_delete_observer_internal(coap_resource_t *resource, coap_session_t *session,
                              coap_subscription_t *s) {
  if (!s)
    return;

  if (coap_get_log_level() >= COAP_LOG_DEBUG) {
    char outbuf[2 * 8 + 1] = "";
    unsigned int i;

    for (i = 0; i < s->pdu->actual_token.length; i++) {
      size_t size = strlen(outbuf);

      snprintf(&outbuf[size], sizeof(outbuf)-size, "%02x",
               s->pdu->actual_token.s[i]);
    }
    coap_log_debug("removed subscription %p with token '%s' key 0x%02x%02x%02x%02x\n",
                   (void *)s, outbuf, s->cache_key->key[0], s->cache_key->key[1],
                   s->cache_key->key[2], s-> cache_key->key[3]);
  }
  if (session->context->observe_deleted)
    session->context->observe_deleted(session, s,
                                      session->context->observe_user_data);

  if (resource->subscribers) {
    LL_DELETE(resource->subscribers, s);
    coap_session_release_lkd(session);
    coap_delete_pdu(s->pdu);
    coap_delete_cache_key(s->cache_key);
    coap_free_type(COAP_SUBSCRIPTION, s);
  }

  return;
}

int
coap_delete_observer(coap_resource_t *resource, coap_session_t *session,
                     const coap_bin_const_t *token) {
  coap_subscription_t *s;

  s = coap_find_observer(resource, session, token);
  if (s)
    coap_delete_observer_internal(resource, session, s);

  return s != NULL;
}

int
coap_delete_observer_request(coap_resource_t *resource, coap_session_t *session,
                             const coap_bin_const_t *token, coap_pdu_t *request) {
  coap_subscription_t *s;
  int ret = 0;

  s = coap_find_observer(resource, session, token);
  s = NULL;
  if (!s) {
    /*
     * It is possible that the client is using the wrong token.
     * An example being a large FETCH spanning multiple blocks.
     */
    coap_cache_key_t *cache_key;

    cache_key = coap_cache_derive_key_w_ignore(session, request,
                                               COAP_CACHE_IS_SESSION_BASED,
                                               cache_ignore_options,
                                               sizeof(cache_ignore_options)/sizeof(cache_ignore_options[0]));
    if (cache_key) {
      s = coap_find_observer_cache_key(resource, session, cache_key);
      if (s) {
        /* Delete entry with setup token */
        ret = coap_delete_observer(resource, session, &s->pdu->actual_token);
      }
      coap_delete_cache_key(cache_key);
    }
  } else {
    coap_delete_observer_internal(resource, session, s);
    ret = 1;
  }
  return ret;
}

void
coap_delete_observers(coap_context_t *context, coap_session_t *session) {
  RESOURCES_ITER(context->resources, resource) {
    coap_subscription_t *s, *tmp;
    LL_FOREACH_SAFE(resource->subscribers, s, tmp) {
      if (s->session == session) {
        if (context->observe_deleted)
          context->observe_deleted(session, s, context->observe_user_data);
        assert(resource->subscribers);
        LL_DELETE(resource->subscribers, s);
        coap_session_release_lkd(session);
        coap_delete_pdu(s->pdu);
        coap_delete_cache_key(s->cache_key);
        coap_free_type(COAP_SUBSCRIPTION, s);
      }
    }
  }
}

static void
coap_notify_observers(coap_context_t *context, coap_resource_t *r,
                      coap_deleting_resource_t deleting) {
  coap_method_handler_t h;
  coap_subscription_t *obs, *otmp;
  coap_pdu_t *response;
  uint8_t buf[4];
  coap_string_t *query;
  coap_block_b_t block;
  coap_tick_t now;
  coap_session_t *obs_session;

  if (r->observable && (r->dirty || r->partiallydirty)) {
    r->partiallydirty = 0;

    LL_FOREACH_SAFE(r->subscribers, obs, otmp) {
      obs_session = obs->session;
      if (r->dirty == 0 && obs->dirty == 0) {
        /*
         * running this resource due to partiallydirty, but this observation's
         * notification was already enqueued
         */
        context->observe_pending = 1;
        continue;
      }
      if (obs->session->con_active >= COAP_NSTART(obs->session) &&
          ((r->flags & COAP_RESOURCE_FLAGS_NOTIFY_CON) ||
           (obs->non_cnt >= COAP_OBS_MAX_NON))) {
        /* Waiting for the previous unsolicited response to finish */
        r->partiallydirty = 1;
        obs->dirty = 1;
        context->observe_pending = 1;
        continue;
      }
      coap_ticks(&now);
      if (obs->session->lg_xmit && obs->session->lg_xmit->last_all_sent == 0 &&
          obs->session->lg_xmit->last_obs &&
          (obs->session->lg_xmit->last_obs + 2*COAP_TICKS_PER_SECOND) > now) {
        /* Waiting for the previous blocked unsolicited response to finish */
        r->partiallydirty = 1;
        obs->dirty = 1;
        context->observe_pending = 1;
        continue;
      }

      coap_mid_t mid = COAP_INVALID_MID;
      obs->dirty = 0;
      /* initialize response */
      response = coap_pdu_init(COAP_MESSAGE_CON, 0, 0,
                               coap_session_max_pdu_size_lkd(obs->session));
      if (!response) {
        obs->dirty = 1;
        r->partiallydirty = 1;
        context->observe_pending = 1;
        coap_log_debug("coap_check_notify: pdu init failed, resource stays "
                       "partially dirty\n");
        continue;
      }

      if (!coap_add_token(response, obs->pdu->actual_token.length,
                          obs->pdu->actual_token.s)) {
        obs->dirty = 1;
        r->partiallydirty = 1;
        context->observe_pending = 1;
        coap_log_debug("coap_check_notify: cannot add token, resource stays "
                       "partially dirty\n");
        coap_delete_pdu(response);
        continue;
      }

      obs->pdu->mid = response->mid = coap_new_message_id_lkd(obs->session);
      /* A lot of the reliable code assumes type is CON */
      if (COAP_PROTO_NOT_RELIABLE(obs->session->proto) &&
          (r->flags & COAP_RESOURCE_FLAGS_NOTIFY_CON) == 0 &&
          ((r->flags & COAP_RESOURCE_FLAGS_NOTIFY_NON_ALWAYS) ||
           obs->non_cnt < COAP_OBS_MAX_NON)) {
        response->type = COAP_MESSAGE_NON;
      } else {
        response->type = COAP_MESSAGE_CON;
      }
      switch (deleting) {
      case COAP_NOT_DELETING_RESOURCE:
        /* fill with observer-specific data */
        coap_add_option_internal(response, COAP_OPTION_OBSERVE,
                                 coap_encode_var_safe(buf, sizeof(buf),
                                                      r->observe),
                                 buf);
        if (coap_get_block_b(obs->session, obs->pdu, COAP_OPTION_BLOCK2,
                             &block)) {
          /* Will get updated later (e.g. M bit) if appropriate */
          coap_add_option_internal(response, COAP_OPTION_BLOCK2,
                                   coap_encode_var_safe(buf, sizeof(buf),
                                                        ((0 << 4) |
                                                         (0 << 3) |
                                                         block.aszx)),
                                   buf);
        }
#if COAP_Q_BLOCK_SUPPORT
        else if (coap_get_block_b(obs->session, obs->pdu, COAP_OPTION_Q_BLOCK2,
                                  &block)) {
          /* Will get updated later (e.g. M bit) if appropriate */
          coap_add_option_internal(response, COAP_OPTION_Q_BLOCK2,
                                   coap_encode_var_safe(buf, sizeof(buf),
                                                        ((0 << 4) |
                                                         (0 << 3) |
                                                         block.szx)),
                                   buf);
        }
#endif /* COAP_Q_BLOCK_SUPPORT */

        h = r->handler[obs->pdu->code - 1];
        assert(h);      /* we do not allow subscriptions if no
                         * GET/FETCH handler is defined */
        query = coap_get_query(obs->pdu);
        coap_log_debug("Observe PDU presented to app.\n");
        coap_show_pdu(COAP_LOG_DEBUG, obs->pdu);
        coap_log_debug("call custom handler for resource '%*.*s' (4)\n",
                       (int)r->uri_path->length, (int)r->uri_path->length,
                       r->uri_path->s);
        coap_lock_callback_release(obs->session->context,
                                   h(r, obs->session, obs->pdu, query, response),
                                   /* context is being freed off */
                                   return);

        /* Check validity of response code */
        if (!coap_check_code_class(obs->session, response)) {
          coap_log_warn("handle_request: Invalid PDU response code (%d.%02d)\n",
                        COAP_RESPONSE_CLASS(response->code),
                        response->code & 0x1f);
          coap_delete_pdu(response);
          return;
        }

        /* Check if lg_xmit generated and update PDU code if so */
        coap_check_code_lg_xmit(obs->session, obs->pdu, response, r, query);
        coap_delete_string(query);
        if (COAP_RESPONSE_CLASS(response->code) != 2) {
          coap_remove_option(response, COAP_OPTION_OBSERVE);
        }
        if (COAP_RESPONSE_CLASS(response->code) > 2) {
          coap_delete_observer(r, obs->session, &obs->pdu->actual_token);
          obs = NULL;
        }
        break;
      case COAP_DELETING_RESOURCE:
      default:
        /* Don't worry if it does not get there */
        response->type = COAP_MESSAGE_NON;
        response->code = COAP_RESPONSE_CODE(404);
        break;
      }

      if (obs) {
        if (response->type == COAP_MESSAGE_CON ||
            (r->flags & COAP_RESOURCE_FLAGS_NOTIFY_NON_ALWAYS)) {
          obs->non_cnt = 0;
        } else {
          obs->non_cnt++;
        }

#if COAP_Q_BLOCK_SUPPORT
        if (response->code == COAP_RESPONSE_CODE(205) &&
            coap_get_block_b(obs->session, response, COAP_OPTION_Q_BLOCK2,
                             &block) &&
            block.m) {
          query = coap_get_query(obs->pdu);
          mid = coap_send_q_block2(obs->session, r, query, obs->pdu->code,
                                   block, response, 1);
          coap_delete_string(query);
          goto finish;
        }
#endif /* COAP_Q_BLOCK_SUPPORT */
      }
      mid = coap_send_internal(obs_session, response);

#if COAP_Q_BLOCK_SUPPORT
finish:
#endif /* COAP_Q_BLOCK_SUPPORT */
      if (COAP_INVALID_MID == mid && obs) {
        coap_subscription_t *s;
        coap_log_debug("coap_check_notify: sending failed, resource stays "
                       "partially dirty\n");
        LL_FOREACH(r->subscribers, s) {
          if (s == obs) {
            /* obs not deleted during coap_send_internal() */
            obs->dirty = 1;
            break;
          }
        }
        r->partiallydirty = 1;
        context->observe_pending = 1;
      }
    }
  }
  r->dirty = 0;
}

COAP_API int
coap_resource_set_dirty(coap_resource_t *r, const coap_string_t *query) {
  int ret;

  coap_lock_lock(r->context, return 0);
  ret = coap_resource_notify_observers_lkd(r, query);
  coap_lock_unlock(r->context);
  return ret;
}

COAP_API int
coap_resource_notify_observers(coap_resource_t *r,
                               const coap_string_t *query) {
  int ret;

  coap_lock_lock(r->context, return 0);
  ret = coap_resource_notify_observers_lkd(r, query);
  coap_lock_unlock(r->context);
  return ret;
}

int
coap_resource_notify_observers_lkd(coap_resource_t *r,
                                   const coap_string_t *query COAP_UNUSED) {
  coap_lock_check_locked(r->context);
  if (!r->observable)
    return 0;
  if (!r->subscribers)
    return 0;
  r->dirty = 1;

  /* Increment value for next Observe use. Observe value must be < 2^24 */
  r->observe = (r->observe + 1) & 0xFFFFFF;

  assert(r->context);

  if (r->context->track_observe_value) {
    /* Track last used observe value */
    if ((r->observe % r->context->observe_save_freq) == 0)
      r->context->track_observe_value(r->context, r->uri_path,
                                      r->observe,
                                      r->context->observe_user_data);
  }

  r->context->observe_pending = 1;
  coap_update_io_timer(r->context, 0);
  return 1;
}

void
coap_resource_set_mode(coap_resource_t *resource, int mode) {
  resource->flags = (resource->flags &
                     ~(COAP_RESOURCE_FLAGS_NOTIFY_CON|COAP_RESOURCE_FLAGS_NOTIFY_NON)) |
                    (mode & (COAP_RESOURCE_FLAGS_NOTIFY_CON|COAP_RESOURCE_FLAGS_NOTIFY_NON));
}

void
coap_resource_set_userdata(coap_resource_t *resource, void *data) {
  resource->user_data = data;
}

void *
coap_resource_get_userdata(coap_resource_t *resource) {
  return resource->user_data;
}

void
coap_resource_release_userdata_handler(coap_context_t *context,
                                       coap_resource_release_userdata_handler_t callback) {
  context->release_userdata = callback;
}

void
coap_resource_set_get_observable(coap_resource_t *resource, int mode) {
  resource->observable = mode ? 1 : 0;
}

coap_str_const_t *
coap_resource_get_uri_path(coap_resource_t *resource) {
  if (resource)
    return resource->uri_path;
  return NULL;
}

COAP_API void
coap_check_notify(coap_context_t *context) {
  coap_lock_lock(context, return);
  coap_check_notify_lkd(context);
  coap_lock_unlock(context);
}

void
coap_check_notify_lkd(coap_context_t *context) {

  coap_lock_check_locked(context);
  if (context->observe_pending) {
    context->observe_pending = 0;
    RESOURCES_ITER(context->resources, r) {
      coap_notify_observers(context, r, COAP_NOT_DELETING_RESOURCE);
    }
  }
}

void
coap_persist_set_observe_num(coap_resource_t *resource,
                             uint32_t start_observe_no) {
  if (!resource)
    return;

  resource->observe = start_observe_no & 0xffffff;
}

/**
 * Checks the failure counter for (peer, token) and removes peer from
 * the list of observers for the given resource when COAP_OBS_MAX_FAIL
 * is reached.
 *
 * @param context  The CoAP context to use
 * @param resource The resource to check for (peer, token)
 * @param session  The observer's session
 * @param token    The token that has been used for subscription.
 */
static void
coap_remove_failed_observers(coap_context_t *context,
                             coap_resource_t *resource,
                             coap_session_t *session,
                             const coap_bin_const_t *token) {
  coap_subscription_t *obs, *otmp;

  LL_FOREACH_SAFE(resource->subscribers, obs, otmp) {
    if (obs->session == session &&
        coap_binary_equal(token, &obs->pdu->actual_token)) {
      /* count failed notifies and remove when
       * COAP_OBS_MAX_FAIL is reached */
      obs->fail_cnt++;
      if (obs->fail_cnt >= COAP_OBS_MAX_FAIL) {
        coap_cancel_all_messages(context, obs->session,
                                 &obs->pdu->actual_token);
        coap_delete_observer(resource, session, token);
      }
      break;                        /* break loop if observer was found */
    }
  }
}

void
coap_handle_failed_notify(coap_context_t *context,
                          coap_session_t *session,
                          const coap_bin_const_t *token) {

  RESOURCES_ITER(context->resources, r) {
    coap_remove_failed_observers(context, r, session, token);
  }
}

#endif /* ! COAP_SERVER_SUPPORT */
