/*
* examples_code_check.c -- Validate the code in EXAMPLES of the man pages
*
* Exits with a non-zero value if there is a coding error.
*
* Copyright (C) 2020-2024 Jon Shallow <supjps-libcoap@jpshallow.com>
*
* SPDX-License-Identifier: BSD-2-Clause
*
* This file is part of the CoAP library libcoap. Please see README for terms
* of use.
*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>

#ifdef _WIN32
#define GCC_OPTIONS "-I../include"
#ifndef WEXITSTATUS
#define WEXITSTATUS(v) (v & 0xff)
#endif /* WEXITSTATUS */
#else /* ! _WIN32 */
#define GCC_OPTIONS "\
  -I../include \
  -std=c99 \
  -g \
  -O2 \
  -pedantic \
  -Wall \
  -Wcast-qual \
  -Wextra \
  -Wformat-security \
  -Winline \
  -Wmissing-declarations \
  -Wmissing-prototypes \
  -Wnested-externs \
  -Wpointer-arith \
  -Wshadow \
  -Wstrict-prototypes \
  -Wswitch-default \
  -Wswitch-enum \
  -Wunused \
  -Wwrite-strings \
  -Wno-unused-function \
  -Wno-unused-but-set-variable \
  -Werror \
"
#endif /* ! _WIN32 */

const char *inline_list[] = {
  "coap_free(",
  "coap_malloc(",
  "coap_encode_var_bytes(",
  "coap_option_clrb(",
  "coap_option_getb(",
  "coap_option_setb(",
  "coap_read(",
  "coap_run_once(",
  "coap_write(",
};

const char *define_list[] = {
  "coap_string_equal(",
  "coap_binary_equal(",
  "coap_log(",
  "coap_log_emerg(",
  "coap_log_alert(",
  "coap_log_crit(",
  "coap_log_err(",
  "coap_log_warn(",
  "coap_log_info(",
  "coap_log_notice(",
  "coap_log_debug(",
  "coap_log_oscore(",
  "coap_dtls_log(",
  "coap_lock_init(",
  "coap_lock_lock(",
  "coap_lock_unlock(",
  "coap_lock_being_freed(",
  "coap_lock_check_locked(",
  "coap_lock_callback(",
  "coap_lock_callback_ret(",
  "coap_lock_invert(",
};

/* xxx *function */
const char *pointer_list[] = {
  "char ",
  "coap_addr_info_t ",
  "coap_async_t ",
  "coap_attr_t ",
  "coap_bin_const_t ",
  "coap_binary_t ",
  "coap_cache_entry_t ",
  "coap_cache_key_t ",
  "coap_endpoint_t ",
  "coap_context_t ",
  "coap_fixed_point_t ",
  "coap_oscore_conf_t ",
  "coap_optlist_t ",
  "coap_session_t ",
  "coap_string_t ",
  "coap_str_const_t ",
  "coap_opt_iterator_t ",
  "coap_opt_t ",
  "coap_pdu_t ",
  "coap_resource_t ",
  "coap_subscription_t ",
  "coap_tls_version_t ",
  "coap_uri_t ",
  "const char ",
  "const coap_address_t ",
  "const coap_bin_const_t ",
  "const coap_pdu_t ",
};

/* xxx function */
const char *number_list[] = {
  "coap_log_t ",
  "coap_pdu_type_t ",
  "coap_mid_t ",
  "coap_pdu_code_t ",
  "coap_proto_t ",
  "coap_session_state_t ",
  "coap_session_type_t ",
  "int ",
  "uint16_t ",
  "uint32_t ",
  "uint64_t ",
  "unsigned int ",
  "size_t ",
  "const uint8_t ",
};

const char *return_void_list[] = {
  "coap_option_filter_set",
  "coap_resource_set_userdata",
  "coap_cache_set_app_data",
};

int exit_code = 0;

static char name_list[100][100];
static unsigned int name_cnt = 0;
static char return_list[100][100];
static unsigned int return_cnt = 0;
static char man_list[400][100];
static unsigned int man_cnt = 0;

static void
check_synopsis(const char *file) {
  char buffer[1024];
  char file_name[300];
  FILE *fpcode;
  int  status;

  snprintf(file_name, sizeof(file_name), "tmp/%s-header.c", file);
  fpcode = fopen(file_name, "w");
  if (!fpcode) {
    fprintf(stderr, "fopen: %s: %s (%d)\n", file_name, strerror(errno), errno);
    exit_code = 1;
    return;
  }
  fprintf(fpcode, "#include <coap3/coap.h>\n");
  fprintf(fpcode, "#ifdef __GNUC__\n");
  fprintf(fpcode, "#define U __attribute__ ((unused))\n");
  fprintf(fpcode, "#else /* not a GCC */\n");
  fprintf(fpcode, "#define U\n");
  fprintf(fpcode, "#endif /* GCC */\n");
  fprintf(fpcode, "\n");
  fprintf(fpcode, "#include \"%s.h\"\n", file);
  fclose(fpcode);
  file_name[strlen(file_name)-1] = '\000';
  snprintf(buffer, sizeof(buffer),
           "gcc " GCC_OPTIONS " -c %sc -o %so",
           file_name, file_name);
  status = system(buffer);
  if (WEXITSTATUS(status)) {
    exit_code = WEXITSTATUS(status);
    snprintf(buffer, sizeof(buffer), "echo %sc ; cat -n %sc", file_name, file_name);
    status = system(buffer);
    snprintf(buffer, sizeof(buffer), "echo tmp/%s.h ; cat -n tmp/%s.h", file, file);
    status = system(buffer);
    if (WEXITSTATUS(status)) {
      printf("Issues with system() call\n");
    }
  }
  return;
}

static void
dump_name_synopsis_mismatch(void) {
  unsigned int i;

  for (i = 0; i < name_cnt; i++) {
    if (name_list[i][0] != '\000') {
      fprintf(stderr, "NAME: %s not in SYNOPSIS or pointer_list[]\n", name_list[i]);
      exit_code = 1;
    }
  }
  name_cnt = 0;
}

static void
dump_return_synopsis_mismatch(void) {
  unsigned int i;

  for (i = 0; i < return_cnt; i++) {
    if (return_list[i][0] != '\000') {
      fprintf(stderr, "SYNOPSIS: %s not in RETURN VALUES\n", return_list[i]);
      exit_code = 1;
    }
  }
  return_cnt = 0;
}

/*
 * It is assumed for a definition that a leading * and trailing * have been
 * added to buffer.
 */
static void
decode_synopsis_definition(FILE *fpheader, const char *buffer, int in_synopsis) {
  size_t len;
  char outbuf[1024];
  const char *cp;
  const char *ecp;
  int is_void_func = 0;
  int is_number_func = 0;
  int is_inline_func = 0;
  int is_struct_func = 0;
  const char *func_start = NULL;
  int is_struct = 0;
  unsigned int i;

  if (strncmp(buffer, "*void ", sizeof("*void ")-1) == 0) {
    if (strncmp(buffer, "*void *", sizeof("*void *")-1) == 0) {
      func_start = &buffer[sizeof("*void *")-1];
    } else {
      is_void_func = 1;
      func_start = &buffer[sizeof("*void ")-1];
    }
  }

  for (i = 0; i < sizeof(number_list)/sizeof(number_list[0]); i++) {
    if (strncmp(&buffer[1], number_list[i],
                strlen(number_list[i])) == 0) {
      if (buffer[1 + strlen(number_list[i])] == '*') {
        func_start = &buffer[2 + strlen(number_list[i])];
      } else {
        is_number_func = 1;
        func_start = &buffer[1 + strlen(number_list[i])];
      }
      break;
    }
  }

  for (i = 0; i < sizeof(pointer_list)/sizeof(pointer_list[0]); i++) {
    if (strncmp(&buffer[1], pointer_list[i],
                strlen(pointer_list[i])) == 0) {
      if (buffer[1 + strlen(pointer_list[i])] == '*') {
        func_start = &buffer[2 + strlen(pointer_list[i])];
      } else {
        is_struct_func = i + 1;
        func_start = &buffer[1 + strlen(pointer_list[i])];
      }
      break;
    }
  }

  if (strncmp(buffer, "*struct ", sizeof("*struct ")-1) == 0) {
    is_struct = 1;
    func_start = &buffer[sizeof("*struct ")-1];
  }

  if (func_start) {
    /* see if COAP_STATIC_INLINE function */
    for (i = 0; i < sizeof(inline_list)/sizeof(inline_list[0]); i++) {
      if (strncmp(func_start, inline_list[i],
                  strlen(inline_list[i])) == 0) {
        is_inline_func = 1;
        break;
      }
    }
    /* see if #define function */
    for (i = 0; i < sizeof(define_list)/sizeof(define_list[0]); i++) {
      if (strncmp(func_start, define_list[i], strlen(define_list[i])) == 0) {
        break;
      }
    }
    if (i != sizeof(define_list)/sizeof(define_list[0]))
      goto cleanup;
  }

  /* Need to include use of U for unused parameters just before comma */
  cp = buffer;
  ecp = strchr(cp, ',');
  if (!ecp)
    ecp = strchr(cp, ')');
  outbuf[0] = '\000';
  while (ecp) {
    len = strlen(outbuf);
    if (strncmp(cp, "void", ecp-cp) == 0)
      snprintf(&outbuf[len], sizeof(outbuf)-len, "%*.*s%c",
               (int)(ecp-cp), (int)(ecp-cp), cp, *ecp);
    else
      snprintf(&outbuf[len], sizeof(outbuf)-len, "%*.*s U%c",
               (int)(ecp-cp), (int)(ecp-cp), cp, *ecp);
    cp = ecp+1;
    if (*cp) {
      ecp = strchr(cp, ',');
      if (!ecp)
        ecp = strchr(cp, ')');
    } else {
      ecp = NULL;
    }
  }
  if (*cp) {
    len = strlen(outbuf);
    snprintf(&outbuf[len], sizeof(outbuf)-len, "%s", cp);
  }

  len = strlen(outbuf);
  if (len > 3 && ((outbuf[len-3] == ';' && outbuf[len-2] == '*') ||
                  (outbuf[len-3] == '*' && outbuf[len-2] == ';'))) {
    if (is_inline_func) {
      strcpy(&outbuf[len-3], ";\n");
    }
    /* Replace ;* or *; with simple function definition */
    else if (is_void_func) {
      strcpy(&outbuf[len-3], "{}\n");
    } else if (is_number_func) {
      strcpy(&outbuf[len-3], "{return 0;}\n");
    } else if (is_struct_func) {
      snprintf(&outbuf[len-3], sizeof(outbuf)-(len-3),
               "{%s v; memset(&v, 0, sizeof(v)); return v;}\n",
               pointer_list[is_struct_func - 1]);
    } else if (is_struct) {
      strcpy(&outbuf[len-3], ";\n");
    } else {
      strcpy(&outbuf[len-3], "{return NULL;}\n");
    }
  }
  if (outbuf[0] == '*') {
    fprintf(fpheader, "%s", &outbuf[1]);
  } else {
    fprintf(fpheader, "%s", outbuf);
  }
cleanup:
  if (in_synopsis && func_start) {
    char *wcp = strchr(func_start, '(');

    if (!wcp && is_struct)
      wcp = strchr(func_start, ';');
    if (!wcp) {
      wcp = strchr(func_start, '\n');
      if (wcp)
        *wcp = '\000';
      fprintf(stderr, "SYNOPSIS: function %s issue\n", func_start);
      return;
    }
    *wcp = '\000';
    for (i = 0; i < name_cnt; i++) {
      if (strcmp(name_list[i], func_start) == 0) {
        name_list[i][0] = '\000';
        break;
      }
    }
    if (i == name_cnt) {
      fprintf(stderr, "SYNOPSIS: %s not in NAME\n", func_start);
      exit_code = 1;
    }
    if (!is_void_func && !is_struct) {
      for (i = 0; i < return_cnt; i++) {
        if (strcmp(func_start, return_list[i]) == 0) {
          fprintf(stderr, "SYNOPSIS: %s duplicated\n", func_start);
          break;
        }
      }
      if (i != return_cnt)
        return;
      if (i >= (int)(sizeof(return_list)/sizeof(return_list[0]))) {
        fprintf(stderr, "SYNOPSIS: %s insufficient space (%u >= %u)\n", func_start,
                i, (int)(sizeof(return_list)/sizeof(return_list[0])));
        return;
      }
      strncpy(return_list[i], func_start, sizeof(return_list[i])-1);
      return_cnt++;
    }
  }
  return;
}

int
main(int argc, char *argv[]) {
  DIR *pdir;
  struct dirent *pdir_ent;
  char buffer[1024];
  char man_name[1024];
  int  status;
  size_t i;
  int man_missing_first = 1;

  if (argc != 2 && argc != 3) {
    fprintf(stderr, "usage: %s man_directory [libcoap-3.sym_file]\n", argv[0]);
    exit(1);
  }

  pdir = opendir(argv[1]);
  if (pdir == NULL) {
    fprintf(stderr, "opendir: %s: %s (%d)\n", argv[1], strerror(errno), errno);
    exit(1);
  }
  if (argc == 3) {
    FILE *fp = fopen(argv[2], "r");
    char tmp_name[100];

    if (fp == NULL) {
      fprintf(stderr, "fopen: %s: %s (%d)\n", argv[2], strerror(errno), errno);
      exit(1);
    }
    while (fgets(tmp_name, sizeof(tmp_name), fp) != NULL) {
      char *cp = strchr(tmp_name, '\n');

      if (cp)
        *cp = '\000';
      if (tmp_name[0]) {
        strncpy(man_list[man_cnt], tmp_name, sizeof(man_list[man_cnt]));
        man_cnt++;
      }
      if (man_cnt == sizeof(man_list) / sizeof(name_list[0])) {
        fprintf(stderr, "man_list[] too small (%zd) for entries from %s\n",
                sizeof(man_list) / sizeof(name_list[0]), argv[2]);
        exit(1);
      }
    }
    fclose(fp);
  }
  if (chdir(argv[1]) == -1) {
    fprintf(stderr, "chdir: %s: %s (%d)\n", argv[1], strerror(errno), errno);
    exit(1);
  }
#if defined(WIN32) || defined(__MINGW32__)
  if (mkdir("tmp") == -1 && errno != EEXIST) {
    fprintf(stderr, "mkdir: %s: %s (%d)\n", "tmp", strerror(errno), errno);
    exit(1);
  }
#else /* ! WIN32 && ! __MINGW32__ */
  if (mkdir("tmp", 0777) == -1 && errno != EEXIST) {
    fprintf(stderr, "mkdir: %s: %s (%d)\n", "tmp", strerror(errno), errno);
    exit(1);
  }
#endif /* ! WIN32 && ! __MINGW32__ */

  while ((pdir_ent = readdir(pdir)) != NULL) {
    if (!strncmp(pdir_ent->d_name, "coap_", sizeof("coap_")-1) &&
        strstr(pdir_ent->d_name, ".txt.in")) {
      FILE  *fp;
      int skip = 1;
      int in_examples = 0;
      int in_synopsis = 0;
      int in_functions = 0;
      int in_name = 0;
      int in_return = 0;
      int count = 1;
      char keep_line[1024] = {0};
      FILE *fpcode = NULL;
      FILE *fpheader = NULL;
      char file_name[300];
      char *cp;

      fprintf(stderr, "Processing: %s\n", pdir_ent->d_name);

      snprintf(man_name, sizeof(man_name), "%s", pdir_ent->d_name);
      fp = fopen(man_name, "r");
      if (fp == NULL) {
        fprintf(stderr, "fopen: %s: %s (%d)\n", man_name, strerror(errno), errno);
        continue;
      }
      cp = strstr(man_name, ".txt.in");
      if (cp)
        *cp = '\000';
      name_cnt = 0;
      while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        if (strncmp(buffer, "NAME", sizeof("NAME")-1) == 0) {
          in_name = 1;
          continue;
        }
        if (strncmp(buffer, "SYNOPSIS", sizeof("SYNOPSIS")-1) == 0) {
          in_name = 0;
          in_synopsis = 1;
          snprintf(file_name, sizeof(file_name), "tmp/%s.h",
                   pdir_ent->d_name);
          fpheader = fopen(file_name, "w");
          if (!fpheader) {
            fprintf(stderr, "fopen: %s: %s (%d)\n", file_name,
                    strerror(errno), errno);
            goto bad;
          }
          continue;
        }
        if (strncmp(buffer, "FUNCTIONS", sizeof("FUNCTIONS")-1) == 0) {
          in_synopsis = 0;
          dump_name_synopsis_mismatch();
          in_functions = 1;
          continue;
        }
        if (strncmp(buffer, "DESCRIPTION", sizeof("DESCRIPTION")-1) == 0) {
          in_synopsis = 0;
          dump_name_synopsis_mismatch();
          if (fpheader)
            fclose(fpheader);
          fpheader = NULL;
          check_synopsis(pdir_ent->d_name);
          continue;
        }
        if (strncmp(buffer, "RETURN VALUES", sizeof("RETURN VALUES")-1) == 0 ||
            strncmp(buffer, "RETURN VALUE", sizeof("RETURN VALUE")-1) == 0) {
          if (in_functions) {
            if (fpheader)
              fclose(fpheader);
            fpheader = NULL;
            check_synopsis(pdir_ent->d_name);
          }
          in_name = 0;
          in_synopsis = 0;
          dump_name_synopsis_mismatch();
          in_functions = 0;
          in_return = 1;
          continue;
        }
        if (strncmp(buffer, "TESTING", sizeof("TESTING")-1) == 0) {
          if (in_functions) {
            if (fpheader)
              fclose(fpheader);
            fpheader = NULL;
            check_synopsis(pdir_ent->d_name);
          }
          in_name = 0;
          in_synopsis = 0;
          in_functions = 0;
          in_return = 0;
          continue;
        }
        if (strncmp(buffer, "EXAMPLES", sizeof("EXAMPLES")-1) == 0 ||
            strncmp(buffer, "EXAMPLE", sizeof("EXAMPLE")-1) == 0) {
          if (in_functions) {
            if (fpheader)
              fclose(fpheader);
            fpheader = NULL;
            check_synopsis(pdir_ent->d_name);
          }
          in_name = 0;
          in_synopsis = 0;
          in_return = 0;
          dump_name_synopsis_mismatch();
          dump_return_synopsis_mismatch();
          in_functions = 0;
          in_examples = 1;
          continue;
        }
        if (strncmp(buffer, "SEE ALSO", sizeof("SEE ALSO")-1) == 0) {
          if (in_functions) {
            if (fpheader)
              fclose(fpheader);
            fpheader = NULL;
            check_synopsis(pdir_ent->d_name);
          }
          in_name = 0;
          in_synopsis = 0;
          in_return = 0;
          dump_name_synopsis_mismatch();
          dump_return_synopsis_mismatch();
          in_functions = 0;
          in_examples = 1;
          break;
        }

        if (in_name) {
          /* Working in NAME section */
          if (buffer[0] == '\n')
            continue;
          if (buffer[0] == '-')
            continue;
          cp = strchr(buffer, '\n');
          if (cp)
            *cp = '\000';
          cp = strchr(buffer, ',');
          if (cp)
            *cp = '\000';
          if (strcmp(man_name, buffer) == 0)
            continue;
          if (strlen(buffer) >= sizeof(name_list[0])) {
            fprintf(stderr, "NAME: %s is too long (%u >= %u)\n", buffer,
                    (int)strlen(buffer), (int)sizeof(name_list[0]));
            continue;
          }
          for (i = 0; i < name_cnt; i++) {
            if (strncmp(buffer, name_list[i], sizeof(name_list[i])) == 0) {
              fprintf(stderr, "NAME: %s duplicated\n", buffer);
              break;
            }
          }
          if (i != name_cnt)
            continue;
          if (i >= (int)(sizeof(name_list)/sizeof(name_list[0]))) {
            fprintf(stderr, "NAME: %s insufficient space (%zu >= %u)\n", buffer,
                    i, (int)(sizeof(name_list)/sizeof(name_list[0])));
            continue;
          }
          memcpy(name_list[i], buffer, sizeof(name_list[i])-1);
          name_list[i][sizeof(name_list[i])-1] = '\000';
          name_cnt++;
          for (i = 0; i < man_cnt; i++) {
            if (strncmp(man_list[i], buffer, sizeof(man_list[i])) == 0) {
              man_list[i][0] = '\000';
              break;
            }
          }
        }

        if (in_synopsis) {
          /* Working in SYNOPSIS section */
          size_t len;
          char outbuf[1024];

          if (buffer[0] == '*' && buffer[1] != '#') {
            /* Start of a new entry */
            snprintf(outbuf, sizeof(outbuf), "%s", buffer);
            while (fgets(buffer, sizeof(buffer), fp) != NULL) {
              if (buffer[0] == '\n') {
                break;
              }
              len = strlen(outbuf);
              outbuf[len-1] = ' ';
              snprintf(&outbuf[len], sizeof(outbuf) - len, "%s", buffer);
            }
            decode_synopsis_definition(fpheader, outbuf, 1);
            continue;
          }
          if (buffer[0] == '\n')
            continue;
          if (buffer[0] == '-')
            continue;
          if (buffer[0] == 'F') {
            /* For specific ..... is the end */
            in_synopsis = 0;
            if (fpheader)
              fclose(fpheader);
            fpheader = NULL;
            check_synopsis(pdir_ent->d_name);
            continue;
          }
        }

        if (in_functions) {
          /* Working in FUNCTIONS section */
          size_t len;
          char outbuf[1024];

          if (strncmp(buffer, "Prototype:\n", sizeof("Prototype:\n")-1)== 0) {
            /* Start of a new entry */
            outbuf[0] = '*';
            outbuf[1] = '\000';
            while (fgets(buffer, sizeof(buffer), fp) != NULL) {
              if (buffer[0] == '\n') {
                break;
              }
              len = strlen(outbuf);
              if (outbuf[len-1] == '\n')
                outbuf[len-1] = ' ';
              snprintf(&outbuf[len], sizeof(outbuf) - len, "%s", buffer);
            }
            len = strlen(outbuf);
            len--;
            snprintf(&outbuf[len], sizeof(outbuf) - len, "*\n");
            decode_synopsis_definition(fpheader, outbuf, 0);
            continue;
          }
        }

        if (in_return) {
          cp = strstr(buffer, "*coap_");
          while (cp) {
            char *ecp = strchr(cp+1, '*');

            if (!ecp) {
              fprintf(stderr, "RETURN VALUES: %s undecipherable\n", cp + 1);
              exit_code = 1;
              break;
            }
            *ecp = '\000';
            for (i = 0; i < return_cnt; i++) {
              if (strcmp(cp+1, return_list[i]) == 0) {
                return_list[i][0] = '\000';
                break;
              }
            }
            if (i == return_cnt) {
              for (i = 0;
                   i < sizeof(return_void_list)/sizeof(return_void_list[0]);
                   i++) {
                if (strcmp(cp+1, return_void_list[i]) == 0)
                  break;
              }
              if (i == sizeof(return_void_list)/sizeof(return_void_list[0])) {
                fprintf(stderr, "RETURN VALUES: %s not defined in SYNOPSIS\n", cp + 1);
                exit_code = 1;
              }
            }
            cp = strstr(ecp+1, "*coap_");
          }
        }

        if (!in_examples) {
          continue;
        }
        /* Working in EXAMPLES section */
        if (skip) {
          if (!strcmp(buffer, "----\n") || !strcmp(buffer, "---\n") ||
              !strcmp(buffer, "--\n") || !strcmp(buffer, "-\n") ||
              !strcmp(buffer, "-----\n")) {
            /* Found start of code */
            if (strcmp(buffer, "----\n")) {
              fprintf(stderr,
                      "Unexpected start of code '%.*s' - expected ----\n",
                      (int)strlen(buffer)-1, buffer);
            }
            snprintf(file_name, sizeof(file_name), "tmp/%s-%d.c",
                     pdir_ent->d_name, count++);
            fpcode = fopen(file_name, "w");
            if (!fpcode) {
              fprintf(stderr, "fopen: %s: %s (%d)\n", file_name,
                      strerror(errno), errno);
              goto bad;
            } else {
              fprintf(fpcode, "/* %s */\n", keep_line);
            }
            skip = 0;
            fprintf(stderr, "Processing: %s EXAMPLE - '%d'\n",
                    pdir_ent->d_name,
                    count-1);
          } else if (buffer[0] == '*') {
            snprintf(keep_line, sizeof(keep_line), "%s", buffer);
          }
          continue;
        }
        if (!strcmp(buffer, "----\n") || !strcmp(buffer, "---\n") ||
            !strcmp(buffer, "--\n") || !strcmp(buffer, "-\n") ||
            !strcmp(buffer, "-----\n")) {
          /* Found end of code */

          skip = 1;
          if (fpcode)
            fclose(fpcode);
          keep_line[0] = '\000';
          file_name[strlen(file_name)-1] = '\000';
          snprintf(buffer, sizeof(buffer),
                   "gcc " GCC_OPTIONS " -c %sc -o %so",
                   file_name, file_name);
          status = system(buffer);
          if (WEXITSTATUS(status)) {
            exit_code = WEXITSTATUS(status);
            snprintf(buffer, sizeof(buffer), "echo %sc ; cat -n %sc", file_name, file_name);
            status = system(buffer);
            if (WEXITSTATUS(status)) {
              printf("Issues with system() call\n");
            }
          }
          continue;
        }
        if (fpcode) {
          if (strstr(buffer, "LIBCOAP_API_VERSION")) {
            fprintf(fpcode, "#include <coap3/coap.h>\n");
            fprintf(fpcode, "\n");
            continue;
          }
          fprintf(fpcode, "%s", buffer);
        }
      }
bad:
      fclose(fp);
    }
  }
  closedir(pdir);
  for (i = 0; i < man_cnt; i++) {
    if (man_list[i][0]) {
      if (man_missing_first) {
        man_missing_first = 0;
        fprintf(stderr, "\nMissing man pages (for reference only)\n");
      }
      fprintf(stderr, "%s\n", man_list[i]);
    }
  }
  exit(exit_code);
}
