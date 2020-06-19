/*
* examples_code_check.c -- Validate the code in EXAMPLES of the man pages
*
* Exits with a non-zero value if there is a coding error.
*
* Copyright (C) 2020 Jon Shallow <supjps-libcoap@jpshallow.com>
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
  "
#endif /* ! _WIN32 */

int main(int argc, char* argv[])
{
  DIR *pdir;
  struct dirent *pdir_ent;
  int exit_code = 0;
  char buffer[512];

  if (argc != 2) {
    fprintf(stderr, "usage: %s man_directory\n", argv[0]);
    exit (1);
  }

  pdir = opendir(argv[1]);
  if (pdir == NULL) {
    fprintf(stderr, "opendir: %s: %s (%d)\n", argv[1], strerror(errno), errno);
    exit(1);
  }
  if (chdir(argv[1]) == -1) {
    fprintf(stderr, "chdir: %s: %s (%d)\n", argv[1], strerror(errno), errno);
    exit(1);
  }
  if (mkdir("tmp", 0777) == -1 && errno != EEXIST) {
    fprintf(stderr, "mkdir: %s: %s (%d)\n", "tmp", strerror(errno), errno);
    exit(1);
  }

  while ((pdir_ent = readdir (pdir)) != NULL) {
    if (!strncmp(pdir_ent->d_name, "coap_", sizeof ("coap_")-1) &&
        strstr (pdir_ent->d_name, ".txt.in")) {
      FILE*  fp;
      int  skip = 1;
      int  in_examples = 0;
      int in_synopsis = 0;
      int  count = 1;
      char  keep_line[1024] = {0};
      FILE*  fpcode = NULL;
      FILE*  fpheader = NULL;
      char  file_name[512];

      fprintf(stderr, "Processing: %s\n", pdir_ent->d_name);

      snprintf(buffer, sizeof (buffer), "%s", pdir_ent->d_name);
      fp = fopen(buffer, "r");
      if (fp == NULL) {
        fprintf(stderr, "fopen: %s: %s (%d)\n", buffer, strerror(errno), errno);
        continue;
      }
      while (fgets(buffer, sizeof (buffer), fp) != NULL) {
        if (strncmp(buffer, "SYNOPSIS", sizeof("SYNOPSIS")-1) == 0) {
          in_synopsis = 1;
          snprintf(file_name, sizeof (file_name), "tmp/%s.h",
                   pdir_ent->d_name);
          fpheader = fopen(file_name, "w");
          if (!fpheader) {
            fprintf(stderr, "fopen: %s: %s (%d)\n", file_name,
                    strerror(errno), errno);
            goto bad;
          }
          continue;
        }
        if (strncmp(buffer, "DESCRIPTION", sizeof("DESCRIPTION")-1) == 0) {
          in_synopsis = 0;
          if (fpheader)
            fclose(fpheader);
          continue;
        }
        if (strncmp(buffer, "EXAMPLES", sizeof("EXAMPLES")-1) == 0) {
          in_synopsis = 0;
          in_examples = 1;
          continue;
        }
        if (strncmp(buffer, "SEE ALSO", sizeof("SEE ALSO")-1) == 0) {
          break;
        }
        if (in_synopsis) {
          /* Working in SYNOPSIS section */
          size_t len;
          if (buffer[0] == '\n')
            continue;
          if (buffer[0] == '-')
            continue;
          if (buffer[0] == 'L') {
            /* Link with ..... is the end */
            in_synopsis = 0;
            continue;
          }
          if (buffer[0] == '*' && buffer[1] == '#')
            continue;

          len = strlen(buffer);
          if (len > 3 && buffer[len-3] == ';' && buffer[len-2] == '*') {
            /* Delete terminating * */
            buffer[len-2] = '\n';
            buffer[len-1] = '\000';
          }
          if (len > 3 && buffer[len-3] == '*' && buffer[len-2] == ';') {
            /* Delete trailing * */
            buffer[len-3] = ';';
            buffer[len-2] = '\n';
            buffer[len-1] = '\000';
          }
          if (buffer[0] == '*') {
            fprintf(fpheader, "%s", &buffer[1]);
          }
          else {
            fprintf(fpheader, "%s", buffer);
          }
          continue;
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
            snprintf(file_name, sizeof (file_name), "tmp/%s-%d.c",
                     pdir_ent->d_name, count++);
            fpcode = fopen(file_name, "w");
            if (!fpcode) {
              fprintf(stderr, "fopen: %s: %s (%d)\n", file_name,
                      strerror(errno), errno);
              goto bad;
            }
            else {
              fprintf(fpcode, "/* %s */\n", keep_line);
            }
            skip = 0;
            fprintf(stderr, "Processing: %s EXAMPLE - '%d'\n",
                    pdir_ent->d_name,
                    count-1);
          }
          else if (buffer[0] == '*') {
            snprintf(keep_line, sizeof (keep_line), "%s", buffer);
          }
          continue;
        }
        if (!strcmp(buffer, "----\n") || !strcmp(buffer, "---\n") ||
            !strcmp(buffer, "--\n") || !strcmp(buffer, "-\n") ||
            !strcmp(buffer, "-----\n")) {
          /* Found end of code */
          int  status;

          skip = 1;
          if (fpcode) fclose(fpcode);
          keep_line[0] = '\000';
          file_name[strlen(file_name)-1] = '\000';
          snprintf (buffer, sizeof (buffer),
                   "gcc " GCC_OPTIONS " -c %sc -o %so",
                   file_name, file_name);
          status = system(buffer);
          if (WEXITSTATUS(status)) {
            exit_code = WEXITSTATUS(status);
          }
          continue;
        }
        if (fpcode) {
          if (strstr (buffer, "LIBCOAP_API_VERSION")) {
            fprintf(fpcode, "#include <coap2/coap.h>\n");
            fprintf(fpcode, "#include \"%s.h\"\n", pdir_ent->d_name);
            continue;
          }
          fprintf(fpcode, "%s", buffer);
        }
      }
bad:
      fclose(fp);
    }
  }
  closedir (pdir);
  exit(exit_code);
}
