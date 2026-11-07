/* SPDX-FileCopyrightText: 2026 Xota Tera */
/* SPDX-License-Identifier: MPL-2.0 */
/* The request builder driven from C: a request is built, refused once for a bad field, then run
   through qinit_run_begin to its exit. Compiled against the header by build.rs and linked into
   the crate's test binaries; tests/smoke.rs calls qinit_builder with a served socket. */

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "qinit_client.h"

int32_t qinit_builder(const char *socket);

/* Steps 4 to 7: runs the request in `bytes` on a client of its own, standard output sent as the
   role's descriptor. */
static int32_t run(const char *socket, const uint8_t *bytes, size_t len) {
  struct qinit_client *c = NULL;
  struct qinit_begun begun;
  struct qinit_finish fin;
  int pipefd[2];
  int32_t step = 0;
  if (pipe(pipefd) != 0) {
    return 4;
  }
  if (qinit_connect(socket, &c) != 0) {
    step = 4;
  } else {
    struct qinit_run_args a;
    memset(&a, 0, sizeof a);
    a.request = bytes;
    a.request_len = len;
    a.stdin_fd = -1;
    a.stdout_fd = pipefd[1];
    a.stderr_fd = -1;
    a.stop_mode = QINIT_STOP_MAIN;
    a.stop_grace_ms = 1000;
    if (qinit_run_begin(c, "job", &a, 5000, &begun) != 0) {
      step = 5;
    } else if (begun.kind != QINIT_BEGUN_STARTED) {
      step = 6;
    } else if (qinit_launch_finish(c, &fin) != 0 || fin.kind != QINIT_FINISH_EXITED ||
               fin.status != 0) {
      step = 7;
    }
    qinit_close(c);
  }
  close(pipefd[0]);
  close(pipefd[1]);
  return step;
}

/* 0 on success, else the number of the failing step. */
int32_t qinit_builder(const char *socket) {
  const uint8_t *bytes = NULL;
  size_t len = 0;
  int32_t step = 0;
  struct qinit_request *r = qinit_request_new();
  if (r == NULL) {
    return 1;
  }
  /* A relative cwd: refused by RequestSpec::check, with its words, and no bytes. */
  if (qinit_request_add_arg(r, "/bin/job") != 0 || qinit_request_add_arg(r, "--once") != 0 ||
      qinit_request_add_env(r, "LANG=C") != 0 || qinit_request_set_user(r, "svc") != 0 ||
      qinit_request_set_cwd(r, "work") != 0 || qinit_request_set_deadline_ms(r, 5000) != 0) {
    step = 2;
  } else if (qinit_request_bytes(r, &bytes, &len) != QINIT_E_ARGUMENT || bytes != NULL ||
             len != 0 ||
             strcmp(qinit_request_error(r), "cwd: `work` is not an absolute path") != 0) {
    step = 2;
    /* Standard output on the descriptor colony gives the stdout role (6). */
  } else if (qinit_request_set_cwd(r, "/") != 0 || qinit_request_set_stdout_fd(r, 6) != 0 ||
             qinit_request_bytes(r, &bytes, &len) != 0 || bytes == NULL || len == 0 ||
             qinit_request_error(r)[0] != '\0') {
    step = 3;
  } else {
    step = run(socket, bytes, len);
  }
  qinit_request_free(r);
  return step;
}
