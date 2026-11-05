/* SPDX-FileCopyrightText: 2026 Xota Tera */
/* SPDX-License-Identifier: MPL-2.0 */
/* The C interface driven from C: compiled against the header by build.rs and linked into the
   crate's test binaries; tests/smoke.rs calls qinit_smoke with a served socket. */

#include <stdint.h>
#include <string.h>

#include "qinit_client.h"

int32_t qinit_smoke(const char *socket);

/* Whether the first `total` (at most `cap`) entries hold `name`. */
static int has_entry(const struct qinit_entry *entries, size_t cap, size_t total,
                     const char *name) {
  size_t n = total < cap ? total : cap;
  for (size_t i = 0; i < n; i++) {
    if (strcmp(entries[i].name, name) == 0) {
      return 1;
    }
  }
  return 0;
}

/* Steps 5 and 6 on a client of their own: a watch consumes the connection. */
static int32_t watch_db(const char *socket) {
  struct qinit_client *w = NULL;
  struct qinit_event ev;
  int32_t step = 0;
  if (qinit_connect(socket, &w) != 0) {
    return 5;
  }
  if (qinit_watch(w, 0, "db") != 0) {
    step = 5;
  } else if (qinit_watch_next(w, 5000, &ev) != QINIT_WATCH_EVENT ||
             (ev.report != QINIT_REPORT_CURRENT && ev.report != QINIT_REPORT_STOPPED)) {
    step = 6;
  }
  qinit_close(w);
  return step;
}

/* 0 on success, else the number of the failing step. */
int32_t qinit_smoke(const char *socket) {
  struct qinit_client *c = NULL;
  struct qinit_entry entries[8];
  struct qinit_status st;
  struct qinit_wait_result wr;
  struct qinit_error err;
  size_t total = 0;
  int32_t step = 0;

  if (qinit_connect(socket, &c) != 0 || c == NULL) {
    return 1;
  }
  if (qinit_list(c, QINIT_LIST_ALL, entries, 8, &total) != 0 ||
      !has_entry(entries, 8, total, "db")) {
    step = 2;
  } else if (qinit_status(c, "db", &st) != 0 || st.is_instance != 0 ||
             st.node.state != QINIT_STATE_READY) {
    step = 3;
  } else if (qinit_change(c, "db", QINIT_ACTION_STOP, 5000, &wr) != 0 ||
             (wr.outcome != QINIT_OUTCOME_SETTLED && wr.outcome != QINIT_OUTCOME_PENDING)) {
    step = 4;
  } else if ((step = watch_db(socket)) != 0) {
    /* step is set */
  } else if (qinit_status(c, "nothing", &st) == 0) {
    step = 7;
  } else {
    qinit_last_error(c, &err);
    if (err.kind != QINIT_E_SERVER || err.code != QINIT_CODE_UNKNOWN_NODE) {
      step = 7;
    }
  }
  qinit_close(c);
  return step;
}
