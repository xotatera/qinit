#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Xota Tera
# SPDX-License-Identifier: GPL-3.0-or-later
# Refuses to gate a tree the working directory does not match. The full gate
# checks the files on disk, but the gate token records the index's tree, so
# an untracked file or an unstaged edit could make the gate pass for code the
# merge does not contain. Ignored files (build output) do not count. Index
# entries marked assume-unchanged or skip-worktree also refuse: git diff
# cannot see their edits.
#
#   worktree-clean.sh [<index file>]   default: the repository's index
set -euo pipefail

dirty=0
if [ -n "${1:-}" ]; then
  GIT_INDEX_FILE="$1" git diff --quiet || dirty=1
else
  git diff --quiet || dirty=1
fi
# --no-empty-directory: `--directory` would otherwise name a directory that
# holds only ignored files (its own .gitignore is `*`). A directory with any
# untracked file inside is still listed.
untracked="$(git ls-files --others --exclude-standard --directory --no-empty-directory)"
# `git diff` cannot see an edit to a file marked assume-unchanged (a
# lowercase tag in `ls-files -v`) or skip-worktree (`S`, as in a sparse
# checkout, whose files are not on disk for the gate to test).
if [ -n "${1:-}" ]; then
  hidden="$(GIT_INDEX_FILE="$1" git ls-files -v | sed -n 's/^[a-zS] //p')"
else
  hidden="$(git ls-files -v | sed -n 's/^[a-zS] //p')"
fi

if [ "$dirty" = 0 ] && [ -z "$untracked" ] && [ -z "$hidden" ]; then
  exit 0
fi
echo "Working tree differs from the tree being merged, so the gate would test other code." >&2
if [ "$dirty" = 1 ]; then
  echo "  unstaged changes (see git diff)" >&2
fi
if [ -n "$untracked" ]; then
  # Display only: a closed pipe (head) must not abort before the final line.
  { printf '%s\n' "$untracked" | head -5 | sed 's/^/  untracked: /' >&2; } || true
fi
if [ "$dirty" = 1 ] || [ -n "$untracked" ]; then
  echo "Stage, stash or ignore them, then merge again." >&2
fi
if [ -n "$hidden" ]; then
  { printf '%s\n' "$hidden" | head -5 | sed 's/^/  hidden from git diff (assume-unchanged or skip-worktree): /' >&2; } || true
  echo "  The gate tests the files on disk: git diff cannot see edits to these entries, and in a sparse checkout they are not on disk at all." >&2
  echo "  Clear the marks first: git sparse-checkout disable, or git update-index --no-skip-worktree / --no-assume-unchanged <file>." >&2
fi
exit 1
