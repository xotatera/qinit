#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Xota Tera
# SPDX-License-Identifier: GPL-3.0-or-later
# Refuses a commit on main, and a branch name without a known prefix. Run
# first by pre-commit.
#
# Two cases pass on purpose:
# - Concluding a merge into main (after a conflict, or `git merge
#   --no-commit`): git skips pre-merge-commit for the `git commit` that
#   finishes it, so pre-commit runs the full gate for that commit instead.
#   MERGE_HEAD marks that state.
# - Detached HEAD (no symbolic ref): rebases commit there.
set -euo pipefail
# Find the repository from the working directory, not from a hook's GIT_DIR,
# which is absolute in a linked worktree.
# shellcheck disable=SC2046
unset $(git rev-parse --local-env-vars)

MAIN="${DISCIPLINES_MAIN_BRANCH:-main}"
# Empty when HEAD is detached. Unlike `rev-parse --abbrev-ref HEAD`, this also
# works on a branch with no commits yet.
branch="$(git symbolic-ref --short -q HEAD || true)"

if [ -z "$branch" ]; then
  exit 0
fi

if [ "$branch" = "$MAIN" ]; then
  if git rev-parse -q --verify MERGE_HEAD >/dev/null; then
    exit 0
  fi
  if ! git rev-parse -q --verify HEAD >/dev/null; then
    echo "$MAIN has no commits yet, and the main guard refuses to create it." >&2
    echo "Make the first commit before installing the hooks, or once:" >&2
    echo "  DISCIPLINES_ALLOW_UNGATED_MAIN='initial commit' git commit --no-verify" >&2
    exit 1
  fi
  echo "Direct commits to $MAIN are not allowed." >&2
  echo "Commit on a branch and merge it with --no-ff:  git switch -c feat/my-change" >&2
  exit 1
fi

case "$branch" in
  feat/?* | fix/?* | spec/?* | docs/?* | chore/?*) ;;
  *)
    echo "Branch name must use a prefix/ format (feat/, fix/, docs/, chore/, spec/)." >&2
    echo "Current branch: $branch" >&2
    exit 1
    ;;
esac
