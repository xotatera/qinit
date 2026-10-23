#!/bin/sh
# SPDX-FileCopyrightText: 2026 Xota Tera
# SPDX-License-Identifier: GPL-3.0-or-later
# Links every hook in .githooks/ into this clone's hooks directory. Run once per
# clone, after main's first commit (the main guard refuses creating main). Under a
# global hooks dispatcher (a global core.hooksPath), check it chains to these.
set -eu
top="$(git rev-parse --show-toplevel)"
hooks="$(git rev-parse --path-format=absolute --git-common-dir)/hooks"
mkdir -p "$hooks"
for f in "$top"/.githooks/*; do
    name="$(basename "$f")"
    [ "$name" = setup-hooks.sh ] && continue
    ln -sf "$f" "$hooks/$name"
done
# Every merge is a merge commit, so pre-merge-commit's full gate runs.
git config merge.ff false
echo "linked .githooks/* into $hooks; set merge.ff=false"
