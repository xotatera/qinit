#!/bin/sh
# SPDX-FileCopyrightText: 2026 Xota Tera
# SPDX-License-Identifier: GPL-3.0-or-later
# Installs clone-local hook sources and links the active hooks to them. Run once
# per clone, after main's first commit (the main guard refuses creating main).
set -eu
top="$(git rev-parse --show-toplevel)"
hooks="$(git rev-parse --path-format=absolute --git-common-dir)/hooks"
effective_hooks="$(git rev-parse --path-format=absolute --git-path hooks)"

# A configured dispatcher can choose to chain to these hooks, but Git has no
# way to verify that relationship. Refuse rather than claim protection is on.
if [ "$effective_hooks" != "$hooks" ]; then
    echo "refusing to install: effective core.hooksPath is $effective_hooks, not $hooks." >&2
    echo "Configure core.hooksPath to $hooks or integrate these hooks with the dispatcher yourself." >&2
    exit 1
fi

# Do every collision check before creating anything. Existing hooks are part of
# clone-local behavior and must be preserved for their owner to integrate.
for f in "$top"/.githooks/*; do
    [ -f "$f" ] || continue
    name="$(basename "$f")"
    [ "$name" = setup-hooks.sh ] && continue
    if [ -e "$hooks/$name" ] || [ -L "$hooks/$name" ]; then
        echo "refusing to install: $hooks/$name already exists." >&2
        exit 1
    fi
done
sources="$hooks/qinit"
if [ -e "$sources" ] || [ -L "$sources" ]; then
    echo "refusing to install: $sources already exists." >&2
    exit 1
fi

mkdir -p "$hooks"
mkdir "$sources"
for f in "$top"/.githooks/*; do
    [ -f "$f" ] || continue
    name="$(basename "$f")"
    [ "$name" = setup-hooks.sh ] && continue
    cp "$f" "$sources/$name"
    chmod 755 "$sources/$name"
    ln -s "qinit/$name" "$hooks/$name"
done
echo "installed clone-local hook sources in $sources and linked active hooks in $hooks"
