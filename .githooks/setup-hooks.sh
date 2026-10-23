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

sources="$hooks/qinit"
refresh=false
if [ -e "$sources" ] || [ -L "$sources" ]; then
    # A refresh may replace only the exact layout this installer created: a
    # real qinit directory, regular source files, and relative active links.
    # Do not follow a source-directory or source-file symlink.
    if [ ! -d "$sources" ] || [ -L "$sources" ]; then
        echo "refusing to refresh: $sources is not a qinit source directory." >&2
        exit 1
    fi
    refresh=true
fi

# Do every collision or ownership check before writing anything. Existing hooks
# are clone-local behavior and must be preserved for their owner to integrate.
for f in "$top"/.githooks/*; do
    [ -f "$f" ] || continue
    name="$(basename "$f")"
    [ "$name" = setup-hooks.sh ] && continue
    if "$refresh"; then
        if [ ! -f "$sources/$name" ] || [ -L "$sources/$name" ] ||
            [ ! -L "$hooks/$name" ] ||
            [ "$(readlink "$hooks/$name")" != "qinit/$name" ]; then
            echo "refusing to refresh: $hooks/$name is not a qinit-installed hook." >&2
            exit 1
        fi
    elif [ -e "$hooks/$name" ] || [ -L "$hooks/$name" ]; then
        echo "refusing to install: $hooks/$name already exists." >&2
        exit 1
    fi
done

if "$refresh"; then
    # Reject extra qinit entries too: this directory is ours only when its
    # complete contents are the current set of installed hook sources.
    for installed in "$sources"/*; do
        [ -e "$installed" ] || [ -L "$installed" ] || continue
        installed_name="$(basename "$installed")"
        known=false
        for f in "$top"/.githooks/*; do
            [ -f "$f" ] || continue
            [ "$(basename "$f")" = "$installed_name" ] || continue
            [ "$installed_name" = setup-hooks.sh ] || known=true
        done
        if ! "$known"; then
            echo "refusing to refresh: $installed is not a qinit hook source." >&2
            exit 1
        fi
    done
else
    mkdir -p "$hooks"
    mkdir "$sources"
fi

for f in "$top"/.githooks/*; do
    [ -f "$f" ] || continue
    name="$(basename "$f")"
    [ "$name" = setup-hooks.sh ] && continue
    cp "$f" "$sources/$name"
    chmod 755 "$sources/$name"
    if ! "$refresh"; then
        ln -s "qinit/$name" "$hooks/$name"
    fi
done
if "$refresh"; then
    echo "refreshed clone-local hook sources in $sources"
else
    echo "installed clone-local hook sources in $sources and linked active hooks in $hooks"
fi
