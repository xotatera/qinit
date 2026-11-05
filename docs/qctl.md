<!--
SPDX-FileCopyrightText: 2026 Xota Tera
SPDX-License-Identifier: CC-BY-4.0
-->

# qctl

`qctl` is the configuration compiler and the command-line client of the colony. It compiles frame
layers into a database, shows and fills the frames as the compiler sees them, and talks to the
running colony over the control protocol (`docs/control-protocol.md`) to inspect, change, launch
and watch. The database format is `docs/db-format.md`; the request that `run` builds is the
launch request of `docs/launch-request.md`.

## Synopsis

```
qctl [--socket PATH] <command> ...

qctl compile [--layer NAME=DIR]... [--policy FILE | --no-policy] [--output FILE] [--dump FILE]
qctl show    [--layer NAME=DIR]... [--policy FILE | --no-policy] <kind>.<name>... | policy
qctl fill    [--layer NAME=DIR]... [--policy FILE | --no-policy] [--dry-run]
             <kind>.<name>... | policy | all
qctl status <target>
qctl list [all | workers | foragers | broods]
qctl start | stop | restart | clear <node> [--wait MS]
qctl refresh <db> [--wait MS]
qctl poweroff | reboot | halt [--wait MS]
qctl launch <frame> [--env K=V]... [--fds stdin,stdout,stderr] [--pidfd] [--wait MS] [-- ARG...]
qctl run <request.toml> --name NAME [--fds ...] [--wait-ready] [--memory-max KIB]
         [--pids-max N] [--stop-mode main|cell] [--stop-grace MS] [--wait MS]
qctl watch --all | <target>
```

Options are `--key value` or `--key=value`. `--` ends the options. An unknown option or command
is a usage error. `--socket` and `--help` are accepted anywhere; `--help` prints the synopsis and
exits 0.

| Option | Commands | Meaning |
|---|---|---|
| `--socket PATH` | all | The colony socket. Default `/run/qinit/colony`. |
| `--layer NAME=DIR` | compile, show, fill | One layer, lowest first; may repeat. |
| `--policy FILE` | compile, show, fill | The policy file. Excludes `--no-policy`. |
| `--no-policy` | compile, show, fill | No policy check. Excludes `--policy`. |
| `--output FILE` | compile | The database to write. |
| `--dump FILE` | compile | Also write the compiler's dump (origin of every value) to `FILE`. |
| `--dry-run` | fill | Print a unified diff of each file instead of writing. |
| `--wait MS` | start, stop, restart, clear, refresh, poweroff, reboot, halt, launch, run | Wait for the request to settle, 1 to 600000 ms. |
| `--env K=V` | launch | An environment entry of the instance; may repeat. |
| `--fds ROLES` | launch, run | Pass `qctl`'s own standard streams for these roles (comma-separated `stdin`, `stdout`, `stderr`). Default none. |
| `--pidfd` | launch | Ask for a pidfd; the outcome is read from it where the kernel can say. |
| `--name NAME` | run | The instance's name (required). |
| `--wait-ready` | run | End the wait when the instance reports readiness. |
| `--memory-max KIB` | run | Memory ceiling in KiB. Default 0: none. |
| `--pids-max N` | run | Process-count ceiling. Default 0: none. |
| `--stop-mode main\|cell` | run | Stop the main process or the whole cell. Default `main`. |
| `--stop-grace MS` | run | Grace before the kill. Default 10000. |
| `--all` | watch | Every node and instance. |

`show` and `fill` take a target `<kind>.<name>` where kind is `worker`, `forager`, `brood` or
`template`; `show` also takes `policy`, and `fill` takes `policy` and `all`. An instance name
(`worker.getty@tty1`) is accepted and means its frame.

## Defaults

| What | Default |
|---|---|
| Layers | `vendor=/usr/lib/qinit/frames`, then `etc=/etc/qinit/frames`. |
| Policy | `/etc/qinit/policy.toml` when it exists, otherwise none. |
| Output | `/etc/qinit/colony.db`. |
| Socket | `/run/qinit/colony`. |
| `--wait` of `launch`, `run` | 600000 ms. |
| `--wait` of the other commands | none: the reply comes on acceptance. |

`--layer` replaces the default layer list as a whole: with one `--layer` given, neither `vendor`
nor `etc` is added. Given layers are used in the order given, lowest first.

An absent default `vendor` layer is an error. An absent default `etc` layer is a notice
(`qctl: etc layer /etc/qinit/frames absent, taken as empty`) and the layer is empty. A layer named
with `--layer` that is absent is an error, and so is a `--policy` file that is absent. When the
policy is not named, `qctl` says on standard error which it did: `qctl: policy <file>` or
`qctl: no policy file <file>, compiling without a policy check`; `--no-policy` and `--policy`
print neither.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Done. |
| 1 | Refused or failed. The message on standard error says by whom: the compiler, the ownership check, the colony (`qctl: colony refused: <code> (<detail>)`), or the system. An error in a request file is exit 1. |
| 2 | Usage: an unknown command or option, a missing or surplus argument, a malformed value, a `--wait` outside 1 to 600000. |

`launch` and `run` exit with the instance's status when it exited: its exit code, or 128 plus the
signal that killed it. They exit 0 when the wait ended first.

## compile

`qctl compile` reads the layers and the policy, compiles them and writes the database. A compile
error is printed one per line as `<file>:<line>: <key>: <message>`; when the key's line cannot be
found it is `<file>: <key>: <message>`. All errors are printed, then the exit code is 1 and no
database is written. A warning is printed as `warning: <key>: <message>` and does not stop the
compile. The database is written to a new temporary file beside the output, `<output>.tmp-<pid>`
(mode 0644, created exclusively: anything already at that name, a symbolic link included, fails
the write and is left alone), synced and renamed over the output, and then the directory is
synced, so a reader never sees a partial file. `--dump` is written the same way, and first: when
the dump cannot be written, the database is not written either. As root, the directory of the
output and of the dump, and every ancestor of it up to `/`, must pass the rule below, or nothing
is written:

```
qctl: <path>: owned by uid <n>, mode <octal>: the output directory must be root's and not writable by group or other
```

## Ownership

`compile`, `show` and `fill` read the policy and the layers, and as root they check them first.
When the effective user id is 0, `qctl` checks the policy file, each layer directory, every file
and directory below each layer, and every ancestor directory of each of them up to `/`:

- `lstat` is used and no symbolic link is followed; a symbolic link anywhere in the set is refused;
- the owner is uid 0;
- no group or other write bit is set (`mode & 0o022 == 0`). A sticky world-writable ancestor such
  as `/tmp` fails too: a layer below it is not a system layer.

The first failure refuses the run with exit 1, before anything is read:

```
qctl: <path>: owned by uid <n>, mode <octal>: the policy and the layers must be root's and not writable by group or other
qctl: <path>: is a symbolic link
qctl: <path>: <error>
```

The last form is a path that cannot be examined or a directory that cannot be listed, with the
system's error.

When the user is not root the check does not run, and one line goes to standard error:

```
qctl: not root: the ownership of the policy and layers is not checked
```

`qctl` reads no environment variable as root. The check is against misconfiguration, not against a
concurrent writer: it is not atomic with the read, since the compiler reads the same paths by name
afterwards. A tree that passed can then be changed only by root. When `/proc/self` cannot be read
the user is taken as root, so the check runs rather than being skipped.

## show

`qctl show` prints the effective frames as TOML. It compiles the layers (so a compile error
stops it with exit 1) and prints each target in the order given, separated by a blank line.

- A frame starts with `[<kind>.<name>]` and has one line `key = value  # <origin>` per key, in the
  order of the compiler's dump, with nested keys as dotted keys. The origin is `vendor`, `etc` (the
  layer's name), `template <name>` or `default`.
- A value a layer wrote is printed as written (so `%i` and units stay); a default is printed as
  the resolved value (`umask` as `0o027`, durations in milliseconds). Inline tables print their
  keys sorted.
- `deps` is a multi-line array, one group per line with its origin.
- A template reference is resolved: a comment line `# template "<name>" (<origin>) is resolved ...`
  follows the header, and the keys the frame inherits carry `# template <name>`.
- An instance name prints its frame, after the line `# <frame>@<inst> is an instance of
  <kind>.<frame>`; the `instances` list is printed. Instances have no tables of their own.
- A `template.<name>` target prints the template as its layers merged it, with each key's origin.
- A few defaults that TOML cannot express are printed as comments, so the output compiles back to
  the same nodes: `# start_timeout = "none"` (a node ready on exit), `# sandbox.user_map = "own"`
  (without a user namespace), and for a policy rule `# users: any user`. Derived values (`errors`
  following `output`) are left out.
- `show policy` prints the policy with every rule and every key, a default marked `# default` and
  a value from the file marked `# policy`. It needs a policy file: with `--no-policy` or without a
  file it exits 1.

Example, from a vendor layer and an `etc` layer (excerpt):

```
$ qctl show --layer vendor=vendor --layer etc=etc --no-policy worker.sshd
[worker.sshd]
exec = ["/usr/sbin/sshd", "-D", "-e"]  # vendor
ready = "pipe"  # vendor
restart.policy = "on-failure"  # vendor
restart.max = 9  # etc
restart.window = "120s"  # vendor
restart.delay = "1000ms"  # default
...
output = { pipe = "logd" }  # vendor
...
# sandbox.user_map = "own"  # default
...
```

## fill

`qctl fill` writes the implicit defaults into the administrator's files, so that they are visible
and pinned. It inserts lines and changes nothing else: no key is reordered, no comment or blank
line is touched, no value is re-serialised.

**Which keys.** The keys whose origin is `default` and whose default is a constant of the schema:
`ready`, `restart.*`, `stop.*`, `start_timeout`, `cell.*`, `cwd`, `umask`, `credentials.caps`,
`credentials.nnp`, `credentials.securebits` and `sandbox.*`; for the policy, the rule keys
`caps_max`, `require_nnp`, `require_seccomp`, `allow_userns`, `allow_inside_ids` and
`allow_idmap` that a rule leaves out. It never writes the defaults that `show` prints as comments,
nor derived values.

**Which file.** Only the last layer is written, never the vendor layer (the lowest layer is the
package manager's and an update would undo the edit). With `--layer` given exactly once `fill`
refuses: the one layer would be the lowest. Without `--layer` the last layer is the default `etc`
layer, created when absent (as root only below directories that pass the ownership rule). The key
goes into the file of that layer that already has a table for the frame; when there is none, into a
file of the same base name as the file that declared the frame, with a new `[<kind>.<name>]`
header. The policy is written in place. A target that is an instance fills its frame.

**Templates.** A key goes into the template's table, once, when the frame takes the field from
the template (it does not set that field itself) and every frame using the template that does
not set the field either has the same default for it; frames that set the field are left out of
that comparison. Otherwise it goes into the frame. When it would go into a frame that takes the
field from a template which sets part of that field, `fill` refuses: the frame's key would replace
the template's whole field. `fill template.<name>` fills what the frames leave to that template.

**Where.** After the last key of the table. A key below a standard table that exists
(`[worker.x.restart]`) goes into it; below an inline table (`restart = { max = 9 }`) it goes
inside the braces; otherwise it is written in dotted form into the frame's table.

**How it looks.** `  <key> = <value>  # default, filled by qctl`, the value in the syntax `show`
prints. Inside an inline table the key is inserted without the comment.

**Refusals.** `fill` parses each file with `toml_edit` and refuses, writing nothing, a file that
`toml_edit` cannot write back byte for byte: a file with the keys of one dotted table apart, one
with no trailing newline, or one with CRLF line ends (the refusal says which of the last two it
is). A file that is a symbolic link or not a regular file is refused. The ownership check applies
as for `compile`.

**Safety.** Every file is edited first, then the new text of every file is written to a new
temporary file beside it with the old file's mode and owner, and only when all of them are
written are they renamed over their files: a file that cannot be edited, or whose temporary file
cannot be written or given the owner and mode, stops the run with no file changed. `--dry-run` prints the unified diff of every file (`--- <path>` / `+++ <path>`, or
`--- /dev/null` for a file that would be created) and writes nothing. When there is nothing to
fill it prints `qctl: fill: nothing to fill` and exits 0, so a second `fill` is a no-op. A real
fill prints `qctl: fill: <n> keys filled in <m> files`, counting the files written. After a fill, `compile` yields the same
database as before: only defaults were written. The database itself is never touched.

Example (`etc/sshd.toml` contains `restart = { max = 9 }`; `qctl fill ... --dry-run worker.sshd`,
excerpt):

```
--- etc/sshd.toml
+++ etc/sshd.toml
@@ -1,4 +1,14 @@
 # SPDX-FileCopyrightText: 2026 Xota Tera
 # SPDX-License-Identifier: GPL-3.0-or-later
 [worker.sshd]
-restart = { max = 9 }
+restart = { max = 9, delay = "1000ms" }
+  stop.mode = "main"  # default, filled by qctl
+  stop.grace = "10000ms"  # default, filled by qctl
+  start_timeout = "90000ms"  # default, filled by qctl
+  cwd = "/"  # default, filled by qctl
 ...
```

## The request file for run

`qctl run request.toml --name NAME` reads a TOML file whose keys are the fields of the launch
request (`docs/launch-request.md`), sends it to the colony and starts an instance named
`~NAME#<id>`. An unknown key is an error, and so is a missing `argv`. A key left out takes the
default below. A file that cannot be read or parsed, or a value that is not valid, is exit 1 with
`qctl: <file>: <why>` before anything is sent. `qctl` checks each value as the table says, and a
request over 64 KiB once laid out; the overseer judges the rest of the request
(`docs/launch-request.md`), and its refusal comes back from colony.

| Key | Type | Default | Notes |
|---|---|---|---|
| `argv` | list of strings | required | Program and arguments. |
| `env` | list of `"K=V"` strings | `[]` | |
| `cwd` | string | `"/"` | An absolute path. |
| `umask` | TOML integer | `0o027` | Write it as an integer (`0o022`), not a string; at most `0o777`. |
| `rlimits` | table | none | Resource name to a number or `"infinity"`; byte limits also take a size (`"64M"`). Same names and rules as a frame's `rlimits`. |
| `user` | string | empty | The user to run as; the overseer needs a name of 1 to 96 bytes, so give one. |
| `caps` | list of names | `[]` | Capability names, e.g. `"net_bind_service"`. |
| `securebits` | string | `"none"` | `none`, `noroot`, `noroot-locked`. |
| `nnp` | bool | `true` | |
| `namespaces` | list of names | `[]` | `mount`, `pid`, `ipc`, `uts`, `net`, `user`. |
| `user_map` | string | `"own"` | `own`, `range`. |
| `inside_uid`, `inside_gid` | integer | `0` | |
| `seccomp` | string | `"none"` | `none`, `default`, `deny`, `allow`. |
| `syscalls` | list of names | none | Syscall names, only with `deny` or `allow` (at least one); with another mode it is an error. |
| `paths` | list of strings | `[]` | `<mode>:<path>` entries. |
| `stdin`, `stdout` | string | `"/dev/null"` | A path or `"fd:N"`. `"same"` is refused. |
| `stderr` | string | `"same"` | A path, `"fd:N"` or `"same"` (wherever stdout goes). |
| `ready_fd` | integer | none | The descriptor the readiness pipe arrives on. |
| `die_with_parent` | bool | `false` | |
| `deadline_ms` | integer | `30000` | At least 1. |

A complete file that `qctl run` accepts:

```toml
argv = ["/usr/bin/job", "--once"]
env = ["LANG=C", "JOB_MODE=batch"]
cwd = "/work"
umask = 0o022
user = "svc"
caps = ["net_bind_service"]
securebits = "noroot"
nnp = true
namespaces = ["mount", "user"]
user_map = "range"
inside_uid = 1000
inside_gid = 1000
seccomp = "deny"
syscalls = ["ptrace", "reboot"]
paths = ["ro:/usr", "rw:/work"]
stdin = "/dev/null"
stdout = "fd:6"
stderr = "same"
ready_fd = 7
die_with_parent = true
deadline_ms = 5000

[rlimits]
nofile = 1024
cpu = "infinity"
as = "64M"
```

## Control commands

These commands connect to the colony socket. A refusal by the colony is exit 1 with
`qctl: colony refused: <code> (<detail>)`.

`--wait MS` (1 to 600000) makes the request settle before the reply; without it the reply comes
on acceptance. A state is printed as its name with `/<detail>` where it has one: `off`, `waiting`
(`/dependency`, `/backoff`), `starting`, `ready`, `done`, `stopping`, `quarantined` (`/breaker`,
`/cascade`, `/start-timeout`, `/stop-failed`).

| Command | Output |
|---|---|
| `list [all\|workers\|foragers\|broods]` | One line per entry over every page: `<kind> <name> <state>[/detail]`, kind `worker`, `forager` or `brood`. Default `all`. |
| `status <node>` | Fields, one per line: `name:`, `kind:`, `state:`, `blocking: group <group> on <target>` (only when blocked), `backoff_ms:`, `since_ms:`, `restarts:`, `pid:` (only with a process). |
| `status <frame>#<id>` | An instance: `frame:`, `id:`, `state:` (`starting`, `running`, `exited`, `stopping`), `status:` (once exited), `pid:` (with a process). |
| `start`, `stop`, `restart`, `clear`, `refresh`, `poweroff`, `reboot`, `halt` | One line: `accepted`, `settled <state>`, `pending <state>` or `superseded <state>`. |

`pending` is exit 0: the wait ran out but the request stays in effect. `refresh` opens the
database read-only and passes the descriptor.

### launch and run

`launch` starts an instance of a frame; `run` starts one from a request file. Neither
passes a standard stream unless `--fds` names its role; the frame decides which roles it takes and
the colony refuses the rest. Output, in order:

| Line | When |
|---|---|
| `started <frame>#<id>` | The instance began. For `run` the frame is `~NAME`. |
| `exited <name> code=N` | It exited; `qctl` exits with `N`. |
| `killed <name> signal=S` | A signal ended it; `qctl` exits with `128+S`. |
| `ready <name>` | `run --wait-ready`: it reported readiness. Exit 0. |
| `still running: <name>` | The wait ran out first. Exit 0. |

If the launch fails the message is `qctl: <frame>: the launch failed at step <n>: <errno text>`
(exit 1); `qctl: <name>: its exit was not seen` (exit 1) when the status is not available. With
`--pidfd` the status is read from the pidfd where the kernel can say.

## watch

`qctl watch --all` or `qctl watch <target>` (a node, or an instance `<frame>#<id>`) prints one
line per notice and waits without limit. There is no timestamp.

| Line | Meaning |
|---|---|
| `node <name> <report> <state>[/detail] [status=N]` | A node changed. |
| `instance <frame>#<id> <report> <instance state> [status=N]` | An instance changed. |
| `swapped` | The database was swapped. |
| `shutdown-complete still=N` | Shutdown finished with `N` still populated. |
| `ended <state>` | The stream ended; exit 0. For an instance the last notice is followed by `ended exited`. |

`<report>` is one of `current`, `started`, `ready`, `done`, `stopped`, `failed`, `quarantined`,
`refused`, `lost`, `starting`, `running`, `stopping`, `exited`. A watch of everything goes on past
an instance's exit. When the colony closes the connection, `qctl: colony closed the stream` is
printed and the exit code is 1.
