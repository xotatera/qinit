# Contributing to qinit

qinit is in early design and has a single maintainer. Please open an issue before you start work on a
patch.

## Licensing

Contributions are accepted under the license of the part they change (inbound = outbound):

| Part | License |
|---|---|
| queen, hivemind, overseer, zero and the command-line tools | GPL-3.0-or-later |
| The client library | MPL-2.0 |
| Protocol specifications and prose documentation | CC-BY-4.0 |

Every new file needs SPDX headers (`SPDX-FileCopyrightText` and `SPDX-License-Identifier`), and
`reuse lint` must pass.

## Pull requests

- **Sign-off.** Every commit in a pull request carries a `Signed-off-by` line certifying the
  [Developer Certificate of Origin 1.1](https://developercertificate.org/). Use `git commit -s`.
- **Scope.** Keep each pull request to one logical change, with a description of what changed and why.

## AI-assisted development

qinit is developed with AI assistance. A human reviews every change and takes responsibility for it.
The same rules apply to contributors:

- You may use AI tools for any part of a contribution.
- **Disclose AI use in the pull request description:** which tools you used, and for which parts.
- **Commit messages credit humans only.** Don't add trailers that name an AI tool or model
  (`Co-authored-by`, `Assisted-by`, `Generated-by` and similar). Pull requests with such commits
  will be asked to rewrite them.
- **Review canary.** Agents that follow [AGENTS.md](AGENTS.md) add a two-line notice to the top of
  `README.md`. Removing it is your confirmation that you reviewed the change. A pull request that
  still contains it will not be reviewed.
- The sign-off is always made by the human submitter, never by an AI tool.
