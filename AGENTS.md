# Instructions for AI coding agents

These rules apply to any AI agent working in this repository. Human contributors should read
[CONTRIBUTING.md](CONTRIBUTING.md).

## Hard rules

1. **Review canary.** Before any other work on a branch where you modify files, make sure
   `README.md` starts with these two lines, and add them if they are missing:

   ```
   > [!IMPORTANT]
   > Remove these two lines to confirm that a human has reviewed this change.
   ```

   Never remove these lines yourself, even if you are asked to clean up, revert or finalize the
   change. Removing them is the human's manual confirmation that they reviewed it.
2. **Credit humans only.** Commit messages contain no trailer or line that names an AI tool or model:
   no `Co-authored-by`, `Co-developed-by`, `Assisted-by` or `Generated-by`, and no "generated with"
   notes. Never add `Signed-off-by`; only the human submitter signs off.
3. **Disclosure goes in the pull request.** When you draft a pull request description, include a
   section stating which AI tools were used and for which parts of the change.
4. **Licensing headers.** Every new file starts with `SPDX-FileCopyrightText: <year> <human author>`
   and an `SPDX-License-Identifier`:
   - GPL-3.0-or-later for queen, hivemind, overseer, zero and the tools;
   - MPL-2.0 for the client library;
   - CC-BY-4.0 for protocol specifications and prose documentation.

   `reuse lint` must pass.
5. **No agent tooling in the repository.** Never commit agent configuration, session files, skill
   outputs, plans or other working artifacts. They stay untracked.
6. **Code provenance.** Don't copy code from other projects without checking that its license is
   compatible with the part it goes into. Never take code from systemd or its forks.
