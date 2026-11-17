<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trusted auto-merge

Gitea is canonical. Agents open pull requests with AGit; no agent holds a
Gitea token.

```sh
git push origin HEAD:refs/for/main
```

The owner-level scoped workflow from `admin/libreharness` runs on this
repository with this repository's runner and short-lived `GITEA_TOKEN`. It
checks the consumer base scripts in `bin/` and merges eligible PRs.

## Consumer scripts

- `bin/pr_policy.py` checks PR metadata, size, protected paths, and forbidden
  files.
- `bin/pr_status.py` publishes `verifier / policy`.
- `bin/pr_merge.py` requires that status and pins the verified head.
- `bin/scan_private.py` checks the PR tree for private paths and token shapes.
- `bin/verify_pr.sh` runs the repo-specific checks.

The full test and lint suite remains `gitea-ci / pull-request`; the verifier
adds policy, secret, and private-path checks.

## Protected paths

Workflow, build, dependency, deploy, and gate changes are blocked from
auto-merge. Use the operator `pr_watch` path for those.
