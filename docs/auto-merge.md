<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trusted GitHub auto-merge

GitHub is canonical for Credarr. Gitea is a read-only pull mirror.
Agents open GitHub pull requests; the gate uses the short-lived
`GITHUB_TOKEN`.

## Open a PR

Open a normal GitHub pull request from a branch or a fork. No agent token is
needed. Draft PRs are ignored.

## Gate

`.github/workflows/auto-merge.yml` on `main` uses `pull_request_target`, so the
workflow comes from the protected base branch.

- `verify` is read-only. It checks out the trusted base and the PR merge ref,
  runs `bin/pr_policy.py --forge github`, `bin/verify_pr.sh`, gitleaks, and
  `git diff --check`. It never executes PR code.
- `merge` has write permission and checks out nothing. It waits for the
  required CI checks and merges the exact verified head with
  `gh pr merge --merge --match-head-commit`.
- The only token is GitHub's short-lived `GITHUB_TOKEN`. Fork PRs are
  supported; the verify job is read-only and the merge job has no checkout.

## Consumer scripts

- `bin/pr_policy.py --forge github` checks PR metadata, size, protected paths,
  secret markers, and fork/size rules.
- `bin/scan_private.py` checks the PR tree for private paths and token shapes.
- `bin/verify_pr.sh` runs the private-path scan and compiles the gate scripts.

The full test and lint suite remains the GitHub CI `pull-request` and `console`
checks. The verifier adds policy, secret, and private-path checks.

## Branch protection

Require `auto-merge / verify` plus the PR CI checks on `main`; disable force
pushes and branch deletion.

## GitHub Actions policy

GitHub's default policy blocks `pull_request_target` in public repositories from
2026-12-02 unless an applicable Actions policy explicitly allows it. This
repository has an active policy that allows only
`.github/workflows/auto-merge.yml` to use `pull_request_target`. If the policy
is removed or the workflow path changes, the gate will not run.

## Gitea mirror

Gitea pulls GitHub `main` and tags read-only. It does not accept PRs and never
pushes back. See the harness mirror doc for the migration policy.

## Protected paths

Workflow, build, dependency, deploy, and gate changes are blocked from
auto-merge. A gate change requires a manual reviewed merge. Repo admins can use
the GitHub admin override for these changes after review; the auto-merge bot
cannot.

## First proof

The GitHub gate was first exercised on 2026-11-17 with a docs-only PR.
