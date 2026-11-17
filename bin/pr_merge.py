#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Schedule a Gitea merge only after the trusted verifier passed.

The workflow runs this from the base branch with the built-in GITEA_TOKEN. It
re-reads the PR and requires a successful verifier status before calling the
merge API. The default context is ``verifier / policy``; the scoped workflow
passes its automatic ``... / verify (pull_request_target)`` context. It never
checks out or executes PR code and never prints the token.
"""

# ruff: noqa: S310

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

BLOCKED_LABELS = {"do-not-merge", "no-auto-merge", "wip"}
VERIFIER_CONTEXT = "verifier / policy"


class MergeError(RuntimeError):
    pass


def api(
    method: str,
    path: str,
    payload: object | None,
    api_url: str,
    token: str,
) -> tuple[int, object]:
    body = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        f"{api_url.rstrip('/')}{path}",
        data=body,
        method=method,
        headers={
            "Authorization": f"token {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.read().decode()
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        detail = error.read().decode()[:300]
        return error.code, detail
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as error:
        raise MergeError(f"Gitea API {path}: {error}") from None


def verifier_state(
    status: dict, context: str = VERIFIER_CONTEXT
) -> tuple[bool, str]:
    entries = [
        item
        for item in (status.get("statuses") or [])
        if isinstance(item, dict) and item.get("context") == context
    ]
    if not entries:
        return False, f"missing required status: {context}"
    states = {str(item.get("status") or "").lower() for item in entries}
    if "success" in states:
        return True, "success"
    if "pending" in states:
        return False, f"{context} is pending"
    return False, f"{context} is {sorted(states)[0] if states else 'unknown'}"


def merge_errors(pr: object, head: str, base: str) -> list[str]:
    errors = []
    if not isinstance(pr, dict):
        return ["PR response is not an object"]
    if pr.get("merged"):
        return []
    if str(pr.get("state") or "").lower() != "open":
        errors.append(f"PR is not open: {pr.get('state') or 'unknown'}")
    if pr.get("draft"):
        errors.append("PR is still a draft")
    base_ref = str((pr.get("base") or {}).get("ref") or "")
    if base_ref != base:
        errors.append(f"PR base is {base_ref or 'unknown'}, expected {base}")
    head_sha = str((pr.get("head") or {}).get("sha") or "").lower()
    if head_sha != head.lower():
        errors.append(f"PR head is {head_sha or 'unknown'}, expected {head.lower()}")
    labels = {
        str(label.get("name"))
        for label in (pr.get("labels") or [])
        if isinstance(label, dict) and label.get("name")
    }
    blocked = sorted(labels & BLOCKED_LABELS)
    if blocked:
        errors.append("blocked label: " + ", ".join(blocked))
    return errors


def merge(
    api_url: str,
    repo: str,
    pr_number: int,
    head: str,
    base: str,
    token: str,
    merge_style: str,
    required_context: str = VERIFIER_CONTEXT,
    dry_run: bool = False,
) -> str:
    status, pr = api(
        "GET", f"/repos/{repo}/pulls/{pr_number}", None, api_url, token
    )
    if status != 200:
        raise MergeError(f"cannot read PR: HTTP {status} {pr}")
    if pr.get("merged"):
        return "already merged"
    errors = merge_errors(pr, head, base)
    if errors:
        raise MergeError("; ".join(errors))

    status, result = api(
        "GET", f"/repos/{repo}/commits/{head}/status", None, api_url, token
    )
    if status != 200:
        raise MergeError(f"cannot read status: HTTP {status} {result}")
    ok, detail = verifier_state(result, required_context)
    if not ok:
        raise MergeError(detail)

    if dry_run:
        return "would merge"

    status, result = api(
        "POST",
        f"/repos/{repo}/pulls/{pr_number}/merge",
        {
            "do": merge_style,
            "merge_when_checks_succeed": True,
            "head_commit_id": head,
            "delete_branch_after_merge": False,
        },
        api_url,
        token,
    )
    if status not in (200, 201):
        raise MergeError(f"merge failed: HTTP {status} {result}")
    return "scheduled"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="OWNER/REPO")
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--head", required=True, help="expected head SHA")
    parser.add_argument("--base", default="main")
    parser.add_argument(
        "--merge-style",
        default="merge",
        choices=("merge", "fast-forward-only", "squash", "rebase"),
    )
    parser.add_argument(
        "--api",
        default=os.environ.get("GITEA_URL", ""),
        help="Gitea API base; defaults to GITEA_URL",
    )
    parser.add_argument(
        "--required-context",
        default=VERIFIER_CONTEXT,
        help="commit status context that must be successful",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    token = os.environ.get("GITEA_TOKEN", "")
    if not token:
        print("pr_merge: GITEA_TOKEN is not set", file=sys.stderr)
        return 2
    if not args.api:
        print("pr_merge: GITEA_URL or --api is required", file=sys.stderr)
        return 2

    try:
        result = merge(
            args.api,
            args.repo,
            args.pr,
            args.head,
            args.base,
            token,
            args.merge_style,
            required_context=args.required_context,
            dry_run=args.dry_run,
        )
    except MergeError as error:
        print(f"pr_merge: {error}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps({"ok": True, "result": result}, indent=2))
    else:
        print(
            f"pr_merge: {result} {args.repo}#{args.pr} at "
            f"{args.head[:12]} ({args.merge_style})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
