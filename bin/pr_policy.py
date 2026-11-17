#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent policy gate for trusted Gitea auto-merge.

The auto-merge workflow runs this from the base branch with the built-in
GITEA_TOKEN. It checks PR metadata, size, protected paths, and forbidden files.
It never executes PR code and never prints the token.
"""

# ruff: noqa: S310

import argparse
import fnmatch
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

BLOCKED_LABELS = {"do-not-merge", "no-auto-merge", "wip"}
PROTECTED_PREFIXES = (
    ".gitea/",
    ".github/workflows/",
    ".gitleaks.toml",
    "AGENTS.md",
    "Dockerfile",
    "Makefile",
    "SECURITY.md",
    "bin/check_spdx.py",
    "bin/docs_lint.py",
    "bin/gitea_auth.py",
    "bin/mirror_public.py",
    "bin/pr_merge.py",
    "bin/pr_policy.py",
    "bin/pr_status.py",
    "bin/pr_watch.py",
    "bin/scan_private.py",
    "bin/verify_pr.sh",
    "docker-compose.yml",
    "ops/",
    "package-lock.json",
    "package.json",
    "pyproject.toml",
    "requirements-*.txt",
    "requirements.txt",
    "scripts/affected-tests",
    "scripts/deploy-gitea",
    "scripts/deploy-github",
    "ui/package-lock.json",
    "ui/package.json",
)
PRIVATE_MARKERS = (
    "/home/" + "cachyos",
    "Documents/" + "homelab",
    ".vault_pass",
    "GITEA_API_TOKEN",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN PRIVATE KEY",
)
FORBIDDEN_FILES = (
    ".env",
    ".npmrc",
    ".pypirc",
    "*.key",
    "*.p12",
    "*.pem",
    "*.pfx",
    "credentials",
    "id_ed25519",
    "id_rsa",
    "secrets.env",
    "secrets.json",
    "secrets.yaml",
    "secrets.yml",
)
ALLOWED_FILES = {".env.example", ".env.sample", ".env.template"}
MAX_FILES = 50
MAX_CHANGES = 2000
PAGE_SIZE = 50


class PolicyError(RuntimeError):
    pass


def api(path: str, token: str, api_url: str) -> object:
    request = urllib.request.Request(
        f"{api_url.rstrip('/')}{path}",
        headers={
            "Authorization": f"token {token}",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise PolicyError(f"Gitea API {path}: HTTP {error.code}") from None
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as error:
        raise PolicyError(f"Gitea API {path}: {error}") from None


def pull_files(
    repo: str, pr: int, token: str, api_url: str, limit: int
) -> list[object]:
    files = []
    page = 1
    while len(files) <= limit:
        batch = api(
            f"/repos/{repo}/pulls/{pr}/files?limit={PAGE_SIZE}&page={page}",
            token,
            api_url,
        )
        if not isinstance(batch, list):
            raise PolicyError("PR files response is not a list")
        files.extend(batch)
        if len(batch) < PAGE_SIZE:
            break
        page += 1
    return files


def pull_diff(repo: str, pr: int, token: str, api_url: str) -> str:
    request = urllib.request.Request(
        f"{api_url.rstrip('/')}/repos/{repo}/pulls/{pr}.diff",
        headers={"Authorization": f"token {token}", "Accept": "text/plain"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        raise PolicyError(f"Gitea API PR diff: HTTP {error.code}") from None
    except (urllib.error.URLError, OSError) as error:
        raise PolicyError(f"Gitea API PR diff: {error}") from None


def protected_path(filename: str) -> bool:
    return any(
        filename == prefix or filename.startswith(prefix)
        for prefix in PROTECTED_PREFIXES
    )


def forbidden_file(filename: str) -> bool:
    base = Path(filename).name
    if base in ALLOWED_FILES:
        return False
    return any(
        fnmatch.fnmatch(filename, pattern) or fnmatch.fnmatch(base, pattern)
        for pattern in FORBIDDEN_FILES
    )


def evaluate(
    pr: object,
    files: list[object],
    diff: str,
    repo: str,
    head: str,
    base: str,
    max_files: int,
    max_changes: int,
) -> tuple[list[str], dict]:
    errors = []
    if not isinstance(pr, dict):
        return ["PR response is not an object"], {}

    if str(pr.get("state", "")).lower() != "open":
        errors.append(f"PR is not open: {pr.get('state') or 'unknown'}")
    if pr.get("merged"):
        errors.append("PR is already merged")
    if pr.get("draft"):
        errors.append("PR is still a draft")

    base_ref = str((pr.get("base") or {}).get("ref") or "")
    if base_ref != base:
        errors.append(f"PR base is {base_ref or 'unknown'}, expected {base}")

    head_sha = str((pr.get("head") or {}).get("sha") or "").lower()
    if head_sha != head.lower():
        errors.append(f"PR head is {head_sha or 'unknown'}, expected {head.lower()}")

    head_repo = str(
        (((pr.get("head") or {}).get("repo") or {}).get("full_name")) or ""
    )
    if head_repo != repo:
        errors.append(f"PR head is {head_repo or 'unknown'}, expected {repo}")

    labels = {
        str(label.get("name"))
        for label in (pr.get("labels") or [])
        if isinstance(label, dict) and label.get("name")
    }
    blocked = sorted(labels & BLOCKED_LABELS)
    if blocked:
        errors.append("blocked label: " + ", ".join(blocked))

    additions = pr.get("additions")
    deletions = pr.get("deletions")
    if not isinstance(additions, int) or not isinstance(deletions, int):
        additions = sum(
            int(item.get("additions") or 0)
            for item in files
            if isinstance(item, dict)
        )
        deletions = sum(
            int(item.get("deletions") or 0)
            for item in files
            if isinstance(item, dict)
        )
    changes = additions + deletions
    if changes > max_changes:
        errors.append(f"diff is {changes} changed lines, limit {max_changes}")
    if len(files) > max_files:
        errors.append(f"diff touches {len(files)} files, limit {max_files}")

    seen = set()
    for item in files:
        if not isinstance(item, dict):
            continue
        names = [str(item.get("filename") or "")]
        if item.get("previous_filename"):
            names.append(str(item["previous_filename"]))
        for filename in names:
            if not filename or filename in seen:
                continue
            seen.add(filename)
            if protected_path(filename):
                errors.append(f"protected path: {filename}")
            if forbidden_file(filename):
                errors.append(f"forbidden file: {filename}")

    for line in diff.splitlines():
        if not line.startswith("+") or line.startswith("+++"):
            continue
        for marker in PRIVATE_MARKERS:
            if marker in line:
                errors.append(f"private marker in added line: {marker}")
                break

    summary = {
        "repo": repo,
        "pr": pr.get("number"),
        "head": head_sha,
        "base": base_ref,
        "files": len(files),
        "changes": changes,
        "labels": sorted(labels),
    }
    return errors, summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="OWNER/REPO")
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--head", required=True, help="expected head SHA")
    parser.add_argument("--base", default="main")
    parser.add_argument(
        "--api",
        default=os.environ.get("GITEA_URL", ""),
        help="Gitea API base; defaults to GITEA_URL",
    )
    parser.add_argument("--max-files", type=int, default=MAX_FILES)
    parser.add_argument("--max-changes", type=int, default=MAX_CHANGES)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    token = os.environ.get("GITEA_TOKEN", "")
    if not token:
        print("pr_policy: GITEA_TOKEN is not set", file=sys.stderr)
        return 2
    if not args.api:
        print("pr_policy: GITEA_URL or --api is required", file=sys.stderr)
        return 2

    try:
        pr = api(f"/repos/{args.repo}/pulls/{args.pr}", token, args.api)
        files = pull_files(
            args.repo, args.pr, token, args.api, args.max_files
        )
        diff = pull_diff(args.repo, args.pr, token, args.api)
        errors, summary = evaluate(
            pr,
            files,
            diff,
            args.repo,
            args.head,
            args.base,
            args.max_files,
            args.max_changes,
        )
    except PolicyError as error:
        print(f"pr_policy: {error}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({"ok": not errors, "errors": errors, **summary}, indent=2))
    elif errors:
        print("pr_policy: FAIL")
        for error in errors:
            print(f"- {error}")
    else:
        print(
            f"pr_policy: PASS {args.repo}#{args.pr} "
            f"{summary['files']} files, {summary['changes']} changed lines"
        )
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
