#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Publish a Gitea commit status without printing the token."""

# ruff: noqa: S310

import argparse
import json
import os
import sys
import urllib.error
import urllib.request


def publish(
    api: str,
    repo: str,
    sha: str,
    state: str,
    context: str,
    description: str,
    target_url: str,
    token: str,
) -> int:
    body = json.dumps(
        {
            "state": state,
            "context": context,
            "description": description,
            "target_url": target_url,
        }
    ).encode()
    request = urllib.request.Request(
        f"{api.rstrip('/')}/repos/{repo}/statuses/{sha}",
        data=body,
        method="POST",
        headers={
            "Authorization": f"token {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"Gitea status API: HTTP {error.code}") from None
    except (urllib.error.URLError, OSError) as error:
        raise RuntimeError(f"Gitea status API: {error}") from None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="OWNER/REPO")
    parser.add_argument("--head", required=True, help="commit SHA")
    parser.add_argument(
        "--state",
        required=True,
        choices=("success", "failure", "error", "pending"),
    )
    parser.add_argument("--context", default="verifier / policy")
    parser.add_argument("--description", default="")
    parser.add_argument("--target-url", default="")
    parser.add_argument(
        "--api",
        default=os.environ.get("GITEA_URL", ""),
        help="Gitea API base; defaults to GITEA_URL",
    )
    args = parser.parse_args()

    token = os.environ.get("GITEA_TOKEN", "")
    if not token:
        print("pr_status: GITEA_TOKEN is not set", file=sys.stderr)
        return 2
    if not args.api:
        print("pr_status: GITEA_URL or --api is required", file=sys.stderr)
        return 2

    try:
        code = publish(
            args.api,
            args.repo,
            args.head,
            args.state,
            args.context,
            args.description,
            args.target_url,
            token,
        )
    except RuntimeError as error:
        print(f"pr_status: {error}", file=sys.stderr)
        return 2
    print(
        f"pr_status: {args.state} {args.context} on {args.head[:12]} "
        f"(HTTP {code})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
