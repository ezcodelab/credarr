#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail

BASE_ROOT="${BASE_ROOT:-.}"
PR_ROOT="${PR_ROOT:-.}"

python3 "$BASE_ROOT/bin/scan_private.py" --root "$PR_ROOT"
python3 -m py_compile \
  "$BASE_ROOT/bin/pr_policy.py" \
  "$BASE_ROOT/bin/pr_status.py" \
  "$BASE_ROOT/bin/pr_merge.py" \
  "$BASE_ROOT/bin/scan_private.py"
