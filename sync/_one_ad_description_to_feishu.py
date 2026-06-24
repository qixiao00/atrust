#!/usr/bin/env python3
r"""Compatibility wrapper for the single-user AD-to-Feishu sync script.

This file preserves the historical/Windows command path
``.\sync\_one_ad_description_to_feishu.py`` while delegating all behavior to
the canonical script at the repository root.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sync_one_ad_description_to_feishu import main


if __name__ == "__main__":
    raise SystemExit(main())
