#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Thin wrapper around scripts/gen.py so that `cd tests/newman && python gen.py`
works per the KAC-196 plan §4.1 convention. The real generator lives in
scripts/gen.py (matches the layout of kacho-iam / kacho-vpc / kacho-compute)."""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "scripts"))

from gen import main  # noqa: E402  (sys.path adjusted above)

if __name__ == "__main__":
    sys.exit(main(sys.argv))
