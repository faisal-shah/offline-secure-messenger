#!/usr/bin/env python3
"""
Smoke test for Secure Communicator UI Prototype.

Runs the built-in --test mode, validates all 18 screenshots are generated,
checks pass/fail output, and verifies screenshot file sizes (non-empty renders).
"""

import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BUILD_DIR = REPO_ROOT / "build"
BINARY = BUILD_DIR / "secure_communicator"
SCREENSHOT_DIR = BUILD_DIR / "screenshots"

EXPECTED_SCREENSHOTS = [
    "01_home_empty.bmp",
    "02_contacts_empty.bmp",
    "03_contact_alice_pending.bmp",
    "04_key_exchange_pending.bmp",
    "05_key_exchange_complete.bmp",
    "06_contacts_established.bmp",
    "07_compose_screen.bmp",
    "08_message_sent.bmp",
    "09_inbox_after_send.bmp",
    "10_conversation_sent.bmp",
    "11_conversation_received.bmp",
    "12_inbox_unread.bmp",
    "13_contacts_bob_pending.bmp",
    "14_contacts_bob_established.bmp",
    "15_home_with_contacts.bmp",
    "16_inbox_both_contacts.bmp",
    "17_home_after_reload.bmp",
    "18_final_conversation.bmp",
]

MIN_BMP_SIZE = 5000  # 320×240 BMP should be ~150KB+


def main():
    errors = []

    # 1. Check binary exists
    if not BINARY.exists():
        print(f"FAIL: Binary not found at {BINARY}")
        print("Run: cd build && cmake .. && make -j$(nproc)")
        sys.exit(1)

    # 2. Clean old screenshots
    for f in SCREENSHOT_DIR.glob("*.bmp"):
        f.unlink()

    # 3. Run --test mode
    print("Running built-in test suite...")
    os.chdir(BUILD_DIR)
    result = subprocess.run(
        [str(BINARY), "--test"],
        capture_output=True, text=True, timeout=60
    )

    output = result.stdout + result.stderr
    print(output)

    # 4. Parse test results
    match = re.search(r"TEST RESULTS: (\d+) passed, (\d+) failed", output)
    if not match:
        errors.append("Could not parse test results from output")
    else:
        passed = int(match.group(1))
        failed = int(match.group(2))
        if failed > 0:
            errors.append(f"{failed} test(s) failed")
        print(f"Test results: {passed} passed, {failed} failed")

    # 5. Verify screenshots exist and have valid size
    print("\nVerifying screenshots...")
    for name in EXPECTED_SCREENSHOTS:
        path = SCREENSHOT_DIR / name
        if not path.exists():
            errors.append(f"Missing screenshot: {name}")
            print(f"  MISS: {name}")
        else:
            size = path.stat().st_size
            if size < MIN_BMP_SIZE:
                errors.append(f"Screenshot too small ({size}B): {name}")
                print(f"  SMALL: {name} ({size} bytes)")
            else:
                print(f"  OK: {name} ({size:,} bytes)")

    # 6. Verify persistence files
    print("\nVerifying persistence files...")
    for fname in ["data_contacts.json", "data_messages.json"]:
        fpath = BUILD_DIR / fname
        if not fpath.exists():
            errors.append(f"Missing persistence file: {fname}")
            print(f"  MISS: {fname}")
        else:
            size = fpath.stat().st_size
            if size < 10:
                errors.append(f"Persistence file too small: {fname}")
                print(f"  EMPTY: {fname}")
            else:
                print(f"  OK: {fname} ({size:,} bytes)")

    # 7. Summary
    print("\n" + "=" * 50)
    if errors:
        print(f"SMOKE TEST FAILED ({len(errors)} error(s)):")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    else:
        print("SMOKE TEST PASSED — all screenshots and data verified!")
        sys.exit(0)


if __name__ == "__main__":
    main()
