#!/bin/bash
# Run full Nvidia-only code coverage for mctp/mctpd.
# Coverage is SOURCE CODE ONLY (src/): mctpd.c, mctp-netlink.c, and Nvidia-authored headers.
# Test/UT code (tests/*.c, Python tests) is NOT included in the report.
# Requires: meson, ninja, gcovr, pkg-config, libsystemd-dev, dbus, pytest (for tests).
# Optional: OPENBMC_AUTOMATION = path to openbmc-automation repo (default: sibling ../openbmc-automation).

set -e
MCTP_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$MCTP_ROOT"

AUTOMATION="${OPENBMC_AUTOMATION:-$(cd "$MCTP_ROOT/../openbmc-automation" 2>/dev/null && pwd)}"
if [ -z "$AUTOMATION" ] || [ ! -f "$AUTOMATION/nvidia-code-coverage/scripts/generate-nvidia-gcovr.sh" ]; then
  echo "Error: openbmc-automation not found. Set OPENBMC_AUTOMATION or clone it next to mctp."
  exit 1
fi

echo "=== 1. Generate gcovr.cfg (Nvidia-authored files only) ==="
FILE_EXTENSIONS="*.c *.h" OUTPUT_FILE="$MCTP_ROOT/gcovr.cfg" \
  bash "$AUTOMATION/nvidia-code-coverage/scripts/generate-nvidia-gcovr.sh"

echo ""
echo "=== 2. Configure and build with coverage ==="
export PATH="${HOME}/.local/bin:${PATH}"
if ! meson setup build-cov -Db_coverage=true -Dtests=true 2>/dev/null; then
  echo "Config with tests failed (install pytest? pip3 install --user pytest pytest-tap -r tests/requirements.txt). Reconfiguring with -Dtests=false..."
  meson setup build-cov --wipe -Db_coverage=true -Dtests=false
fi
# Build coverage binaries; skip mctp-bench (may fail on some kernels without ALLOCTAG ioctl)
if ! meson compile -C build-cov 2>/dev/null; then
  ninja -C build-cov mctp test-mctp mctpd test-mctpd 2>/dev/null || true
fi

echo ""
echo "=== 3. Run tests (if built with tests) ==="
if meson test -C build-cov 2>/dev/null; then
  echo "Tests completed."
else
  echo "Tests skipped or failed (run manually: meson test -C build-cov --verbose)."
fi

echo ""
echo "=== 4. Generate Nvidia-only coverage report (source code only, no test/UT) ==="
gcovr --config gcovr.cfg --exclude='.*/tests/.*' --root . build-cov \
  --html --html-details -o build-cov/coverage-nvidia.html --print-summary

echo ""
echo "Report: $MCTP_ROOT/build-cov/coverage-nvidia.html"
