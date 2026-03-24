#!/bin/bash
# Generate Nvidia-only code coverage report for mctp/mctpd.
#
# Usage:
#   ./scripts/run-nvidia-coverage.sh              # full: build + test + report
#   ./scripts/run-nvidia-coverage.sh --report-only # gcov data already exists
#   ./scripts/run-nvidia-coverage.sh --regen-cfg   # regenerate gcovr.cfg then full run
#   ./scripts/run-nvidia-coverage.sh --setup       # install dependencies only
#
# The checked-in gcovr.cfg is used by default. To regenerate it from git
# history, pass --regen-cfg (requires openbmc-automation as a sibling repo
# or set OPENBMC_AUTOMATION=path).
#
# System prerequisites (one-time, requires sudo):
#   sudo apt install pkg-config libsystemd-dev gcc
#
# Environment variables:
#   BUILD_DIR            Build directory (default: build-cov)
#   OPENBMC_AUTOMATION   Path to openbmc-automation repo (for --regen-cfg only)

set -e

MCTP_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$MCTP_ROOT"

SCRIPT_DIR="$MCTP_ROOT/scripts"
BUILD_DIR="${BUILD_DIR:-build-cov}"
REPORT_ONLY=false
REGEN_CFG=false
SETUP_ONLY=false

for arg in "$@"; do
  case "$arg" in
    --report-only) REPORT_ONLY=true ;;
    --regen-cfg)   REGEN_CFG=true ;;
    --setup)       SETUP_ONLY=true ;;
    -h|--help)
      sed -n '2,/^[^#]/{ /^#/s/^# \?//p }' "$0"
      exit 0
      ;;
    *) echo "Unknown option: $arg (use --help)"; exit 1 ;;
  esac
done

# --- Install Python dependencies if missing ---
install_deps() {
  export PATH="${HOME}/.local/bin:${PATH}"
  local need_install=false

  for cmd in meson ninja gcovr pytest; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      need_install=true
      break
    fi
  done

  if [ "$need_install" = true ]; then
    echo "=== Installing Python dependencies ==="
    local pip_flags=""
    if [ -z "${VIRTUAL_ENV:-}" ]; then
      pip_flags="--user"
    fi
    pip3 install $pip_flags -r "$SCRIPT_DIR/coverage-requirements.txt"
    echo ""
  fi
}

install_deps
export PATH="${HOME}/.local/bin:${PATH}"

if [ "$SETUP_ONLY" = true ]; then
  echo "Dependencies installed. Verify:"
  echo "  meson:  $(meson --version 2>/dev/null || echo 'NOT FOUND')"
  echo "  ninja:  $(ninja --version 2>/dev/null || echo 'NOT FOUND')"
  echo "  gcovr:  $(gcovr --version 2>/dev/null | head -1 || echo 'NOT FOUND')"
  echo "  pytest: $(pytest --version 2>/dev/null || echo 'NOT FOUND')"
  exit 0
fi

# --- Verify system-level prerequisites ---
for cmd in gcc pkg-config; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Error: '$cmd' not found. Install: sudo apt install ${cmd}"
    exit 1
  fi
done

if ! pkg-config --exists libsystemd 2>/dev/null; then
  echo "Error: libsystemd-dev not found. Install: sudo apt install libsystemd-dev"
  exit 1
fi

# --- Step 0 (optional): Regenerate gcovr.cfg from git history ---
if [ "$REGEN_CFG" = true ]; then
  AUTOMATION="${OPENBMC_AUTOMATION:-$(cd "$MCTP_ROOT/../openbmc-automation" 2>/dev/null && pwd)}"
  GEN_SCRIPT="$AUTOMATION/nvidia-code-coverage/scripts/generate-nvidia-gcovr.sh"
  if [ -z "$AUTOMATION" ] || [ ! -f "$GEN_SCRIPT" ]; then
    echo "Error: openbmc-automation not found. Set OPENBMC_AUTOMATION or clone it next to mctp."
    exit 1
  fi
  echo "=== Regenerating gcovr.cfg (Nvidia-authored files only) ==="
  FILE_EXTENSIONS="*.c *.h" OUTPUT_FILE="$MCTP_ROOT/gcovr.cfg" \
    bash "$GEN_SCRIPT"

  cat >> "$MCTP_ROOT/gcovr.cfg" << 'GCOVR_EXTRA'
decisions = yes

exclude-throw-branches = yes
exclude-unreachable-branches = yes
GCOVR_EXTRA
  echo ""
fi

if [ ! -f "$MCTP_ROOT/gcovr.cfg" ]; then
  echo "Error: gcovr.cfg not found. Run with --regen-cfg or commit gcovr.cfg to the repo."
  exit 1
fi

# --- Step 1: Build with coverage + run tests ---
if [ "$REPORT_ONLY" = false ]; then
  echo "=== 1. Configure with coverage ==="
  if [ -d "$BUILD_DIR" ]; then
    meson setup --reconfigure "$BUILD_DIR" -Db_coverage=true -Dtests=true \
      || meson setup --reconfigure "$BUILD_DIR" -Db_coverage=true -Dtests=false
  else
    meson setup "$BUILD_DIR" -Db_coverage=true -Dtests=true \
      || meson setup "$BUILD_DIR" --wipe -Db_coverage=true -Dtests=false
  fi

  echo ""
  echo "=== 2. Build ==="
  if ! meson compile -C "$BUILD_DIR"; then
    echo "Full build failed (mctp-bench needs ALLOCTAG ioctl). Building core targets..."
    ninja -C "$BUILD_DIR" mctp mctpd test-mctp test-mctpd \
      test-mctpd-fault test-mctpd-util test-mctp-netlink-unit \
      test-mctp-client-unit test-mctp-util-unit test-mctp-ops-unit
  fi

  echo ""
  echo "=== 3. Run tests ==="
  if meson test -C "$BUILD_DIR" --print-errorlogs; then
    echo "All tests passed."
  else
    echo "WARNING: Some tests failed. Coverage data may be incomplete."
    echo "  Re-run with: meson test -C $BUILD_DIR --verbose"
  fi
fi

# --- Step 2: Generate report ---
gcda_count=$(find "$BUILD_DIR" -name '*.gcda' 2>/dev/null | wc -l)
if [ "$gcda_count" -eq 0 ]; then
  echo "Error: No .gcda files found in $BUILD_DIR/. Build and run tests first."
  exit 1
fi
echo "Found $gcda_count .gcda files."

echo ""
echo "=== 4. Generate Nvidia-only coverage report ==="
gcovr --config gcovr.cfg --exclude='.*/tests/.*' --root . "$BUILD_DIR" \
  --html --html-details -o "$BUILD_DIR/coverage-nvidia.html"

echo ""
echo "Report: $MCTP_ROOT/$BUILD_DIR/coverage-nvidia.html"
