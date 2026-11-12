#!/usr/bin/env bash
#
# mayhem/test.sh — run the known-answer selftest (mayhem/tests/selftest.c, built by mayhem/build.sh with
# the project's normal flags). It decodes hand-built NFSv4 COMPOUND / NFSv3 LOOKUP / MOUNT messages and
# parses a ganesha.conf, asserting the decoded fields. exit 0 = pass.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

SELFTEST=/mayhem/mayhem_selftest
EXPECTED=18   # PASS lines a healthy selftest prints; a binary that prints nothing must not pass

[ -x "$SELFTEST" ] || { echo "missing $SELFTEST (mayhem/build.sh builds it)" >&2; emit_ctrf "nfs-ganesha-selftest" 0 1 0; exit 1; }

out="$("$SELFTEST" 2>&1)"; rc=$?
printf '%s\n' "$out"
passed=$(printf '%s\n' "$out" | grep -c '^PASS ')
failed=$(printf '%s\n' "$out" | grep -c '^FAIL ')
if [ "$failed" -eq 0 ]; then
  [ "$rc" -eq 0 ] && printf '%s\n' "$out" | grep -q '^selftest failures=0$' || failed=1
fi
[ "$passed" -ge "$EXPECTED" ] || failed=$(( failed + EXPECTED - passed ))
emit_ctrf "nfs-ganesha-selftest" "$passed" "$failed" 0
