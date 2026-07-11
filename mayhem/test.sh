#!/usr/bin/env bash
#
# gss-ntlmssp/mayhem/test.sh — RUN gss-ntlmssp's own unit test suite (ntlmssptest, built by
# mayhem/build.sh) and emit a CTRF summary. exit 0 iff no test failed.
#
# PATCH-grade oracle: ntlmssptest is a known-answer suite (tests/ntlmssptest.c) that drives the
# REAL NTLM crypto + message encode/decode code with hard-coded RFC/MS-NLMP test vectors and
# checks the outputs byte-for-byte — e.g. NTOWFv1/v2 hashes, LM/NT response generation, session
# key derivation, SEAL/SIGN, and the message codecs (test_LMv2_NTLMv2, test_NTOWF_UTF16,
# test_bad_challenge, test_import_name, ...). Each case prints "Test: SUCCESS" or "Test: FAIL"
# and the program returns the count of failures, so a no-op / exit(0) PATCH that breaks the
# crypto or the parser CANNOT pass. This covers the SAME NTLM message/codec code the fuzzer
# reaches (src/ntlm.c, src/crypto.c). We run it with NTLM_USER_FILE pointed at the shipped
# examples/ credential file (as tests/env1.sh does) so the credential-store path is exercised
# too — fully hermetic, no network, no root, no running services. This script only RUNS the
# pre-built binary; it never compiles.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

TEST_BIN="$SRC/ntlmssptest"
[ -x "$TEST_BIN" ] || TEST_BIN="$SRC/.libs/ntlmssptest"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
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

if [ ! -x "$TEST_BIN" ]; then
  echo "missing ntlmssptest — run mayhem/build.sh first" >&2
  emit_ctrf "ntlmssptest" 0 1 0; exit 2
fi

# The sanitized build can leak benign allocations on error/abort paths; keep the suite hermetic.
export ASAN_OPTIONS="detect_leaks=0:${ASAN_OPTIONS:-}"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1:${UBSAN_OPTIONS:-}"

# Point the credential store at the shipped test user file (as tests/env1.sh does) so the
# credential-acquisition path runs against real data.
export NTLM_USER_FILE="$SRC/examples/test_user_file2.txt"
export TEST_USER_NAME="testuser"

echo "=== running ntlmssptest ==="
out="$("$TEST_BIN" 2>&1)"; rc=$?
echo "$out"

# Each case prints exactly one "Test: SUCCESS" / "Test: FAIL" line.
PASSED=$(printf '%s\n' "$out" | grep -c 'Test: SUCCESS')
FAILED=$(printf '%s\n' "$out" | grep -c 'Test: FAIL')
: "${PASSED:=0}" "${FAILED:=0}"

# Sanity: if we parsed no result lines at all, fall back to the program exit code (a sanitizer
# abort or a crash prints no summary).
if [ "$(( PASSED + FAILED ))" -eq 0 ]; then
  echo "could not parse ntlmssptest output; using exit code $rc" >&2
  [ "$rc" -eq 0 ] && { emit_ctrf "ntlmssptest" 1 0 0; exit 0; }
  emit_ctrf "ntlmssptest" 0 1 0; exit 1
fi

# A non-zero exit with zero parsed failures means a crash/abort after some passes — record a fail.
if [ "$rc" -ne 0 ] && [ "$FAILED" -eq 0 ]; then
  echo "ntlmssptest exited $rc with no FAIL line (crash/abort?) — recording a failure" >&2
  FAILED=1
fi

emit_ctrf "ntlmssptest" "$PASSED" "$FAILED" 0
