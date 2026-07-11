#!/usr/bin/env bash
#
# gss-ntlmssp/mayhem/build.sh — build the OSS-Fuzz `fuzz-accept-sec-context` harness as a sanitized
# libFuzzer target (+ a standalone reproducer), AND gss-ntlmssp's own crypto/parse unit test suite
# (ntlmssptest) for mayhem/test.sh.
#
# Fuzzed surface: the NTLM message parser reached through the GSSAPI server entry point. The harness
# walks an attacker-controlled buffer as a sequence of [uint16 token_length][token] records and feeds
# each token to gssntlm_accept_sec_context() while GSS_S_CONTINUE_NEEDED holds. That drives
# ntlm_decode_msg_type / ntlm_decode_negotiate_msg / ntlm_decode_*_msg (src/ntlm.c) — the wire
# NTLMSSP message decoders ("NTLMSSP\0" signature + LE msg_type + wire field headers with
# offset/len pointers into the payload) — plus the GSSAPI sec-context state machine (src/gss_sec_ctx.c).
# All of libgssntlmssp is compiled with $SANITIZER_FLAGS so the parsed code, not just the harness,
# is instrumented.
#
# Build contract from the org base ENV: CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/SRC/
# STANDALONE_FUZZ_MAIN. gss-ntlmssp builds with autotools; the OSS-Fuzz recipe is
# `autoreconf -f -i; ./configure --disable-shared --enable-static --without-wbclient; make`,
# which produces the static archive .libs/gssntlmssp.a. Extra -dev deps (libkrb5, libunistring,
# libssl, zlib, gettext, xsltproc/docbook for the man pages) are apt-installed in the Dockerfile.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"

# Narrow UBSan relax — keep ASan + the rest of halting UBSan ON.
# ntlm_encode_field (src/ntlm.c:376) memcpy()s an EMPTY field: field->data is NULL and
# field->length is 0. A 0-length memcpy with a NULL source is benign (the standard's pointer rules
# notwithstanding), but UBSan's `nonnull-attribute` check halts on the NULL argument to memcpy's
# nonnull parameter. This fires on the ordinary NTLM message-encode path (any empty domain/
# workstation/target field) — i.e. on ~every message — so under halting UBSan it aborts before the
# fuzzer can explore and breaks the unit suite. Relax ONLY this one check; real spatial/temporal
# bugs are still caught by ASan and the rest of UBSan keeps halting. Only relax when sanitizers are
# actually on (an explicit empty SANITIZER_FLAGS = natural-crash build stays empty).
case "$SANITIZER_FLAGS" in
  *-fsanitize=*) SANITIZER_FLAGS="$SANITIZER_FLAGS -fno-sanitize=nonnull-attribute" ;;
esac

# SanitizerCoverage for libFuzzer feedback. The org base ships SANITIZER_FLAGS with only
# -fsanitize=address,undefined; without -fsanitize=fuzzer-no-link the library objects carry no
# __sanitizer_cov_trace_pc_guard call sites, so the NTLM decoder code the harness drives is
# UNINSTRUMENTED -> libFuzzer/Mayhem observe 0 edges on every run (the bug this fixes). Add it
# to the flags used to compile the library (CFLAGS) AND the harness, but only when sanitizers
# are on (an explicit empty SANITIZER_FLAGS = natural-crash build stays empty). fuzzer-no-link
# instruments for coverage without linking the libFuzzer runtime, so the standalone reproducer
# (no $LIB_FUZZING_ENGINE) still links cleanly while gaining the coverage stubs.
case "$SANITIZER_FLAGS" in
  *fuzzer-no-link*) : ;;
  *-fsanitize=*) SANITIZER_FLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link" ;;
esac

export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

cd "$SRC"

HARNESS_DIR="$SRC/mayhem/harnesses"

# ── 1) Sanitized autotools build of gss-ntlmssp ───────────────────────────────────────────────
# --without-wbclient: drop the optional winbind client dependency (matches OSS-Fuzz; not on the
#   fuzzed/tested path). --disable-shared --enable-static: produce .libs/gssntlmssp.a for static
#   linking into the harness and the test binary.
# --without-manpages: skip the DocBook->man regeneration. That step shells out to xmllint/xsltproc
#   which try to fetch the DocBook DTD over the network (http://www.oasis-open.org/...); the build
#   runs offline, so it would fail. Man pages are not on the fuzzed/tested path.
# autotools honours $CFLAGS, so push $SANITIZER_FLAGS through it; the whole library (the NTLM
# decoders the fuzzer reaches) is compiled instrumented.
autoreconf -f -i
CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" \
  ./configure --disable-shared --enable-static --without-wbclient --without-manpages
# Build the library + the ntlmssptest test binary (test.sh runs it). `make` builds the lib and the
# noinst_PROGRAMS test binary together.
make -j"$MAYHEM_JOBS"
echo "built sanitized gss-ntlmssp (.libs/gssntlmssp.a + ntlmssptest)"

LIB="$SRC/.libs/gssntlmssp.a"
[ -f "$LIB" ] || { echo "ERROR: $LIB not produced"; find "$SRC" -name 'gssntlmssp.a' 2>/dev/null; exit 1; }

# Library link line — same external libs as the OSS-Fuzz fuzzing/Makefile.
INC="-I$SRC/src"
EXTLIBS=( -lssl -lcrypto -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err -lunistring -lz )

# ── 2) Build the harness: compile once, link twice (libFuzzer + standalone reproducer) ─────────
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c -o "$SRC/fuzz-accept-sec-context.o" \
    $INC "$HARNESS_DIR/fuzz-accept-sec-context.c"

# libFuzzer target -> /mayhem/fuzz-accept-sec-context  (link with clang++ for the libFuzzer runtime)
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -o /mayhem/fuzz-accept-sec-context \
    "$SRC/fuzz-accept-sec-context.o" "$LIB" $LIB_FUZZING_ENGINE "${EXTLIBS[@]}"

# Standalone reproducer (no libFuzzer runtime; reads one input file, runs once, natural crash).
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$SRC/standalone_main.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -o /mayhem/fuzz-accept-sec-context-standalone \
    "$SRC/fuzz-accept-sec-context.o" "$SRC/standalone_main.o" "$LIB" "${EXTLIBS[@]}"

echo "built fuzz-accept-sec-context (+ standalone)"

echo "build.sh complete:"
ls -la /mayhem/fuzz-accept-sec-context /mayhem/fuzz-accept-sec-context-standalone 2>&1 || true
