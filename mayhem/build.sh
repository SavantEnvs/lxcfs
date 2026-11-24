#!/usr/bin/env bash
#
# mayhem/build.sh — build lxcfs's fuzz harnesses and its unit test.
#
# 1) Upstream meson build (normal flags) into mayhem/build-tests: produces config.h and the
#    upstream cpuset unit test tests/test-cpusetrange that mayhem/test.sh runs.
# 2) The liblxcfs sources the harnesses reach, compiled with $SANITIZER_FLAGS $DEBUG_FLAGS into
#    mayhem/build-fuzz/liblxcfs_fuzz.a (the same config.h), then each harness linked twice:
#    libFuzzer binary + run-once -standalone reproducer.
# Both build dirs are gitignored by mayhem/.gitignore. Re-runnable and offline.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
T="$SRC/mayhem/build-tests"
F="$SRC/mayhem/build-fuzz"

# 1) upstream build, normal flags (+ optional coverage), tests on, no docs/init scripts
if [ ! -f "$T/build.ninja" ]; then
  CFLAGS="$COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS" \
    meson setup "$T" -Dtests=true -Ddocs=false -Dinit-script=[] -Dfuse-version=3
fi
ninja -C "$T" -j"$MAYHEM_JOBS" tests/test-cpusetrange

# 2) sanitized liblxcfs objects for the harnesses
mkdir -p "$F"
FUSE_CFLAGS="$(pkg-config --cflags fuse3)"
# -fsanitize=fuzzer-no-link always (also with empty SANITIZER_FLAGS): SanCov on the library, not
# only on the harness TU, or the fuzzer gets no coverage feedback from lxcfs code.
CFL="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1 -I$T -I$SRC/src -I$SRC/src/cgroups $FUSE_CFLAGS"
# every liblxcfs source from meson.build except lxcfs.c (the daemon, which has main())
LIBSRC="bindings.c cgroups/cgfsng.c cgroups/cgroup.c cgroups/cgroup_utils.c cpuset_parse.c proc_cpuview.c proc_fuse.c proc_loadavg.c sysfs_fuse.c utils.c"
objs=()
for s in $LIBSRC; do
  o="$F/$(echo "$s" | tr / _).o"
  # shellcheck disable=SC2086
  $CC $CFL -c "$SRC/src/$s" -o "$o"
  objs+=("$o")
done
rm -f "$F/liblxcfs_fuzz.a"
ar rcs "$F/liblxcfs_fuzz.a" "${objs[@]}"

# shellcheck disable=SC2086
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$F/lsan_off.o"
# shellcheck disable=SC2086
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$F/standalone_main.o"

LIBS="$(pkg-config --libs fuse3) -lm -lpthread -ldl"
for h in fuzz_cpuset fuzz_cpuacct_usage fuzz_cpuview_stat fuzz_utils_strings fuzz_read_file; do
  # shellcheck disable=SC2086
  $CC $CFL -c "$SRC/mayhem/harnesses/$h.c" -o "$F/$h.o"
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$F/$h.o" "$F/lsan_off.o" \
    "$F/liblxcfs_fuzz.a" $LIBS -o "$SRC/$h"
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS "$F/$h.o" "$F/standalone_main.o" "$F/lsan_off.o" \
    "$F/liblxcfs_fuzz.a" $LIBS -o "$SRC/$h-standalone"
done
