#!/usr/bin/env bash
#
# mayhem/build.sh — build the nfs-ganesha fuzz harnesses and the selftest oracle.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem, offline.
# nfs-ganesha's RPC library (libntirpc) is a git submodule that the checkout does not carry; the
# Dockerfile caches the pinned source under /opt/toolchains/deps/ntirpc-*/src and this script builds it
# out of tree, once per flag set, together with the ganesha object libraries the harnesses link
# (XDR codecs, config parser, RPC helpers). The daemon itself is never built.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# cmake runs `git` for version strings; /mayhem is owned by another uid in some graders
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0='*'

NTIRPC_SRC="$(echo /opt/toolchains/deps/ntirpc-*/src)"
[ -f "$NTIRPC_SRC/CMakeLists.txt" ] || { echo "ntirpc source cache missing under /opt/toolchains/deps" >&2; exit 1; }

# The XDR codecs call each other through (xdrproc_t) casts, as upstream does everywhere; that is
# benign, so only the `function` check is relaxed. ASan and the rest of UBSan stay halting.
RELAX="-fno-sanitize=function"

# build_variant <dir> <flags> <sancov>: libntirpc + the ganesha objects the harnesses need, built
# out of tree under <dir> with <flags>. Leaves <dir>/obj/*.o, <dir>/libntirpc.a, <dir>/inc (include flags).
build_variant() {
  local dir="$1" flags="$2" sancov="$3"
  local nb="$dir/ntirpc" gb="$dir/ganesha" prefix="$dir/prefix"
  local ns="$dir/ntirpc-src"
  rm -rf "$nb" "$gb" "$prefix" "$dir/obj"
  mkdir -p "$nb" "$gb" "$dir/obj"
  # ntirpc's cmake writes generated files into its source dir; the deps cache is read-only
  rm -rf "$ns" && cp -a "$NTIRPC_SRC" "$ns"

  cmake -S "$ns" -B "$nb" -DCMAKE_BUILD_TYPE=None \
        -DCMAKE_C_COMPILER="$CC" -DCMAKE_INSTALL_PREFIX="$prefix" \
        -DCMAKE_C_FLAGS="$flags $sancov -ffile-prefix-map=$ns=$NTIRPC_SRC" -DCMAKE_SHARED_LINKER_FLAGS="$flags" \
        -DUSE_GSS=OFF -DUSE_MONITORING=OFF -DUSE_LTTNG=OFF -DUSE_TLS=OFF \
        -DUSE_RPC_RDMA=OFF -DUSE_PROFILE=OFF >/dev/null
  cmake --build "$nb" -j"$MAYHEM_JOBS" >/dev/null
  cmake --install "$nb" >/dev/null
  rm -f "$dir/libntirpc.a"
  find "$nb/src/CMakeFiles/ntirpc.dir" -name '*.o' -print0 | xargs -0 llvm-ar rcs "$dir/libntirpc.a"

  cmake -S "$SRC/src" -B "$gb" -DCMAKE_BUILD_TYPE=None \
        -DCMAKE_C_COMPILER="$CC" \
        -DCMAKE_C_FLAGS="$flags $sancov -I$NTIRPC_SRC/src/monitoring/include" \
        -DUSE_SYSTEM_NTIRPC=ON -DNTIRPC_PREFIX="$prefix" \
        -DUSE_GSS=OFF -DUSE_DBUS=OFF -DUSE_LTTNG=OFF -DUSE_MONITORING=OFF \
        -DUSE_TLS=OFF -DUSE_ADMIN_TOOLS=OFF -DUSE_GUI_ADMIN_TOOLS=OFF \
        -DUSE_NFSIDMAP=OFF -DUSE_RADOS_RECOV=OFF -DUSE_9P=OFF >/dev/null
  cmake --build "$gb" -j"$MAYHEM_JOBS" --target nfs_mnt_xdr config_parsing rpcal >/dev/null

  cp "$gb"/Protocols/XDR/CMakeFiles/nfs_mnt_xdr.dir/*.o \
     "$gb"/config_parsing/CMakeFiles/config_parsing.dir/*.o \
     "$gb"/RPCAL/CMakeFiles/rpcal.dir/rpc_tools.c.o "$dir/obj/"

  INC="-I$gb/include -I$SRC/src/include -I$SRC/src/include/os/linux -I$SRC/src/config_parsing \
-I$NTIRPC_SRC/src/monitoring/include -I$prefix/include/ntirpc \
-DHAS_DOFF -D_GNU_SOURCE=1 -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -fno-strict-aliasing -fPIC"
  for f in avl/avl.c support/city.c log/display.c; do
    $CC $flags $sancov $INC -c "$SRC/src/$f" -o "$dir/obj/$(basename "$f" .c).o"
  done
  $CC $flags $sancov $INC -c "$SRC/mayhem/harnesses/env_stubs.c" -o "$dir/obj/env_stubs.o"
}

# ---------------------------------------------------------------------------------------------------
# 1) fuzz variant: everything instrumented with $SANITIZER_FLAGS + DWARF 3 (+ SanCov on the library code)
SANCOV=""
[ -z "$SANITIZER_FLAGS" ] || SANCOV="-fsanitize=fuzzer-no-link"
FUZZ_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS $RELAX"
FB="$SRC/build/fuzz"
build_variant "$FB" "$FUZZ_FLAGS" "$SANCOV"
FINC="$INC"

# 2) harnesses, twice each: libFuzzer + standalone run-once reproducer
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/harnesses/lsan_off.c" -o "$FB/obj/lsan_off.o"
COMMON="$FB/obj/env_stubs.o $FB/obj/lsan_off.o $FB/libntirpc.a -lurcu-bp -lpthread -lm"
XDR_OBJS="$(ls "$FB"/obj/xdr_*.o) $FB/obj/rpc_tools.c.o"
CFG_OBJS="$(ls "$FB"/obj/conf_*.o "$FB"/obj/config_parsing.c.o "$FB"/obj/analyse.c.o) $FB/obj/avl.o $FB/obj/city.o $FB/obj/display.o"

build_harness() {
  local name="$1"; shift
  $CC $FUZZ_FLAGS $SANCOV $FINC -c "$SRC/mayhem/harnesses/$name.c" -o "$FB/obj/$name.o"
  $CC $FUZZ_FLAGS $SANCOV $LIB_FUZZING_ENGINE "$FB/obj/$name.o" "$@" $COMMON -o "/mayhem/$name"
  $CC $FUZZ_FLAGS $SANCOV "$STANDALONE_FUZZ_MAIN" "$FB/obj/$name.o" "$@" $COMMON -o "/mayhem/$name-standalone"
}
build_harness fuzz_nfs4_compound $XDR_OBJS
build_harness fuzz_nfs23_args $XDR_OBJS
build_harness fuzz_config_parse $CFG_OBJS

# 3) test oracle: same sources with the project's NORMAL flags (no sanitizers), run by mayhem/test.sh
TB="$SRC/build/test"
build_variant "$TB" "-g -O1 $COVERAGE_FLAGS" ""
$CC -g -O1 $COVERAGE_FLAGS $INC -c "$SRC/mayhem/tests/selftest.c" -o "$TB/obj/selftest.o"
$CC -g -O1 $COVERAGE_FLAGS "$TB/obj/selftest.o" $(ls "$TB"/obj/xdr_*.o) "$TB/obj/rpc_tools.c.o" \
    $(ls "$TB"/obj/conf_*.o "$TB"/obj/config_parsing.c.o "$TB"/obj/analyse.c.o) \
    "$TB/obj/avl.o" "$TB/obj/city.o" "$TB/obj/display.o" "$TB/obj/env_stubs.o" \
    "$TB/libntirpc.a" -lurcu-bp -lpthread -lm -o /mayhem/mayhem_selftest
