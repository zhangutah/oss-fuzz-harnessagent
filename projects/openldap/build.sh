#!/bin/bash
# OSS-Fuzz compatible build script for OpenLDAP fuzzing harnesses
#
# This script builds OpenLDAP libraries and fuzzing harnesses compatible with
# LibFuzzer and OSS-Fuzz infrastructure.
#
# Environment variables expected (OSS-Fuzz standard):
#   $CC, $CXX           - Compiler executables (with sanitizer flags)
#   $CFLAGS, $CXXFLAGS  - Compilation flags (including sanitizer flags)
#   $LIB_FUZZING_ENGINE - Path to libFuzzer or -fsanitize=fuzzer
#   $OUT                - Output directory for fuzzer binaries
#   $SRC                - Source root directory (optional, defaults to /src)
#
# For local testing without OSS-Fuzz:
#   CC=clang CXX=clang++ \
#   CFLAGS="-fsanitize=address,fuzzer-no-link" \
#   CXXFLAGS="-fsanitize=address,fuzzer-no-link" \
#   LIB_FUZZING_ENGINE="-fsanitize=fuzzer" \
#   OUT=/out \
#   ./fuzz/build.sh

set -e  # Exit on error
set -x  # Print commands (helpful for debugging)

# Set defaults for local testing
export CC=${CC:-clang}
export CXX=${CXX:-clang++}
export CFLAGS=${CFLAGS:--fsanitize=address,fuzzer-no-link -g}
export CXXFLAGS=${CXXFLAGS:--fsanitize=address,fuzzer-no-link -g}
export LIB_FUZZING_ENGINE=${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}
export OUT=${OUT:-/out}
export SRC=${SRC:-/src}

# OpenLDAP source directory
OPENLDAP_SRC="${SRC}/openldap"
cd "${OPENLDAP_SRC}"

# Create output directory if it doesn't exist
mkdir -p "${OUT}"

#------------------------------------------------------------------------------
# Step 1: Configure OpenLDAP
#------------------------------------------------------------------------------
# We only need the client libraries (libldap, liblber) for fuzzing the public API.
# Disable server components (slapd) to reduce build time and dependencies.
#
# Key configure options:
#   --disable-slapd           : Don't build the LDAP server
#   --disable-backends        : Don't build any backend databases
#   --disable-overlays        : Don't build overlays
#   --disable-syslog          : Reduce external dependencies
#   --disable-shared          : Prefer static linking for fuzzing
#   --enable-static           : Build static libraries
#   --without-cyrus-sasl      : Disable SASL to reduce dependencies
#   --without-fetch           : Disable fetch support
#   --without-threads         : Disable threading (simpler for fuzzing)
#   --disable-slapi           : Disable server plugin API

echo "[*] Configuring OpenLDAP for fuzzing (client libraries only)..."

# Clean any previous configuration
make distclean 2>/dev/null || true

./configure \
    --disable-slapd \
    --disable-backends \
    --disable-overlays \
    --disable-syslog \
    --disable-shared \
    --enable-static \
    --without-cyrus-sasl \
    --without-fetch \
    --without-threads \
    --disable-slapi \
    --prefix="${OPENLDAP_SRC}/install"

#------------------------------------------------------------------------------
# Step 2: Build OpenLDAP libraries
#------------------------------------------------------------------------------
# Build only the libraries we need (liblber, libldap, supporting libs).
# The public API is primarily in libldap, which depends on liblber.

echo "[*] Building OpenLDAP libraries..."

# Build dependencies first
make -j$(nproc) -C include
make -j$(nproc) -C libraries

# Verify static libraries were created
echo "[*] Verifying static libraries..."
ls -lh libraries/liblber/.libs/liblber.a
ls -lh libraries/libldap/.libs/libldap.a
ls -lh libraries/liblutil/liblutil.a
ls -lh libraries/librewrite/librewrite.a

#------------------------------------------------------------------------------
# Step 3: Build fuzzing harnesses
#------------------------------------------------------------------------------
echo "[*] Building fuzzing harnesses..."

# Common include paths
INCLUDES="-I${OPENLDAP_SRC}/include -I${OPENLDAP_SRC}/libraries/libldap -I${OPENLDAP_SRC}/libraries/liblber"

# Library paths (prefer static archives)
LDAP_LIBS="${OPENLDAP_SRC}/libraries/libldap/.libs/libldap.a"
LBER_LIBS="${OPENLDAP_SRC}/libraries/liblber/.libs/liblber.a"
LUTIL_LIBS="${OPENLDAP_SRC}/libraries/liblutil/liblutil.a"
REWRITE_LIBS="${OPENLDAP_SRC}/libraries/librewrite/librewrite.a"

# Link order matters: libldap depends on liblber and liblutil
STATIC_LIBS="${LDAP_LIBS} ${LBER_LIBS} ${LUTIL_LIBS} ${REWRITE_LIBS}"

# System libraries that OpenLDAP may depend on
SYSTEM_LIBS="-lresolv"

# Find all fuzzer harnesses in fuzz/ directory
for fuzzer_source in "${SRC}"/fuzz_*.cpp; do
    if [ ! -f "$fuzzer_source" ]; then
        echo "[!] No fuzzer harnesses found in fuzz/ directory"
        exit 1
    fi

    fuzzer_name=$(basename "$fuzzer_source" .cpp)
    echo "[*] Building ${fuzzer_name}..."

    # Compile fuzzer harness
    # Link order: fuzzer source -> static libs -> system libs -> fuzzing engine
    ${CXX} ${CXXFLAGS} ${INCLUDES} \
        "$fuzzer_source" \
        ${STATIC_LIBS} \
        ${SYSTEM_LIBS} \
        ${LIB_FUZZING_ENGINE} \
        -o "${OUT}/${fuzzer_name}"

    echo "[+] Built: ${OUT}/${fuzzer_name}"
done

#------------------------------------------------------------------------------
# Step 4: Verify and test fuzzer binaries
#------------------------------------------------------------------------------
# echo "[*] Verifying fuzzer binaries..."
# 
# for fuzzer_binary in "${OUT}"/fuzz_*; do
#     if [ -f "$fuzzer_binary" ] && [ -x "$fuzzer_binary" ]; then
#         echo "[+] Fuzzer ready: ${fuzzer_binary}"
# 
#         # Quick smoke test: run for 1 second to ensure it doesn't crash immediately
#         echo "    Running smoke test (1 second)..."
#         timeout 1 "$fuzzer_binary" -max_total_time=1 2>&1 || {
#             # timeout returns 124 on timeout, which is expected
#             exit_code=$?
#             if [ $exit_code -ne 124 ] && [ $exit_code -ne 0 ]; then
#                 echo "[!] ERROR: Fuzzer crashed during smoke test!"
#                 exit 1
#             fi
#         }
#         echo "    Smoke test passed"
#     fi
# done

#------------------------------------------------------------------------------
# Summary
#------------------------------------------------------------------------------
echo ""
echo "=============================================="
echo "Build completed successfully!"
echo "=============================================="
echo "Fuzzer binaries available in: ${OUT}"
# echo ""
# echo "Built fuzzers:"
# ls -lh "${OUT}"/fuzz_* 2>/dev/null || echo "  (none)"
# echo ""
# echo "To run a fuzzer:"
# echo "  ${OUT}/fuzz_ldap_url_parse -max_total_time=30"
# echo ""
# echo "To run with a corpus directory:"
# echo "  ${OUT}/fuzz_ldap_url_parse /path/to/corpus -max_total_time=30"
# echo ""
