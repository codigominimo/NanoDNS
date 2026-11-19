#!/usr/bin/env bash
# Build NanoDNS for Linux x86_64/ARM64 and Windows x86_64/ARM64 (GNU ABI).
#
# Cross C compilation is handled by cargo-zigbuild + Zig when available.
# Otherwise install the matching cross toolchains (or use `cross`).
# Set CARGO to override the builder, e.g. CARGO="cargo cross".
# Artifacts are written to dist/<target>.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

PROFILE="${PROFILE:-release}"
read -r -a BUILDER <<< "${CARGO:-cargo}"
TARGETS=(
    x86_64-unknown-linux-gnu
    aarch64-unknown-linux-gnu
    x86_64-pc-windows-gnu
    aarch64-pc-windows-gnu
)

failed=()

for target in "${TARGETS[@]}"; do
    if ! rustup target list --installed | grep -qx "$target"; then
        echo "Adding Rust target $target"
        if ! rustup target add "$target"; then
            failed+=("$target")
            continue
        fi
    fi

    builder=("${BUILDER[@]}")
    if [[ "${builder[0]:-cargo}" == "cargo" && "${builder[1]:-}" != "zigbuild" ]] \
        && command -v cargo-zigbuild >/dev/null 2>&1; then
        builder=(cargo zigbuild)
    fi

    echo "Building $target ($PROFILE) with ${builder[*]}"
    if ! "${builder[@]}" build --profile "$PROFILE" --target "$target" -p nano-dns; then
        echo "Build failed for $target. Install the matching cross toolchain, Zig or cross." >&2
        failed+=("$target")
        continue
    fi

    binary=nano-dns
    if [[ "$target" == *windows* ]]; then
        binary=nano-dns.exe
    fi
    destination="$ROOT/dist/$target"
    mkdir -p "$destination"
    cp "target/$target/$PROFILE/$binary" "$destination/"
    cp config/nano-dns.json "$destination/"
    echo "Artifact: $destination"
done

if [ "${#failed[@]}" -gt 0 ]; then
    echo "Failed targets: ${failed[*]}" >&2
    exit 1
fi

echo "All targets built successfully."
