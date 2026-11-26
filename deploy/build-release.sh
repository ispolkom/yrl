#!/bin/sh
set -eu
if [ "$#" -ne 1 ]; then echo "usage: $0 NEW-ARTIFACT-DIRECTORY" >&2; exit 64; fi
out=$1
test ! -e "$out"
mkdir -m 0700 "$out"
cargo build --release --locked -p yrl --bins
for name in yrl yrld yrl-relay yrl-audit yrl-release yrl-update; do
    install -m 0755 "target/release/$name" "$out/$name"
done
{
    echo "source_commit $(git rev-parse HEAD)"
    echo "rustc $(rustc --version)"
    echo "cargo $(cargo --version)"
    echo "target ${CARGO_BUILD_TARGET:-native}"
} > "$out/provenance.txt"
echo "Artifacts built in $out; create and sign the manifest offline as documented in docs/RELEASES.md." >&2
