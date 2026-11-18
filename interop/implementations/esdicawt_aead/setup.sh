#!/bin/sh
# Build an isolated, pinned test adapter. Does not alter an existing checkout.
set -eu
if [ "$#" -ne 1 ]; then
    echo "usage: $0 NEW_CHECKOUT_DIRECTORY" >&2
    exit 2
fi
adapter_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
checkout=$1
if [ -e "$checkout" ]; then
    echo "destination already exists: $checkout" >&2
    exit 2
fi
git clone --branch feat/encrypted-disclosures --single-branch https://github.com/beltram/esdicawt.git "$checkout"
git -C "$checkout" checkout --detach c6eb0e426ac3e8ecdbcadf70f2a9d44af05a748f
git -C "$checkout" apply "$adapter_dir/cli.patch"
cp "$adapter_dir/Cargo.lock" "$checkout/Cargo.lock"
cargo build --locked --manifest-path "$checkout/Cargo.toml" -p interop
printf '\nSet ESDICAWT_AEAD_BIN to %s/target/debug/interop\n' "$(CDPATH= cd -- "$checkout" && pwd)"
