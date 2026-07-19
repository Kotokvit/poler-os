#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

# Find the dynamic linker in our lib directory
# Usually it's named ld-linux-x86-64.so.2 on 64-bit systems
LINKER=""
for f in "$DIR/lib"/ld-linux-*; do
    if [ -f "$f" ]; then
        LINKER="$f"
        break
    fi
done

if [ -n "$LINKER" ]; then
    echo "Running QEMU using bundled linker and libraries..."
    exec "$LINKER" --library-path "$DIR/lib" "$DIR/bin/qemu-system-x86_64" -L "$DIR/share/qemu" "$@"
else
    echo "Bundled linker not found. Running with LD_LIBRARY_PATH..."
    export LD_LIBRARY_PATH="$DIR/lib"
    exec "$DIR/bin/qemu-system-x86_64" -L "$DIR/share/qemu" "$@"
fi
