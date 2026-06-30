#!/usr/bin/env bash
# Fail if any git-tracked file is a compiled binary (Mach-O / ELF / PE) or an
# oversized blob. This guards against accidentally committing build artifacts
# such as `bin/gateway` or the loadgen binary from `go build ./tests/load`,
# which slipped in as an untracked 8 MB Mach-O before this check existed.
#
# Source repos should carry source, not compiled output. Run locally with
# `make check-binaries`; CI runs it in the lint workflow.
set -euo pipefail

# Tracked files larger than this (bytes) are rejected unless allowlisted.
MAX_SIZE=$((1024 * 1024)) # 1 MiB

# Substrings of paths that are allowed to exceed MAX_SIZE (large text/docs).
# Keep this list short and justified.
ALLOW_LARGE=(
  "README.md" # extensive product/usage documentation
  "go.sum"    # dependency checksums grow with the module graph
)

fail=0

is_allowed_large() {
  local f="$1"
  for a in "${ALLOW_LARGE[@]}"; do
    [[ "$f" == *"$a"* ]] && return 0
  done
  return 1
}

while IFS= read -r f; do
  [ -f "$f" ] || continue

  desc=$(file -b "$f")
  # Match compiled executables/objects/archives, but not shell/scripts which
  # `file` also tags "... text executable".
  case "$desc" in
    *text*) : ;; # any text file (incl. executable shell scripts) is fine
    *Mach-O* | *ELF* | *PE32* | "current ar archive"* | *"relocatable"*)
      echo "ERROR: tracked compiled binary: $f ($desc)"
      fail=1
      ;;
  esac

  size=$(wc -c <"$f")
  if [ "$size" -gt "$MAX_SIZE" ] && ! is_allowed_large "$f"; then
    echo "ERROR: tracked file exceeds $((MAX_SIZE / 1024)) KiB: $f (${size} bytes)"
    echo "       if this is intentional, add it to ALLOW_LARGE in $0"
    fail=1
  fi
done < <(git ls-files)

if [ "$fail" -ne 0 ]; then
  echo
  echo "Commit compiled artifacts to bin/ (gitignored), not to the repo."
  exit 1
fi

echo "check-no-binaries: OK (no tracked binaries or oversized blobs)"
