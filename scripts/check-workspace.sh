#!/usr/bin/env bash
# Verify the Cargo workspace matches what is actually on disk.
#
# A crate is only compiled and tested if its path is listed in `members` in the
# root Cargo.toml. It is easy to add a crate directory and forget that line, at
# which point the crate silently stops being built — it looks like coverage
# while running nothing.
#
# Exits non-zero with a specific message when the two disagree.
set -uo pipefail
cd "$(dirname "$0")/.."

fail=0

on_disk=$(
  for d in vulnerable/*/ secure/*/ registry/; do
    [ -f "${d}Cargo.toml" ] && printf '%s\n' "${d%/}"
  done | LC_ALL=C sort -u
)

members_raw=$(sed -n '/^members[[:space:]]*=[[:space:]]*\[/,/^]/p' Cargo.toml |
  grep -oE '"[^"]+"' | tr -d '"')
members=$(printf '%s\n' "$members_raw" | LC_ALL=C sort -u)

# 1. crates on disk that are not workspace members
missing=$(LC_ALL=C comm -23 <(printf '%s\n' "$on_disk") <(printf '%s\n' "$members"))
if [ -n "$missing" ]; then
  echo "ERROR: these crates exist on disk but are not in the workspace 'members' list."
  echo "       They are never built and never tested. Add each to Cargo.toml:"
  printf '         %s\n' $missing
  fail=1
fi

# 2. members that no longer exist on disk
stale=$(LC_ALL=C comm -13 <(printf '%s\n' "$on_disk") <(printf '%s\n' "$members"))
if [ -n "$stale" ]; then
  echo "ERROR: these paths are listed in 'members' but do not exist on disk:"
  printf '         %s\n' $stale
  fail=1
fi

# 3. duplicate entries
dupes=$(printf '%s\n' "$members_raw" | LC_ALL=C sort | uniq -d)
if [ -n "$dupes" ]; then
  echo "ERROR: these paths are listed more than once in 'members':"
  printf '         %s\n' $dupes
  fail=1
fi

if [ "$fail" -eq 0 ]; then
  echo "Workspace OK: $(printf '%s\n' "$members" | wc -l | tr -d ' ') members, all present on disk, no duplicates."
fi
exit "$fail"
