#!/usr/bin/env bash
# usage: fetch-release.sh URL CHECKSUM_URL OUT
set -euo pipefail
curl -fsSL --retry 3 "$1" -o "$3"
# checksum files list "HASH  NAME", "HASH  ./NAME", or just the hash. awk reads the whole thing so curl never writes into a closed pipe.
sum=$(curl -fsSL --retry 3 "$2" | awk -v a="${1##*/}" '!sum && $1 ~ /^[0-9a-f]+$/ && length($1) == 64 && (NF == 1 || $2 == a || $2 == "./" a) {sum = $1} END {print sum}')
printf '%s  %s\n' "$sum" "$3" | sha256sum -c --quiet -
