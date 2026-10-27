#!/usr/bin/env bash
# zkey-i "main" nga ceremonia e zkLogin (sui-foundation/zklogin-ceremony-contributions, Git LFS).
set -euo pipefail
cd "$(dirname "$0")"
URL="https://media.githubusercontent.com/media/sui-foundation/zklogin-ceremony-contributions/main/zkLogin-main.zkey"
[ -f zkLogin-main.zkey ] || curl -fL --retry 3 -o zkLogin-main.zkey "$URL"
# Krahaso me hash-in e publikuar në README e ceremonisë para përdorimit në prodhim.
sha256sum zkLogin-main.zkey
