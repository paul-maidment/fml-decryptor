#!/usr/bin/env bash
# Build Native AOT release binaries for FmlDecryptor.
#
# Outputs clean binaries to dist/aot/<rid>/ (no PDBs, no SampleFiles).
#
# Prerequisites (see https://aka.ms/nativeaot-prerequisites):
#   Windows:  Visual Studio 2022 with "Desktop development with C++"
#             For win-arm64 also install "C++ ARM64 build tools"
#   Linux:    clang, zlib development headers (e.g. apt install clang zlib1g-dev)
#             For linux-arm64, prefer a native arm64 host (e.g. ubuntu-24.04-arm in CI)
#             rather than cross-compiling from x64; see https://aka.ms/nativeaot-cross-compile
#   macOS:    Xcode command-line tools
#
# Native AOT cannot cross-compile across operating systems. Build each OS on
# that OS (or use WSL/Docker on Windows for Linux targets).
#
# Usage:
#   ./scripts/build-aot.sh                  # build all targets for this host OS
#   ./scripts/build-aot.sh linux-x64        # build one target
#   ./scripts/build-aot.sh linux-x64 win-x64
#   ./scripts/build-aot.sh --clean          # wipe dist/aot before building

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist/aot"
PROJECT="$ROOT/FmlDecryptor.csproj"
CLEAN=0
REQUESTED=()

ALL_RIDS=(win-x64 win-arm64 linux-x64 linux-arm64 osx-x64 osx-arm64)

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  echo
  echo "Targets: ${ALL_RIDS[*]}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --clean)
      CLEAN=1
      shift
      ;;
    *)
      REQUESTED+=("$1")
      shift
      ;;
  esac
done

detect_host_os() {
  case "$(uname -s)" in
    Linux)  echo linux ;;
    Darwin) echo osx ;;
    MINGW*|MSYS*|CYGWIN*)
      echo windows
      ;;
    *)
      echo unknown
      ;;
  esac
}

detect_host_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo x64 ;;
    aarch64|arm64) echo arm64 ;;
    *)
      echo unknown
      ;;
  esac
}

rid_os() {
  echo "${1%-*}"
}

rid_supported_on_host() {
  local rid="$1"
  local host_os host_arch rid_os rid_arch

  host_os="$(detect_host_os)"
  host_arch="$(detect_host_arch)"
  rid_os="$(rid_os "$rid")"
  rid_arch="${rid#*-}"

  if [[ "$host_os" == unknown || "$host_arch" == unknown ]]; then
    return 1
  fi

  if [[ "$rid_os" != "$host_os" ]]; then
    return 1
  fi

  if [[ "$rid_arch" == "$host_arch" ]]; then
    return 0
  fi

  # Same-OS cross-architecture (x64 <-> arm64).
  case "$host_os" in
    windows|linux|osx)
      if [[ "$host_arch" == x64 && "$rid_arch" == arm64 ]]; then
        return 0
      fi
      if [[ "$host_arch" == arm64 && "$rid_arch" == x64 ]]; then
        return 0
      fi
      ;;
  esac

  return 1
}

select_rids() {
  local host_os rid
  host_os="$(detect_host_os)"

  if [[ ${#REQUESTED[@]} -gt 0 ]]; then
    printf '%s\n' "${REQUESTED[@]}"
    return
  fi

  for rid in "${ALL_RIDS[@]}"; do
    if rid_supported_on_host "$rid"; then
      echo "$rid"
    fi
  done
}

publish_rid() {
  local rid="$1"
  local out="$DIST/$rid"

  mkdir -p "$out"

  echo "==> Publishing $rid -> $out"
  dotnet publish "$PROJECT" \
    -c Release \
    -r "$rid" \
    -p:PublishAot=true \
    --self-contained true \
    -o "$out"

  local binary_name="FmlDecryptor"
  if [[ "$rid" == win-* ]]; then
    binary_name="FmlDecryptor.exe"
  fi

  if [[ ! -f "$out/$binary_name" ]]; then
    echo "ERROR: expected binary not found: $out/$binary_name" >&2
    exit 1
  fi

  rm -f "$out"/*.pdb "$out"/*.dbg 2>/dev/null || true
  chmod +x "$out/$binary_name" 2>/dev/null || true

  echo "    $(du -h "$out/$binary_name" | awk '{print $1}')  $out/$binary_name"
}

main() {
  if ! command -v dotnet >/dev/null 2>&1; then
    echo "ERROR: dotnet SDK not found on PATH." >&2
    exit 1
  fi

  local host_os
  host_os="$(detect_host_os)"
  echo "Host: $host_os ($(uname -m))"
  echo "SDK:  $(dotnet --version)"
  echo "Out:  $DIST"
  echo

  if [[ "$CLEAN" -eq 1 && -d "$DIST" ]]; then
    echo "Cleaning $DIST"
    rm -rf "$DIST"
  fi

  local rid
  local built=0
  local skipped=0

  while IFS= read -r rid; do
    [[ -z "$rid" ]] && continue

    if ! rid_supported_on_host "$rid"; then
      echo "SKIP $rid (cannot Native AOT cross-compile to $(rid_os "$rid") from $host_os)"
      skipped=$((skipped + 1))
      continue
    fi

    publish_rid "$rid"
    built=$((built + 1))
    echo
  done < <(select_rids)

  if [[ "$built" -eq 0 ]]; then
    echo "No targets were built."
    if [[ "$host_os" == windows ]]; then
      echo "On Windows, install VS C++ tools for win-x64/win-arm64."
      echo "For Linux targets, run this script inside WSL or Docker."
    elif [[ "$host_os" == linux ]]; then
      echo "Install clang and zlib dev packages. See script header for details."
    elif [[ "$host_os" == osx ]]; then
      echo "Install Xcode command-line tools: xcode-select --install"
    fi
    exit 1
  fi

  echo "Done. Built $built target(s), skipped $skipped."
  echo "Artifacts:"
  find "$DIST" -type f ! -name '*.json' -print | sort
}

main
