#!/usr/bin/env bash
# Build mini-acme for Linux using Docker.
# Resulting binary is copied into the project directory as ./mini-acme
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${IMAGE:-gcc:13}"
OUTPUT="${SCRIPT_DIR}/mini-acme"

if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker is not installed or not in PATH" >&2
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "ERROR: docker daemon is not running. Start Docker Desktop and retry." >&2
    exit 1
fi

# Git Bash (MSYS2) rewrites POSIX-looking arguments (like /src) into Windows
# paths, which breaks docker -v/-w flags. Convert the host path explicitly and
# disable automatic conversion for the docker invocation.
if command -v cygpath >/dev/null 2>&1; then
    HOST_PATH="$(cygpath -w "${SCRIPT_DIR}")"
    export MSYS_NO_PATHCONV=1
else
    HOST_PATH="${SCRIPT_DIR}"
fi

echo "Building mini-acme (Linux) with Docker image: ${IMAGE}"
# -static
docker run --rm \
    -v "${HOST_PATH}:/src" \
    -w /src \
    "${IMAGE}" \
    bash -c 'gcc -O2 -o mini-acme -I. -I./zlib -I./crypery -I./utilery ./zlib/*.c ./crypery/*.c ./utilery/*.c mini-acme.c -lpthread'

if [ ! -f "${OUTPUT}" ]; then
    echo "ERROR: build finished but ${OUTPUT} was not found" >&2
    exit 1
fi

echo "Build OK: ${OUTPUT}"
file "${OUTPUT}" 2>/dev/null || true
