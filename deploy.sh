#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "$SCRIPT_DIR/.env" ]; then
    source "$SCRIPT_DIR/.env"
fi

TARGET="${DEPLOY_TARGET:?Missing DEPLOY_TARGET in .env}"
SSH_USER="${DEPLOY_SSH_USER:?Missing DEPLOY_SSH_USER in .env}"
REMOTE_DIR="${DEPLOY_REMOTE_DIR:?Missing DEPLOY_REMOTE_DIR in .env}"
FILE="${1:-channels.exe}"

if [ ! -f "$SCRIPT_DIR/$FILE" ]; then
    echo "Error: File not found: $FILE"
    echo "Usage: ./deploy.sh [file_path]"
    echo "  default: channels.exe"
    exit 1
fi

echo "Sending $FILE to $TARGET via Tailscale..."

tailscale file cp "$SCRIPT_DIR/$FILE" "${TARGET}:"

echo "Receiving file on remote..."
ssh "${SSH_USER}@${TARGET}" "tailscale file get \"${REMOTE_DIR}\""

echo "Done! File saved to ${REMOTE_DIR} on ${TARGET}"
