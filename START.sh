#!/usr/bin/env bash
cd "$(dirname "$0")"
export LIMS_PORT="${LIMS_PORT:-5050}"
export LIMS_HOST="${LIMS_HOST:-0.0.0.0}"
echo "IQRA GROUP OF LAB LIMS: http://localhost:${LIMS_PORT}"
node server.js
