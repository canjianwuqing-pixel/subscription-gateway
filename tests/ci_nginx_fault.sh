#!/bin/sh
set -eu
if [ "${1:-}" = -t ] && [ -f /tmp/ci-test-once ]; then rm /tmp/ci-test-once; exit 1; fi
if [ "${1:-}" = -s ] && [ "${2:-}" = reload ] && [ -f /tmp/ci-reload-once ]; then rm /tmp/ci-reload-once; exit 1; fi
exec /usr/sbin/nginx.real "$@"
