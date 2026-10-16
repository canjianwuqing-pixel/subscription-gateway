#!/bin/sh
set -eu
if [ "${1:-}" = -t ]; then
    rm -f /tmp/ci-domain-config
    # Only the domain channel replaces this include in its staged test config.
    # Ordinary rule/expiry reloads must not consume an alias fault injection.
    if [ "${2:-}" = -c ] && [ -f "${3:-}" ] && ! grep -Fq 'include /control/domains.conf;' "$3"; then
        touch /tmp/ci-domain-config
        if [ -f /tmp/ci-test-once ]; then rm /tmp/ci-test-once; exit 1; fi
    fi
fi
if [ "${1:-}" = -s ] && [ "${2:-}" = reload ] && [ -f /tmp/ci-domain-config ] && [ -f /tmp/ci-reload-once ]; then rm /tmp/ci-reload-once; exit 1; fi
exec /usr/sbin/nginx.real "$@"
