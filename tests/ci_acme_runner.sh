#!/bin/sh
set -eu
umask 027
fqdn=$1 release=$2 temporary=$3
case $fqdn in fail.example.net) exit 1;; esac
if [ -f /control/ci-fail-issue ]; then exit 1; fi
if [ -f /control/ci-wrong-host ]; then fqdn=wrong.example.net; fi
# Model acme.sh trying to save DNS secrets in its transient config. Nothing in this directory may persist.
printf 'SAVED_CF_Token=%s\n' "$CF_Token" > "$temporary/domain.conf"
mkdir -p "$temporary/ca/test-ca"
if [ ! -f "$temporary/ca/test-ca/account.key" ]; then
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$temporary/ca/test-ca/account.key" >/dev/null 2>&1
    printf '{"registered":true}\n' > "$temporary/ca/test-ca/account.json"
fi
openssl req -x509 -newkey rsa:2048 -nodes -days 60 -subj "/CN=$fqdn" \
    -addext "subjectAltName=DNS:$fqdn" -keyout "$release/privkey.pem" -out "$release/fullchain.pem" >/dev/null 2>&1
