#!/usr/bin/env bash
set -euo pipefail
for command in openssl sha256sum mktemp; do
    command -v "$command" >/dev/null || { echo "NOT RUN: missing $command"; exit 77; }
done
. "$(dirname "$0")/../sgw/ops.sh"
test_root=$(mktemp -d)
[[ -d $test_root && $test_root == /tmp/* ]] || exit 1
trap 'rm -rf -- "$test_root"' EXIT

valid_domain test.example.test
! valid_domain 'bad;domain.test'
! valid_domain 'one-label'
valid_port 64444
! valid_port 99999

MSYS2_ARG_CONV_EXCL=/CN= openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj '/CN=test.example.test' -addext 'subjectAltName=DNS:test.example.test' \
    -keyout "$test_root/key.pem" -out "$test_root/cert.pem" >/dev/null 2>&1
MSYS2_ARG_CONV_EXCL=/CN= openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj '/CN=other.example.test' -addext 'subjectAltName=DNS:other.example.test' \
    -keyout "$test_root/other-key.pem" -out "$test_root/other-cert.pem" >/dev/null 2>&1
certificate_verify "$test_root/cert.pem" "$test_root/key.pem" test.example.test
! certificate_verify "$test_root/cert.pem" "$test_root/key.pem" test.example.test 172800
! certificate_verify "$test_root/cert.pem" "$test_root/key.pem" wrong.example.test
! certificate_verify "$test_root/cert.pem" "$test_root/other-key.pem" test.example.test
! certificate_verify "$test_root/other-cert.pem" "$test_root/key.pem" test.example.test

mkdir -p "$test_root/runtime/ssl/releases/old" "$test_root/runtime/ssl/staging"
cp "$test_root/cert.pem" "$test_root/runtime/ssl/releases/old/fullchain.pem"
cp "$test_root/key.pem" "$test_root/runtime/ssl/releases/old/privkey.pem"
cp "$test_root/other-cert.pem" "$test_root/runtime/ssl/staging/fullchain.pem"
cp "$test_root/other-key.pem" "$test_root/runtime/ssl/staging/privkey.pem"
ln -s releases/old "$test_root/runtime/ssl/active"
if [[ -L $test_root/runtime/ssl/active ]]; then
    RUNTIME=$test_root/runtime
    ENV_FILE=$test_root/test.env
    printf 'GATEWAY_DOMAIN=other.example.test\n' > "$ENV_FILE"
    compose() {
        if [[ $1 == ps ]]; then printf 'fake-container\n'; return 0; fi
        if [[ $1 == exec && ${5:-} == -t && ${FAKE_TEST_FAIL:-0} == 1 ]]; then
            FAKE_TEST_FAIL=0
            return 1
        fi
        return 0
    }
    FAKE_TEST_FAIL=1
    ! cert_activate other.example.test
    [[ $(readlink "$RUNTIME/ssl/active") == releases/old ]]
else
    echo 'NOT RUN: symlink rollback simulation unavailable on this Windows filesystem'
fi

mkdir "$test_root/fake"
cat > "$test_root/fake/docker" <<'FAKE'
#!/usr/bin/env bash
[[ ${DOCKER_FAKE_FAIL:-0} == 0 ]]
FAKE
chmod 0755 "$test_root/fake/docker"
PATH="$test_root/fake:$PATH" ensure_docker
if printf 'n\n' | (export PATH="$test_root/fake:$PATH" DOCKER_FAKE_FAIL=1; ensure_docker) >/dev/null 2>&1; then
    echo 'Expected Docker-install refusal to fail' >&2
    exit 1
fi

cat > "$test_root/fake/acme" <<'FAKE'
#!/usr/bin/env bash
exit 1
FAKE
chmod 0755 "$test_root/fake/acme"
mkdir -p "$test_root/runtime/ssl/staging"
RUNTIME=$test_root/runtime
acme_binary() { printf '%s\n' "$test_root/fake/acme"; }
if printf 'synthetic-token\n\n' | (acquire_certificate dns-cf test.example.test) >/dev/null 2>&1; then
    echo 'Expected ACME failure to stop certificate acquisition' >&2
    exit 1
fi

cat > "$test_root/fake/docker" <<'FAKE'
#!/usr/bin/env bash
if [[ $1 == inspect ]]; then printf 'unhealthy\n'; exit 0; fi
exit 1
FAKE
chmod 0755 "$test_root/fake/docker"
compose() { [[ $1 == ps ]] && printf 'fake-container\n'; }
if (export PATH="$test_root/fake:$PATH"; wait_health) >/dev/null 2>&1; then
    echo 'Expected unhealthy container to fail healthcheck' >&2
    exit 1
fi
echo 'PASS: domain/port, certificate SAN/key checks, Docker refusal, fake ACME/health failures, certificate rollback where supported'
