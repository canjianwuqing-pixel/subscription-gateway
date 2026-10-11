#!/bin/sh
# Official acme.sh DNS hook: only TXT operations. Secrets stay in inherited environment and PHP curl memory.
dns_sgw_cf_add() { php /app/src/cloudflare_dns.php add "$1" "$2"; }
dns_sgw_cf_rm() { php /app/src/cloudflare_dns.php remove "$1" "$2"; }
