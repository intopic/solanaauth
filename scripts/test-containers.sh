#!/usr/bin/env bash
set -euo pipefail
cleanup() { docker rm -f auth-prover-test auth-salt-test >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker build -t auth-prover-test services/prover
docker build -t auth-salt-test services/salt
docker run -d --name auth-prover-test -p 18080:8080 -e ALLOWED_AUDIENCES=app -e RATE_LIMIT_PER_MIN=1 auth-prover-test
docker run -d --name auth-salt-test -p 18787:8787 -e ALLOWED_AUDIENCES=app -e RATE_LIMIT_PER_MIN=1 -e SALT_MASTER_SEED=$(printf '01%.0s' {1..32}) auth-salt-test
for entry in '18080 /v1' '18787 /salt'; do
  read -r port route <<< "$entry"
  curl --retry 20 --retry-all-errors --retry-delay 1 --fail "http://localhost:$port/health"
  first=$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -H 'X-Forwarded-For: 1.2.3.4' -d '{}' "http://localhost:$port$route")
  second=$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -H 'X-Forwarded-For: 5.6.7.8' -d '{}' "http://localhost:$port$route")
  test "$first" = 400
  test "$second" = 429
done
