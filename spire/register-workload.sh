#!/bin/sh
# Registers a join token for the agent + a demo workload entry, so
# integration tests have something to attest against out of the box.
# Idempotent: safe to re-run. Runs on the HOST (not inside the containers —
# the official spire-server/spire-agent images are distroless, no shell).
#
# Run after `docker compose -f docker-compose.spire.yml up -d spire-server`:
#   ./spire/register-workload.sh
set -eu

COMPOSE="docker compose -f docker-compose.spire.yml"
TRUST_DOMAIN="example.org"
# spire-test (tests/test_spiffe_spire.py's execution environment) runs as
# root by default, same as the base Dockerfile's `test` stage — so the
# demo workload is registered against uid 0. Override for a different
# workload container's UID.
WORKLOAD_UID="${WORKLOAD_UID:-0}"

echo "Generating a join token for the agent..."
JOIN_TOKEN=$($COMPOSE exec -T spire-server /opt/spire/bin/spire-server token generate \
    -spiffeID "spiffe://${TRUST_DOMAIN}/agent" | awk '/^Token:/ {print $2}')
echo "Join token: ${JOIN_TOKEN}"
echo "${JOIN_TOKEN}" > spire/data/join_token.txt

echo "Registering demo workload (selector: unix:uid:${WORKLOAD_UID})..."
$COMPOSE exec -T spire-server /opt/spire/bin/spire-server entry create \
    -spiffeID "spiffe://${TRUST_DOMAIN}/workload/demo" \
    -parentID "spiffe://${TRUST_DOMAIN}/agent" \
    -selector "unix:uid:${WORKLOAD_UID}" \
    || echo "Entry may already exist — continuing."

echo "Done. Registered entries:"
$COMPOSE exec -T spire-server /opt/spire/bin/spire-server entry show
