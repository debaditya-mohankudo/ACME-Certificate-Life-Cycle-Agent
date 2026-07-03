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
WORKLOAD_UID="${WORKLOAD_UID:-0}"   # UID the spire-test/spire-agent containers run as

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
