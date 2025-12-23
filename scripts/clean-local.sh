#!/bin/bash

PACKAGE_SCOPE="@monocloud"
INSECURE_REGISTRY_HOST="//localhost:4874"
DOCKER_COMPOSE_FILE="./scripts/verdaccio/docker-compose.yml"

echo "--- 1. Cleaning up Docker container and volumes ---"
docker-compose -f $DOCKER_COMPOSE_FILE down --volumes --remove-orphans

rm -rf ./scripts/verdaccio/verdaccio-storage

echo "--- 2. Removing local pnpm registry configurations ---"

pnpm config delete "${PACKAGE_SCOPE}:registry"

pnpm config delete "${INSECURE_REGISTRY_HOST}/:_authToken"

echo "--- ✅ Local registry and config cleanup complete! ---"