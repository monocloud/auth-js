#!/bin/bash

LOCAL_REGISTRY_URL="http://localhost:4874/"
VERDACCIO_CONTAINER_NAME="verdaccio"
DOCKER_COMPOSE_FILE="./scripts/verdaccio/docker-compose.yml"
MAX_WAIT_SECONDS=60
WAIT_INTERVAL=5
PACKAGE_SCOPE="@monocloud"

echo "--- 1. Starting local Verdaccio registry on $LOCAL_REGISTRY_URL ---"

docker compose -f $DOCKER_COMPOSE_FILE up -d verdaccio

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to start Verdaccio container. Aborting."
    exit 1
fi

echo "--- 2. Waiting for Verdaccio to be ready (max $MAX_WAIT_SECONDS seconds) ---"

for i in $(seq 1 $((MAX_WAIT_SECONDS / WAIT_INTERVAL))); do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" $LOCAL_REGISTRY_URL)

    if [ "$STATUS" -eq 200 ]; then
        echo "Verdaccio is ready. HTTP $STATUS."
        break
    else
        echo "Waiting... Verdaccio not ready yet (HTTP $STATUS). Retrying in $WAIT_INTERVAL seconds."
        sleep $WAIT_INTERVAL
    fi

    if [ $i -eq $((MAX_WAIT_SECONDS / WAIT_INTERVAL)) ]; then
        echo "ERROR: Verdaccio did not become ready within $MAX_WAIT_SECONDS seconds. Aborting."
        docker compose -f $DOCKER_COMPOSE_FILE down
        exit 1
    fi
done

echo "--- 3. Configuring local registry for automated publishing ---"

INSECURE_REGISTRY_HOST="//localhost:4874"
DUMMY_TOKEN="dummy-local-token-required-by-cli-check"

pnpm config set "${PACKAGE_SCOPE}:registry" "$LOCAL_REGISTRY_URL"

pnpm config set "${INSECURE_REGISTRY_HOST}/:_authToken" "$DUMMY_TOKEN"

echo "--- 4. Incrementing package versions (Patch Bump) ---"

find ./packages -maxdepth 1 -mindepth 1 -type d | while read dir; do
    PACKAGE_NAME=$(basename $dir)

    if [ "$PACKAGE_NAME" = "test-utils" ]; then
        echo "Skipping $PACKAGE_NAME"
        continue
    fi

    echo "Bumping $PACKAGE_NAME"
    (cd $dir && pnpm version patch)
done

echo "--- 5. Building all packages ---"

pnpm build

pnpm install

if [ $? -ne 0 ]; then
    echo "ERROR: Package build failed. Aborting."
    docker compose -f $DOCKER_COMPOSE_FILE down
    exit 1
fi

echo "--- 6. Publishing all built packages to $LOCAL_REGISTRY_URL ---"

find ./packages -maxdepth 1 -mindepth 1 -type d | while read dir; do
    PACKAGE_NAME=$(basename $dir)

    if [ "$PACKAGE_NAME" = "test-utils" ]; then
        echo "Skipping $PACKAGE_NAME"
        continue
    fi

    echo "Publishing $PACKAGE_NAME"
    (cd $dir && pnpm publish --registry $LOCAL_REGISTRY_URL --no-git-checks --tag local)
done

echo "--- ✅ Local publishing complete! ---"
echo "Registry URL: $LOCAL_REGISTRY_URL"
echo "To use these packages, see the consumption instructions below."
