find . -type d -name ".turbo" -exec rm -rf {} +
find . -type d -name "node_modules" -exec rm -rf {} +
find . -type d -name "dist" -exec rm -rf {} +
find . -type d -name ".DS_Store" -exec rm -rf {} +
find . -type d -name "coverage" -exec rm -rf {} +
rm -rf ./scripts/verdaccio/verdaccio-storage