#!/bin/bash
set -e

echo "=== Step 1: Build Docker Image ==="
echo "Building gsa-gateway:3.1.0..."

cd "$(dirname "$0")/.."

docker build -t gsa-gateway:3.1.0 .

echo ""
echo "✓ Image built successfully"
docker images | grep gsa-gateway:3.1.0 | awk '{print "  " $0}'

echo ""
echo "Next: Run ./k8s/2-create-secrets.sh"
