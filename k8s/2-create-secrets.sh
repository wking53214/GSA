#!/bin/bash
set -e

echo "=== Step 2: Create Kubernetes Secrets ==="
echo ""
echo "This script creates the gsa-secrets in the gsa namespace."
echo "You must provide:"
echo "  - An HMAC key (for attestation signing)"
echo "  - An RS256 public key (for JWT verification)"
echo ""

# Check for kubectl
if ! command -v kubectl &> /dev/null; then
  echo "✗ kubectl not found. Install kubectl first."
  exit 1
fi

# Ensure namespace exists
echo "Creating gsa namespace..."
kubectl create namespace gsa --dry-run=client -o yaml | kubectl apply -f -

# Generate HMAC key if not provided
if [ -z "$GSA_HMAC_KEY" ]; then
  echo ""
  echo "Generating HMAC key..."
  export GSA_HMAC_KEY=$(openssl rand -hex 32)
  echo "  HMAC_KEY=$GSA_HMAC_KEY"
fi

# Check for JWT public key
if [ -z "$GSA_JWT_PUBLIC_KEY_FILE" ]; then
  echo ""
  echo "ERROR: GSA_JWT_PUBLIC_KEY_FILE not set"
  echo "Usage: GSA_JWT_PUBLIC_KEY_FILE=/path/to/jwt_public.pem ./2-create-secrets.sh"
  echo ""
  echo "To generate a test key pair (DO NOT USE IN PRODUCTION):"
  echo "  openssl genrsa -out jwt_private.pem 2048"
  echo "  openssl rsa -in jwt_private.pem -pubout -out jwt_public.pem"
  echo ""
  exit 1
fi

if [ ! -f "$GSA_JWT_PUBLIC_KEY_FILE" ]; then
  echo "✗ JWT public key file not found: $GSA_JWT_PUBLIC_KEY_FILE"
  exit 1
fi

echo "Using JWT public key from: $GSA_JWT_PUBLIC_KEY_FILE"

# Create the secret
echo ""
echo "Creating gsa-secrets in gsa namespace..."
kubectl create secret generic gsa-secrets \
  --namespace=gsa \
  --from-literal=hmac-key="$GSA_HMAC_KEY" \
  --from-file=jwt-public-key="$GSA_JWT_PUBLIC_KEY_FILE" \
  --dry-run=client -o yaml | kubectl apply -f -

echo ""
echo "✓ Secret created successfully"
kubectl get secret gsa-secrets -n gsa

echo ""
echo "Next: Run ./k8s/3-deploy.sh"
