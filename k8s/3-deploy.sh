#!/bin/bash
set -e

echo "=== Step 3: Deploy GSA Gateway ==="
echo ""

# Check for kubectl
if ! command -v kubectl &> /dev/null; then
  echo "✗ kubectl not found. Install kubectl first."
  exit 1
fi

# Check namespace exists
if ! kubectl get namespace gsa &> /dev/null; then
  echo "✗ gsa namespace not found. Run ./2-create-secrets.sh first."
  exit 1
fi

# Check secret exists
if ! kubectl get secret gsa-secrets -n gsa &> /dev/null; then
  echo "✗ gsa-secrets not found. Run ./2-create-secrets.sh first."
  exit 1
fi

# Apply manifests
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Applying Kubernetes manifests..."
echo ""

kubectl apply -f "$SCRIPT_DIR/pvc.yaml"
echo "✓ PersistentVolumeClaim created"

kubectl apply -f "$SCRIPT_DIR/service.yaml"
echo "✓ Service created"

kubectl apply -f "$SCRIPT_DIR/prometheus-configmap.yaml"
echo "✓ Prometheus ConfigMap created"

kubectl apply -f "$SCRIPT_DIR/grafana-configmap.yaml"
echo "✓ Grafana ConfigMaps created"

kubectl apply -f "$SCRIPT_DIR/deployment.yaml"
echo "✓ Deployment created"

echo ""
echo "Waiting for deployment to be ready..."
kubectl rollout status deployment/gsa-gateway -n gsa --timeout=5m

echo ""
echo "✓ Deployment successful"
kubectl get all -n gsa

echo ""
echo "Next: Run ./k8s/4-validate.sh"
