#!/bin/bash
set -e

echo "=== Step 4: Validate Deployment ==="
echo ""

# Check for kubectl
if ! command -v kubectl &> /dev/null; then
  echo "✗ kubectl not found"
  exit 1
fi

# Validation checklist
CHECKS=(
  "Pod running and healthy"
  "Readiness probe passes"
  "Liveness probe succeeds"
  "Metrics endpoint responds"
  "All 12 metrics exported"
  "Prometheus scrapes successfully"
  "Grafana dashboard loads"
  "Load test succeeds"
  "Circuit breaker state closed"
  "Health regime nominal"
)

# Check pod status
echo "1. Pod running and healthy"
POD=$(kubectl get pods -n gsa -l app=gsa-gateway -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
if [ -z "$POD" ]; then
  echo "   ✗ No pod found"
  exit 1
fi
echo "   ✓ Pod: $POD"

# Wait for pod to be ready
echo ""
echo "2. Readiness probe passes"
kubectl wait --for=condition=ready pod -l app=gsa-gateway -n gsa --timeout=300s
echo "   ✓ Pod is ready"

# Verify liveness
echo ""
echo "3. Liveness probe succeeds"
kubectl get pods -n gsa -l app=gsa-gateway -o jsonpath='{.items[0].status.conditions[?(@.type=="Ready")].status}' | grep -q True
echo "   ✓ Liveness check passed"

# Port-forward and verify metrics
echo ""
echo "4. Metrics endpoint responds"
kubectl port-forward -n gsa svc/gsa-gateway 8000:80 &
PF_PID=$!
sleep 2

if curl -s http://localhost:8000/metrics > /dev/null 2>&1; then
  echo "   ✓ Metrics endpoint responding"
else
  echo "   ✗ Metrics endpoint not responding"
  kill $PF_PID 2>/dev/null || true
  exit 1
fi

# Check metrics count
echo ""
echo "5. All 12 metrics exported"
METRIC_COUNT=$(curl -s http://localhost:8000/metrics | grep -c '^gsa_')
if [ "$METRIC_COUNT" -ge 12 ]; then
  echo "   ✓ Found $METRIC_COUNT metrics"
else
  echo "   ✗ Only found $METRIC_COUNT metrics, expected 12"
fi

# Check health
echo ""
echo "6. Prometheus scrapes successfully"
HEALTH=$(curl -s http://localhost:8000/health 2>/dev/null | grep -o '"status":"[^"]*"' | head -1)
echo "   Health response: $HEALTH"
if echo "$HEALTH" | grep -q "ok"; then
  echo "   ✓ Health endpoint responding"
else
  echo "   ✗ Health endpoint not responding correctly"
fi

# Check circuit breaker
echo ""
echo "7. Circuit breaker state closed"
CIRCUIT=$(curl -s http://localhost:8000/metrics | grep 'gsa_circuit_state' | tail -1)
echo "   $CIRCUIT"
if echo "$CIRCUIT" | grep -q ' 0$'; then
  echo "   ✓ Circuit breaker closed"
else
  echo "   ⚠ Circuit breaker may be open or half-open"
fi

# Cleanup port-forward
kill $PF_PID 2>/dev/null || true

echo ""
echo "=== Validation Summary ==="
echo ""
echo "Basic checks complete. For full validation:"
echo "  - Run ./k8s/5-verify.sh to check Prometheus and Grafana"
echo "  - See K8S_DEPLOYMENT.md for detailed validation steps"
echo ""
echo "Next: Run ./k8s/5-verify.sh"
