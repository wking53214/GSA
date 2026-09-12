#!/bin/bash

echo "=== Step 5: Verify Prometheus and Grafana ==="
echo ""
echo "This script helps you verify Prometheus scraping and Grafana dashboard."
echo ""

# Check for kubectl
if ! command -v kubectl &> /dev/null; then
  echo "✗ kubectl not found"
  exit 1
fi

# Check if pod is running
if ! kubectl get pods -n gsa -l app=gsa-gateway -o jsonpath='{.items[0].metadata.name}' &> /dev/null; then
  echo "✗ GSA pod not found. Run ./3-deploy.sh first."
  exit 1
fi

echo "Verification Steps:"
echo ""
echo "1. Verify Prometheus is scraping the gateway:"
echo "   a) Get Prometheus service info:"
PROM_NS=$(kubectl get svc prometheus -o jsonpath='{.metadata.namespace}' 2>/dev/null || echo "monitoring")
echo "      kubectl port-forward -n $PROM_NS svc/prometheus 9090:9090"
echo "   b) Visit http://localhost:9090/targets"
echo "   c) Look for job 'gsa-gateway' status: UP"
echo ""

echo "2. Verify Prometheus is collecting metrics:"
echo "   a) In Prometheus UI, go to Graph tab"
echo "   b) Try these queries:"
echo "      - gsa_circuit_state (should show 0)"
echo "      - gsa_health_composite_risk (should be < 0.8)"
echo "      - gsa_request_rate_total (should show traffic)"
echo ""

echo "3. Load the Grafana dashboard:"
echo "   a) Get Grafana service info:"
GRAFANA_NS=$(kubectl get svc grafana -o jsonpath='{.metadata.namespace}' 2>/dev/null || echo "monitoring")
echo "      kubectl port-forward -n $GRAFANA_NS svc/grafana 3000:3000"
echo "   b) Visit http://localhost:3000"
echo "   c) Go to Dashboards > Browse"
echo "   d) Search for 'GSA Gateway' or uid 'gsa-gateway'"
echo "   e) Verify all 12 panels show data:"
echo ""
echo "      Service State (top row, 1/4):"
echo "        - Circuit breaker → 0 (closed)"
echo "        - Substrate health → ~1.0 (healthy)"
echo "        - Composite health risk → < 0.8"
echo "        - Attestation queue depth → low"
echo ""
echo "      Traffic and Outcomes (second row, 12/4):"
echo "        - Request rate by status"
echo "        - Blocks by reason"
echo "        - Latency percentiles"
echo "        - Rate limiting (should be idle)"
echo ""
echo "      Adaptive Control (third row, 12/4):"
echo "        - Risk threshold vs observed FDR"
echo "        - Correction attempts per request"
echo ""
echo "      URE Operational Health (fourth row, 12/4):"
echo "        - Lyapunov energy"
echo "        - Substrate health over time"
echo ""

echo "4. Run a load test (optional):"
echo "   kubectl port-forward -n gsa svc/gsa-gateway 8000:80 &"
echo "   for i in {1..50}; do"
echo "     curl -s http://localhost:8000/api/v1/assess \\"
echo "       -H 'Authorization: Bearer test-token' \\"
echo "       -H 'Content-Type: application/json' \\"
echo "       -d '{\"input\":\"test prompt\"}' &"
echo "   done"
echo "   wait"
echo ""

echo "5. Verify all 10 checklist items:"
checklist=(
  "Gateway pod running and healthy"
  "Readiness probe passes"
  "Liveness probe succeeds"
  "Prometheus scrapes metrics successfully"
  "All 12 metrics appear in Prometheus"
  "Grafana dashboard displays all 12 panels"
  "Load test completes without errors"
  "Circuit breaker state remains closed (0)"
  "Health remains nominal"
  "FDR stays below 0.10"
)

echo ""
echo "Validation Checklist:"
for i in "${!checklist[@]}"; do
  echo "   [ ] $((i+1)). ${checklist[$i]}"
done

echo ""
echo "=== When all checks pass ==="
echo ""
echo "Update GSA_SCORECARD.py:"
echo "  - Change 'Deployment' gap to note manifests ARE validated"
echo "  - Change 'Operational Health' gap to note Grafana IS validated"
echo "  - Update score from 8.17/10 to 8.27/10"
echo ""
echo "Commit:"
echo "  git add GSA_SCORECARD.py"
echo "  git commit -m 'Validate k8s deployment against live cluster: 8.27/10'"
echo "  git push origin main"
echo ""
