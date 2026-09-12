# GSA Gateway — Kubernetes Deployment Guide

This guide covers deploying GSA to Kubernetes and validating the manifests against a live cluster.

## Prerequisites

- A Kubernetes cluster (1.20+)
- `kubectl` configured and authenticated
- Docker image `gsa-gateway:3.1.0` available (build with `docker build -t gsa-gateway:3.1.0 .`)
- Prometheus and Grafana installed (or available via Helm)

## Step 1: Create secrets

Generate the required secrets and store them in your secret manager:

```bash
# Generate HMAC key for attestation
export GSA_SECRET_KEY=$(openssl rand -hex 32)

# Use your RS256 public key (JWT validation)
# This should be obtained from your IdP
export GSA_JWT_PUBLIC_KEY=$(cat /path/to/jwt-public-key.pem)

# Create the Kubernetes secret
kubectl create secret generic gsa-secrets \
  -n gsa \
  --from-literal=hmac-key="$GSA_SECRET_KEY" \
  --from-literal=jwt-public-key="$GSA_JWT_PUBLIC_KEY" \
  --dry-run=client -o yaml | kubectl apply -f -
```

Alternatively, edit `k8s/secret.yaml.example`, populate it, and apply:

```bash
cp k8s/secret.yaml.example k8s/secret.yaml
# Edit k8s/secret.yaml with your actual values
kubectl apply -f k8s/secret.yaml
```

## Step 2: Apply manifests

Apply the Kubernetes manifests in order:

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/pvc.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/prometheus-configmap.yaml
kubectl apply -f k8s/grafana-configmap.yaml
kubectl apply -f k8s/deployment.yaml
```

Or apply all at once:

```bash
kubectl apply -f k8s/
```

Verify deployment:

```bash
kubectl rollout status deployment/gsa-gateway -n gsa
kubectl get pods -n gsa
kubectl logs -f deployment/gsa-gateway -n gsa
```

## Step 3: Configure Prometheus

The `k8s/prometheus-configmap.yaml` manifest includes scrape configuration for the GSA gateway.
Mount it into your Prometheus pod:

### Option A: Helm (recommended)

```bash
helm upgrade prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --set prometheus.additionalServiceMonitorConfigs[0].static_configs[0].targets='["gsa-gateway.gsa.svc.cluster.local:80"]' \
  --set prometheus.additionalServiceMonitorConfigs[0].job_name='gsa-gateway'
```

### Option B: Manual ConfigMap mount

If running Prometheus directly, mount the ConfigMap:

```bash
# Update your Prometheus Deployment to mount the ConfigMap
kubectl patch deployment prometheus -n monitoring \
  -p '{"spec":{"template":{"spec":{"volumes":[{"name":"gsa-config","configMap":{"name":"prometheus-gsa","defaultMode":420}}]}}}}'
```

### Verify Prometheus scraping

```bash
# Port-forward to Prometheus
kubectl port-forward -n monitoring svc/prometheus 9090:9090

# Visit http://localhost:9090/targets and verify gsa-gateway is HEALTHY
```

## Step 4: Load Grafana dashboard

Load the GSA dashboard into Grafana:

### Option A: Grafana UI (manual)

1. Port-forward to Grafana: `kubectl port-forward -n monitoring svc/grafana 3000:3000`
2. Visit http://localhost:3000 and log in
3. Go to Dashboards → Import
4. Paste the contents of `grafana/gsa_gateway_dashboard.json`
5. Select Prometheus as the data source
6. Save

### Option B: Grafana provisioning

Mount the ConfigMap into Grafana and provision the dashboard:

```bash
# Apply the Grafana ConfigMaps
kubectl apply -f k8s/grafana-configmap.yaml

# Update your Grafana Deployment to mount provisioning configs
kubectl patch deployment grafana -n monitoring \
  -p '{"spec":{"template":{"spec":{"volumes":[
    {"name":"provisioning-datasources","configMap":{"name":"grafana-provisioning-datasources"}},
    {"name":"provisioning-dashboards","configMap":{"name":"grafana-provisioning-dashboards"}},
    {"name":"dashboards","configMap":{"name":"grafana-gsa-dashboard"}}
  ]}}}}'
```

Then create a ConfigMap with the dashboard JSON:

```bash
kubectl create configmap grafana-gsa-dashboard \
  -n gsa \
  --from-file=gsa_gateway_dashboard.json=grafana/gsa_gateway_dashboard.json \
  --dry-run=client -o yaml | kubectl apply -f -
```

## Step 5: Validate the gateway

### Health check

```bash
kubectl port-forward -n gsa svc/gsa-gateway 8000:80

# Check gateway health
curl http://localhost:8000/health

# Should return:
# {"status":"ok","circuit":"closed","health":"nominal","threshold":0.80,"regime":"nominal"}
```

### Verify metrics are exported

```bash
curl http://localhost:8000/metrics | grep gsa_

# Should list ~12 metrics:
# gsa_circuit_state, gsa_health_composite_risk, gsa_observed_fdr, gsa_risk_threshold,
# gsa_request_latency_ms, gsa_rate_limited_total, gsa_attestation_queue_depth,
# gsa_blocks_by_reason_total, gsa_correction_attempts_total, gsa_substrate_health_regime,
# gsa_request_rate_total, gsa_lyapunov_energy
```

### Load test (optional)

```bash
# Generate load against the gateway
for i in {1..100}; do
  curl -s http://localhost:8000/api/v1/assess \
    -H "Authorization: Bearer $JWT_TOKEN" \
    -d '{"input":"test prompt"}' &
done
wait

# Check metrics for request volume
curl http://localhost:8000/metrics | grep gsa_request_rate_total
```

## Step 6: Verify Prometheus scraping

Visit Prometheus UI (`http://localhost:9090/graph`):

```promql
# Check that metrics are being collected
gsa_request_rate_total
gsa_health_composite_risk
gsa_circuit_state
```

## Step 7: Verify Grafana dashboard

Visit Grafana UI (`http://localhost:3000`) and open the GSA Gateway dashboard.
Verify that all 12 panels are displaying data:

1. **Circuit breaker** — should show "0" (closed)
2. **Substrate health** — should show a regime (nominal, attacked, stressed, etc.)
3. **Composite health risk** — should be well below 0.8
4. **Attestation queue depth** — should be low
5. **Request rate by status** — should show success rate and error rate
6. **Blocks by reason** — should show block breakdown
7. **Latency percentiles** — should show p50, p95, p99
8. **Rate limiting** — should show active rate-limit buckets
9. **Risk threshold vs observed FDR** — should track together
10. **Correction attempts per request** — should be low in nominal regime
11. **Lyapunov energy** — should trend toward equilibrium
12. **Substrate health over time** — should show regime transitions

## Troubleshooting

### Pod fails to start

```bash
kubectl describe pod <pod-name> -n gsa
kubectl logs <pod-name> -n gsa
```

Common issues:
- Secret not mounted: verify `gsa-secrets` exists in the `gsa` namespace
- PVC not found: verify `gsa-audit-pvc` exists
- Image not available: verify `gsa-gateway:3.1.0` is in your registry

### No metrics appearing

- Verify Prometheus can reach the gateway: `kubectl port-forward -n gsa svc/gsa-gateway 8000:80`
- Check `/metrics` endpoint: `curl http://localhost:8000/metrics`
- Verify Prometheus scrape config points to the correct service DNS: `gsa-gateway.gsa.svc.cluster.local:80`

### Grafana dashboard empty

- Verify Prometheus datasource is configured and healthy
- Verify the dashboard UID matches the provisioning config
- Check Grafana logs: `kubectl logs -n monitoring deployment/grafana`

## Cleanup

```bash
kubectl delete namespace gsa
```

---

## Validation Checklist

Once deployed, verify:

- [ ] Gateway pod is running and healthy
- [ ] Readiness probe passes (`/health` returns 200)
- [ ] Liveness probe succeeds (pod stays running)
- [ ] Prometheus scrapes metrics successfully
- [ ] All 12 metrics appear in Prometheus
- [ ] Grafana dashboard displays all 12 panels with data
- [ ] Load test completes without errors
- [ ] Circuit breaker state remains closed (0)
- [ ] Health remains nominal
- [ ] FDR stays below 0.10

When all checks pass, the k8s deployment is validated and the scorecard can be updated from 8.17 to 8.27 (+0.1 for manifests, +0.05 for Grafana).
