# Kubernetes deployment

Drop-in DaemonSet for running shannon on every node of a cluster.

## Quick start

```bash
kubectl apply -f https://raw.githubusercontent.com/DatanoiseTV/shannon/main/deploy/k8s/daemonset.yaml
```

That creates a `shannon` namespace, a ServiceAccount, and a DaemonSet
that:

- runs the recorder as `privileged` with `hostPID + hostNetwork`
- writes a rotating capture file to `/var/log/shannon/capture.jsonl.zst`
  on each node (200 MiB per file, 10 GiB absolute cap)
- exposes Prometheus metrics on `:9750/metrics` via the pod IP

Verify:

```bash
kubectl -n shannon get pods -o wide
kubectl -n shannon logs -l app.kubernetes.io/name=shannon --tail=20
```

## Hardening: drop privileged

Once you've confirmed it loads on your kernel, swap `privileged: true`
for the explicit capability set commented inside `daemonset.yaml`:

```yaml
securityContext:
  privileged: false
  capabilities:
    drop: [ALL]
    add: [BPF, PERFMON, NET_ADMIN, DAC_READ_SEARCH, SYS_RESOURCE]
```

`SYS_RESOURCE` only matters on kernels < 5.11; drop it on newer
clusters.

## Scrape with Prometheus

The pod template carries the standard `prometheus.io/scrape` annotations
so a kube-prometheus / vanilla Prom configured for pod-annotation
discovery picks shannon up automatically. For Prom Operator users:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  name: shannon
  namespace: shannon
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: shannon
  podMetricsEndpoints:
    - port: metrics
      interval: 30s
```

## Reading captures off the node

Captures live on each node's host filesystem, not inside the pod's
overlay. Pull one off via `kubectl debug` on the node, your usual
log-shipper (filebeat / vector / fluent-bit), or just SSH:

```bash
kubectl debug node/$(kubectl get pod -n shannon -l app.kubernetes.io/name=shannon -o jsonpath='{.items[0].spec.nodeName}') -it --image=busybox -- sh
# inside the debug pod:
ls /host/var/log/shannon/
```

## Constraints

- **Kernel ≥ 5.8 with BTF on every node.** Container runtimes that
  blacklist `bpf()` (some hardened multi-tenant clusters) are
  incompatible — there's no userspace fallback.
- shannon sees every TCP / UDP socket on the node. That's a privacy
  surface as wide as `tcpdump`. See [SECURITY.md](../../SECURITY.md)
  before deploying outside hosts you own.
- The default config records *everything*. Use `--protocol`, `--comm`,
  or `--pod` flags in the args block to narrow scope before turning
  this on against multi-tenant clusters.
