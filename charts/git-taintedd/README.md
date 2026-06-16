# git-taintedd Helm chart

Deploys [`git-taintedd`](https://github.com/mivanov93/git-tainted) — the
git-tainted server. It polls registered git remotes via `git ls-remote --tags`,
records each tag's oid in an append-only, per-remote, SHA-256 hash-chained
ledger, and serves the verify/admin API. It runs **fully without Redis**.

- **Chart version** tracks the chart; **app version** is the default image tag.
- Release images are published to Docker Hub: `docker.io/mivanov93/git-taintedd`.
- The chart is also published to GHCR OCI: `oci://ghcr.io/mivanov93/charts/git-taintedd`.

## TL;DR

```sh
# from a checkout of the repo:
helm install gt ./charts/git-taintedd

# or from the published OCI chart (pin --version to a release):
helm install gt oci://ghcr.io/mivanov93/charts/git-taintedd --version 0.1.0
```

## Prerequisites

- Kubernetes >= 1.25
- Helm 3.8+ (OCI support)
- For `metrics.serviceMonitor.enabled`: the Prometheus Operator CRDs.
- For the default `sqlite` driver: a StorageClass that can provision a
  `ReadWriteOnce` PVC.

## Storage drivers

| Driver   | Replicas | Needs                                    | Notes                                                  |
| -------- | -------- | ---------------------------------------- | ------------------------------------------------------ |
| `sqlite` | exactly 1 | a PVC (`persistence.enabled=true`)       | single-writer; the chart `fail`s if `replicaCount>1`.  |
| `mysql`  | 1..N     | `secrets.data.mysqlDSN` / `existingSecret` | chain-head CAS + DB lease handle concurrency; HPA OK. |

The chart **refuses to render** an unsafe combination:

- `config.db.driver=sqlite` with `replicaCount>1` → `helm` errors.
- `autoscaling.enabled` with `sqlite`/`persistence` → `helm` errors.

## Configuration

Every non-secret `GT_*` env var maps to a typed value under `config` (and
`metrics` / `auth`); see [`values.yaml`](./values.yaml) for the full,
commented surface and the app defaults. Sensitive values live under `secrets`.

### Secrets — prefer `existingSecret` in production

Do **not** commit real credentials to `values.yaml`. Create a Secret
out-of-band (sealed-secrets / external-secrets / Vault) with the relevant
`GT_*` keys and reference it:

```yaml
secrets:
  create: false
  existingSecret: git-taintedd-creds   # contains GT_MYSQL_DSN, GT_API_KEYS, ...
```

The chart-created Secret (when `secrets.create=true`) only renders the keys you
actually set, using `stringData`.

### Common scenarios

**MySQL, 3 replicas, autoscaling, metrics + ServiceMonitor:**

```yaml
config:
  db:
    driver: mysql
persistence:
  enabled: false
replicaCount: 3
autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 8
metrics:
  enabled: true
  serviceMonitor:
    enabled: true
    labels:
      release: kube-prometheus-stack
secrets:
  existingSecret: git-taintedd-creds
```

**API-key auth on the control endpoints:**

```yaml
auth:
  mode: apikey
secrets:
  existingSecret: git-taintedd-creds   # provides GT_API_KEYS / GT_API_KEYS_SHA256
```

**Ingress + TLS:**

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: git-taintedd.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: git-taintedd-tls
      hosts:
        - git-taintedd.example.com
```

**SSH deploy key for ssh:// remotes** (read-only rootfs ⇒ `HOME=/tmp` already):

```yaml
extraVolumes:
  - name: ssh
    secret:
      secretName: gt-ssh
      defaultMode: 0400
extraVolumeMounts:
  - name: ssh
    mountPath: /tmp/.ssh        # HOME=/tmp, so git finds /tmp/.ssh/id_*
    readOnly: true
```

## Security posture

The pod runs as a non-root user (uid/gid 10001), `readOnlyRootFilesystem: true`,
all capabilities dropped, `allowPrivilegeEscalation: false`, and the
`RuntimeDefault` seccomp profile. A `tmp` `emptyDir` provides the writable
`HOME=/tmp` that `git` needs. `podSecurityContext.fsGroup=10001` makes the PVC
writable. The ServiceAccount token is not mounted by default.

## Health & rollout

- Liveness `/healthz`, readiness `/readyz` (DB-ping), startup `/healthz`.
- A `checksum/config` + `checksum/secret` pod annotation rolls the pods when the
  ConfigMap/Secret changes.
- `updateStrategy: auto` → `Recreate` when `persistence.enabled` (a RWO PVC
  can't be dual-attached), else `RollingUpdate`.

## Testing the release

```sh
helm test <release> --namespace <ns>
```

runs an in-cluster Pod that curls `/readyz` and fails loudly if not ready.

## Uninstall

```sh
helm uninstall <release>
```

The sqlite PVC is retained by default (Helm does not delete PVCs); delete it
manually if you want the data gone.
