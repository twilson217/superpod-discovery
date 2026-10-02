# CBU SuperPOD Discovery

Collect configuration and upgrade-planning evidence from a BCM-managed
SuperPOD with Kubernetes and optional Run:ai. The package contains a standalone
Python collector and usage documentation.

## Run

Use root on the active primary BCM head node. Python 3, cmsh, BCM Kubernetes
modules, kubectl, Helm and SSH access to managed servers are required.
The collector uses the Python standard library and installs no dependencies.

```bash
chmod 0755 superpod-discovery-collector.py
./superpod-discovery-collector.py
```

For **Run:ai 2.19**, use:

```bash
./superpod-discovery-collector.py --runai-auth-mode app-token
```

At the API prompts, enter the URL, **Application name** (not its UUID), and
Application secret. Version 2.19 uses `app_token` with `appID`/`appSecret`;
the default `client-credentials` flow remains available for newer deployments.
Authentication failures are reported without retrying a different credential flow.

The script discovers cluster and host names automatically. It prompts for
optional Run:ai API collection: enter the UI URL, application/service-account
client ID, and client secret. The secret prompt hides typed input. The head node
must resolve and reach that URL and trust its TLS certificate. Do not disable
TLS verification to bypass a DNS or CA problem.

Run:ai 2.23 calls this API identity an Application; newer releases use Service
Account terminology. Have the customer create an identity with approved read
access to all clusters and objects to be inventoried:

- [Run:ai 2.23 Applications](https://run-ai-docs.nvidia.com/self-hosted/2.23/infrastructure-setup/authentication/applications)
- [Run:ai Service Accounts](https://run-ai-docs.nvidia.com/self-hosted/infrastructure-setup/authentication/service-accounts)

Authentication uses a token request; discovery API operations are reads. API
permissions and release differences can leave individual endpoints unavailable.
The results record these failures rather than treating them as empty inventories.

## Collected Evidence

- BCM devices, software images, categories, networks, overlays, HA and Kubernetes
  definitions, trusted domains and labelsets. Individual definitions are gathered
  for non-switch/non-infrastructure devices.
- Every BCM-discovered Kubernetes cluster: nodes and allocatable resources, live
  pod/controller specs, images, services, ingress, storage, admission, RBAC,
  installed CRDs, and referenced ConfigMaps. Manifest-installed controllers are
  included independently of Helm releases.
- Redacted effective Helm values for **every release**, including Network
  Operator, GPU Operator, Kyverno and Run:ai.
- Live networking/GPU/policy resources discovered from installed CRDs:
  NICClusterPolicy, NIC configuration/firmware resources, Spectrum-X resources,
  SR-IOV policies and node states, IP pools, NetworkAttachmentDefinitions,
  Whereabouts, NFD, Calico/Tigera, MetalLB and Kyverno policies where installed.
  Resource names are fully qualified to avoid similarly named API collisions.
  Resource reconciliation status is retained. Bulk policy-report APIs are omitted.
- Labeled Spectrum-X profile ConfigMaps, including profiles not mounted directly
  by a controller, and primary node capacity/allocatable state.
- Management/control-plane server hardware, interfaces, routes, bonds, mounts
  and runtime state; compact discovery across identified GPU hosts; detailed
  NIC/RDMA/QoS/Spectrum-X systemd evidence on the first two identified GPU hosts.
- Storage/identity detail on two GPU hosts and one control-plane server; APT,
  package pins, image repository configuration, discovered DNS/TLS endpoints.
- Optional Run:ai object inventory through the existing version-tolerant API
  client, including cluster-scoped and workload-related objects it can access.

The BCM device list may mention switches, but the collector does **not** connect
to switches or collect switch CLI/configuration output. The discovery archive
is an inventory; private Run:ai restore backups are
created separately. Neither archive is a performance test or an exhaustive
per-host configuration export.
Review the selected-host list: unfamiliar host/category naming can affect which
machines are classified as GPU hosts.

## Outputs And Review

By default the collector writes these files under `/tmp`:

```text
superpod-discovery-<UTC timestamp>.tar.gz
superpod-discovery-<UTC timestamp>.tar.gz.sha256
```

Inspect `collector/collection-summary.json`, `collector/selected-hosts.json`,
the failed-command reports and `SECURITY_REVIEW.txt` before transferring anything.
Unsupported APIs, missing tools, denied permissions and unreachable nodes are
recorded with return codes; a completed archive can still contain collection gaps.

Redaction is best effort, not a guarantee. Discovery does not query Kubernetes
Secret resources. The separate Run:ai backup intentionally includes Secrets,
raw Helm configuration and full database contents for recovery. Values,
manifests, ConfigMaps, host output and API objects may still
contain sensitive information. Keep the archive private and review it before
sharing through the customer's approved channel. The script refuses to create
an archive if its final scan identifies private-key/bearer-token material.

Use `--keep-directory` to keep the extracted outputs for review. Diagnostic
options `--skip-runai`, `--skip-remote`, and `--skip-helm-values` deliberately
produce partial discovery. Use `--max-workers 4` to reduce concurrent SSH load.
`--help` lists all options.

## Run:ai Backups

Normal discovery attempts backups in all BCM-discovered Kubernetes clusters,
independently of API credentials. `--skip-runai` only skips the API prompt;
`--skip-runai-backup` disables backups. `--skip-helm-values` only affects redacted
inventory and does not suppress restore configuration in the backup.

To back up Run:ai without BCM or discovery, run as a user with Kubernetes access:

```bash
python3 superpod-discovery-collector.py --runai-backup-only
# Separate control-plane and workload clusters:
python3 superpod-discovery-collector.py --runai-backup-only \
  --runai-backup-context control-plane --runai-backup-context workloads
```

Backup-only defaults to the current kube context and never prompts for API
credentials. Explicit contexts also override the BCM targets in normal mode.
Python 3, kubectl and Helm are required. Permissions must allow Helm reads,
RunaiConfig reads, namespace configuration/Secret reads and PostgreSQL pod exec.
A full database export also requires a PostgreSQL administrative account.

Private outputs are separate from discovery:

```text
runai-backup-<UTC timestamp>--<target>.tar.gz
runai-backup-<UTC timestamp>--<target>.tar.gz.sha256
```

Each contains unredacted Helm user/effective values and manifests, complete
RunaiConfig objects, namespace restore resources (including Secrets and PVC
specifications), a backup manifest, restore notes and per-file checksums. A
control-plane archive also includes `postgres/all-databases.sql`: **pg_dumpall**
with every accessible database and global roles/password hashes. This expands
on the documented backend-only `pg_dump`. It is consistent per database; use a
quiet window if consistency across databases is required. Successful logical
exports do not prove a restore will succeed.

Helm app versions (or chart-version fallback) select the recorded backup profile.
The [2.20](https://run-ai-docs.nvidia.com/self-hosted/2.20/infrastructure-setup/procedures/cluster-restore)
and [2.21](https://run-ai-docs.nvidia.com/self-hosted/2.21/infrastructure-setup/procedures/cluster-restore)
procedures use the same logical PostgreSQL backup approach.
[2.23](https://run-ai-docs.nvidia.com/self-hosted/2.23/infrastructure-setup/procedures/cluster-restore)
and current docs explicitly include cluster Helm values. We save both cluster
and control-plane values across versions. The 2.19 profile is patch-specific: its
legacy procedure/API schema and live restore require patch-specific validation.
**2.19.144 has been validated** with its bundled charts/images: trusted TLS,
API inventory and pagination, BCM discovery, private backup and a PostgreSQL
16.11 restore followed by 2.19.144 control-plane login/inventory checks. Other
2.19 patches remain provisional. The lab did not validate metrics/PV recovery,
external PostgreSQL export, GPU execution, nonempty group/SSO recovery or
reconnection of a restored workload cluster. This does not establish an upgrade
path to a later Run:ai release.
Other unexamined releases are marked as requiring validation. Unidentified or pre-2.19
versions fail.

The PostgreSQL pod/container is detected from running database images. Multiple
candidates require `--runai-pg-pod` and optionally `--runai-pg-container`; explicit
pod selection also supports custom image names. Select the primary. The default
DB user is `postgres`; override with `--runai-pg-user`. Authentication uses the
pod's PostgreSQL password environment/file variables. If these are unavailable,
use `--runai-pg-password-env NAME` to send a local environment variable's value
over stdin without placing it in argv. Use an approved secret-loading mechanism
and avoid shell-history literals. A missing pod never silently selects external
PostgreSQL.

For external PostgreSQL, use `--runai-external-postgres` with local `pg_dumpall`
and libpq `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSFILE`/other PG settings configured for
the intended server and trusted TLS. Use an appropriate client version. The
external credentials are separate from `--runai-pg-password-env`. The connection
is explicitly operator-configured; the collector cannot confirm its association
with the selected Helm deployment. Global dump permissions are required; managed
server restrictions produce a failed backup rather than an incomplete success.

**Metrics/PV boundary:** database SQL and PVC specifications do not contain
volume bytes. Thanos metrics, external object stores and workload data need
separate consistent storage backups. Include an existing consistent metrics
volume tar.gz with `--runai-metrics-backup /secure/path/metrics.tar.gz`. It is
copied without extraction; its provenance, coverage and consistency still need
operator verification and a restore test. Custom project namespace/RBAC outside
release namespaces also needs separate protection. `backup-manifest.json` reports
metrics coverage and explicitly does not claim verified full disaster recovery.

Archives are 0600 and staging directories 0700. They retain sensitive data and
must be restricted and encrypted for storage/transfer; do not send them with the
redacted discovery package without customer authorization. Backup data bypasses
discovery redaction/security scanning intentionally, so restore data is intact.
`--keep-directory` retains staging output. Failed commands retain private partial
output and stderr and do not create a successful backup archive. Per-command
backup timeout defaults to 3600 seconds (`--runai-backup-timeout`).

Cluster-only contexts produce configuration archives. Include the backend context
to obtain the database archive. When Run:ai is found but no DB backup succeeds,
the command exits nonzero; normal discovery still completes its own archive.
No Run:ai in an ordinary cluster is recorded as a skip. Read each backup manifest
and `RESTORE.txt` and test a restore before relying on these artifacts.

## Verification And Support Scope

```bash
python3 superpod-discovery-collector.py --help
python3 superpod-discovery-collector.py --version
```

The collector has automated regression tests in its development repository.
Run:ai 2.19.144 received live API, BCM discovery and logical backup/restore checks.
This distribution contains the runtime script and customer documentation.
Optional API paths can still return 403/404; those remain visible in inventory.
Quotas are present in department/project responses even when separate quota-summary
paths fail. Viewer permissions do not include roles/access rules/identity settings
on 2.19; use approved access and review authentication/endpoint results.
