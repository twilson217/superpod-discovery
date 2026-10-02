# Change Log

## 1.5.1 - 2026-10-02

- Added Run:ai 2.19 Application-name authentication with `--runai-auth-mode app-token`.
- Fixed legacy access-rule and node-pool pagination, added stable sorting and
  detection of repeated object IDs to flag incomplete inventory.
- Validated 2.19.144 API collection, BCM discovery, PostgreSQL 16.11 logical backup
  and restore, and restored control-plane login/inventory. Other patches and
  complete volume/metrics or workload-cluster recovery remain unvalidated.

## 1.5.0 - 2026-10-02

- Added separate private Run:ai restore archives containing full PostgreSQL
  logical dumps, Helm configuration and Kubernetes restore resources.
- Added `--runai-backup-only`, explicit contexts, version profiles, external
  PostgreSQL support and optional inclusion of a consistent metrics-volume export.
- Added streaming dumps, timeout/failure handling, private output permissions,
  checksums and restore notes. Logical backups do not contain PV bytes.

## 1.4.0 - 2026-10-02

- Added BCM, Kubernetes, GPU/networking/policy and selected-host discovery.
- Added redacted Helm values, live resource status and node allocatable evidence.
- Added device definition redaction, restrictive output permissions and failure
  reporting for unavailable resources and commands.
