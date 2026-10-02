#!/usr/bin/env python3
"""Collect a from-scratch SuperPOD inventory from the primary BCM head node.

Run as root with no arguments:

    ./superpod-discovery-collector.py

The script uses only the Python standard library. It discovers BCM objects and
hosts from cmsh, uses BCM Kubernetes environment modules for cluster queries,
collects read-only host evidence over SSH, redacts likely secret-valued Helm
and Run:AI API settings, and creates a compressed archive and SHA-256 file
under /tmp. By default it interactively offers optional Run:AI API discovery;
use --skip-runai to suppress that prompt. A separate unredacted Run:ai restore
backup is also attempted by default. Use --runai-backup-only for backups using
kubectl/Helm without BCM discovery, or --skip-runai-backup for inventory only.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import getpass
import hashlib
import json
import os
import re
import shlex
import signal
import shutil
import socket
import subprocess
import sys
import tarfile
import textwrap
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


VERSION = "1.5.1"
DEFAULT_COMMAND_TIMEOUT = 180
DEFAULT_SSH_TIMEOUT = 240
DEFAULT_WORKERS = 12
RUNAI_API_TIMEOUT = 60
RUNAI_API_LIMIT = 500
RUNAI_API_MAX_BYTES = 50 * 1024 * 1024

PRINT_LOCK = threading.Lock()
RESULT_LOCK = threading.Lock()


@dataclass
class CommandResult:
    command: str
    returncode: int
    stdout: str
    stderr: str
    started: str
    finished: str
    timed_out: bool = False


@dataclass
class Device:
    hostname: str
    category: str = ""
    software_image: str = ""
    device_type: str = ""

    @property
    def search_text(self) -> str:
        return " ".join(
            (self.hostname, self.category, self.software_image, self.device_type)
        ).lower()


@dataclass
class RunAIConfig:
    base_url: str
    client_id: str
    client_secret: str
    auth_mode: str = "client-credentials"


@dataclass
class APIResult:
    path: str
    status: int
    data: object | None
    error: str
    started: str
    finished: str
    timed_out: bool = False


class SameHostRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevent bearer credentials from following redirects to another host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old = urllib.parse.urlsplit(req.full_url)
        new = urllib.parse.urlsplit(newurl)
        if (old.scheme, old.hostname, old.port) != (new.scheme, new.hostname, new.port):
            raise urllib.error.HTTPError(
                req.full_url,
                code,
                "Refused cross-host redirect while using Run:AI credentials",
                headers,
                fp,
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class RunAIClient:
    def __init__(self, config: RunAIConfig) -> None:
        self.base_url = config.base_url
        self.client_id = config.client_id
        self.client_secret = config.client_secret
        self.auth_mode = config.auth_mode
        self.token = ""
        self.opener = urllib.request.build_opener(SameHostRedirectHandler())

    def request_json(
        self,
        method: str,
        path: str,
        *,
        payload: object | None = None,
        authenticated: bool = True,
    ) -> APIResult:
        started = now_utc()
        url = urllib.parse.urljoin(f"{self.base_url}/", path.lstrip("/"))
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if authenticated:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=RUNAI_API_TIMEOUT) as response:
                raw = response.read(RUNAI_API_MAX_BYTES + 1)
                if len(raw) > RUNAI_API_MAX_BYTES:
                    return APIResult(
                        path,
                        413,
                        None,
                        f"Response exceeded {RUNAI_API_MAX_BYTES} bytes",
                        started,
                        now_utc(),
                    )
                try:
                    data = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    return APIResult(
                        path,
                        response.status,
                        None,
                        "Response was not valid JSON",
                        started,
                        now_utc(),
                    )
                return APIResult(
                    path, response.status, data, "", started, now_utc()
                )
        except urllib.error.HTTPError as exc:
            return APIResult(
                path,
                exc.code,
                None,
                f"HTTP {exc.code}: {exc.reason}",
                started,
                now_utc(),
            )
        except urllib.error.URLError as exc:
            reason = exc.reason
            timed_out = isinstance(reason, TimeoutError)
            return APIResult(
                path,
                124 if timed_out else 1,
                None,
                f"Connection failed: {reason}",
                started,
                now_utc(),
                timed_out=timed_out,
            )
        except TimeoutError:
            return APIResult(
                path,
                124,
                None,
                f"Request timed out after {RUNAI_API_TIMEOUT} seconds",
                started,
                now_utc(),
                timed_out=True,
            )

    def authenticate(self) -> APIResult:
        self.token = ""
        # 2.19's installed schema and live token API use the Application name
        # as appID. Select explicitly; never retry rejected credentials.
        payload = (
            {"grantType": "app_token", "appID": self.client_id,
             "appSecret": self.client_secret}
            if self.auth_mode == "app-token" else
            {"grantType": "client_credentials", "clientId": self.client_id,
             "clientSecret": self.client_secret}
        )
        result = self.request_json(
            "POST",
            "/api/v1/token",
            payload=payload,
            authenticated=False,
        )
        if isinstance(result.data, dict):
            token = result.data.get("accessToken") or result.data.get("access_token")
            if isinstance(token, str) and token:
                self.token = token
                result.data = None
                return result
            result.error = "Authentication response did not contain an access token"
            result.status = 1
            result.data = None
        return result


class Collector:
    def __init__(self, args: argparse.Namespace) -> None:
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.root = args.output_root / f"superpod-discovery-{stamp}"
        self.archive = self.root.with_suffix(".tar.gz")
        self.digest_file = Path(f"{self.archive}.sha256")
        self.args = args
        self.backup_failed = False
        self.runai_backups: list[dict] = []
        self.command_timeout = args.command_timeout
        self.ssh_timeout = args.ssh_timeout
        self.max_workers = args.max_workers
        self.skip_remote = args.skip_remote
        self.skip_helm_values = args.skip_helm_values
        self.keep_directory = args.keep_directory
        self.runai_config: RunAIConfig | None = getattr(args, "runai_config", None)
        self.runai_prompt_status: str = getattr(
            args, "runai_prompt_status", "not-configured"
        )
        self.results: list[tuple[str, int, bool]] = []
        self.security_findings: list[str] = []
        self.kubernetes_clusters: list[str] = []
        self.software_images: list[str] = []
        self.categories: list[str] = []
        self.devices: list[Device] = []
        self.kubernetes_nodes: set[str] = set()
        self.control_plane_nodes: set[str] = set()
        self.endpoint_names: set[str] = set()

    def progress(self, message: str) -> None:
        with PRINT_LOCK:
            print(message, flush=True)

    def prepare(self) -> None:
        for name in (
            "bcm",
            "hosts",
            "kubernetes",
            "dgx",
            "storage",
            "airgap",
            "dns-tls",
            "runai",
            "collector",
        ):
            (self.root / name).mkdir(parents=True, exist_ok=True)

        metadata = {
            "collector_version": VERSION,
            "started_utc": now_utc(),
            "collector_host": socket.getfqdn(),
            "collector_user": getpass.getuser(),
            "python": sys.version,
            "command_timeout_seconds": self.command_timeout,
            "ssh_timeout_seconds": self.ssh_timeout,
            "max_workers": self.max_workers,
            "runai_api_collection": self.runai_prompt_status,
        }
        write_text(self.root / "collector" / "metadata.json", json.dumps(metadata, indent=2))
        try:
            shutil.copy2(Path(__file__).resolve(), self.root / "collector" / Path(__file__).name)
        except OSError as exc:
            write_text(self.root / "collector" / "script-copy-error.txt", f"{exc}\n")

    def execute(
        self,
        command: Sequence[str],
        *,
        timeout: int | None = None,
        input_text: str | None = None,
        env: dict[str, str] | None = None,
    ) -> CommandResult:
        display = shlex.join(str(part) for part in command)
        started = now_utc()
        try:
            completed = subprocess.run(
                [str(part) for part in command],
                input=input_text,
                text=True,
                capture_output=True,
                timeout=timeout or self.command_timeout,
                env=env,
                check=False,
            )
            return CommandResult(
                display,
                completed.returncode,
                completed.stdout,
                completed.stderr,
                started,
                now_utc(),
            )
        except subprocess.TimeoutExpired as exc:
            stdout = decode_timeout_stream(exc.stdout)
            stderr = decode_timeout_stream(exc.stderr)
            stderr += f"\nCollector timeout after {timeout or self.command_timeout} seconds.\n"
            return CommandResult(
                display, 124, stdout, stderr, started, now_utc(), timed_out=True
            )
        except OSError as exc:
            return CommandResult(display, 127, "", f"{exc}\n", started, now_utc())

    def execute_shell(self, script: str, *, timeout: int | None = None) -> CommandResult:
        return self.execute(["/bin/bash", "-lc", script], timeout=timeout)

    def record(
        self,
        relative_path: str | Path,
        result: CommandResult,
        *,
        stdout_transform=None,
        stderr_transform=None,
    ) -> CommandResult:
        output = result.stdout
        error_output = result.stderr
        if stdout_transform:
            output = stdout_transform(output)
        if stderr_transform:
            error_output = stderr_transform(error_output)
        content = "\n".join(
            (
                f"Command: {result.command}",
                f"Started UTC: {result.started}",
                f"Finished UTC: {result.finished}",
                f"Return code: {result.returncode}",
                f"Timed out: {'yes' if result.timed_out else 'no'}",
                "",
                "--- stdout ---",
                output.rstrip(),
                "",
                "--- stderr ---",
                error_output.rstrip(),
                "",
            )
        )
        target = self.root / relative_path
        write_text(target, content)
        with RESULT_LOCK:
            self.results.append((str(relative_path), result.returncode, result.timed_out))
        return result

    def collect_local(self, relative_path: str, command: Sequence[str]) -> CommandResult:
        return self.record(relative_path, self.execute(command))

    def collect_shell(self, relative_path: str, script: str) -> CommandResult:
        return self.record(relative_path, self.execute_shell(script))

    def cmsh(self, statement: str, relative_path: str) -> CommandResult:
        return self.record(
            relative_path,
            self.execute(["cmsh", "-c", statement]),
            stdout_transform=redact_cmsh_output,
            stderr_transform=redact_sensitive_yaml,
        )

    def collect_bcm(self) -> None:
        self.progress("[1/9] Collecting BCM inventory and discovering managed objects")
        commands = {
            "bcm/hostname.txt": ["hostname", "-f"],
            "bcm/os-release.txt": ["cat", "/etc/os-release"],
            "bcm/kernel.txt": ["uname", "-a"],
            "bcm/bcm-packages.txt": ["dpkg-query", "-W"],
            "bcm/ha-status.txt": ["cmha", "status"],
            "bcm/kubernetes-versions-available.txt": [
                "cm-kubernetes-setup",
                "--list-versions",
            ],
        }
        for path, command in commands.items():
            self.collect_local(path, command)

        cmsh_commands = {
            "bcm/devices.txt": "device; list",
            "bcm/device-fields.txt": (
                "device; list -f "
                "hostname:80,category:80,softwareimage:120,type:30 -d \"|\""
            ),
            "bcm/software-images.txt": "softwareimage; list",
            "bcm/software-image-names.txt": "softwareimage; list -f name",
            "bcm/categories.txt": "category; list",
            "bcm/category-names.txt": "category; list -f name",
            "bcm/configuration-overlays.txt": "configurationoverlay; list",
            "bcm/networks.txt": "network; list",
            "bcm/network-names.txt": "network; list -f name",
            "bcm/overlay-names.txt": "configurationoverlay; list -f name",
            "bcm/kubernetes-clusters.txt": "kubernetes; list",
            "bcm/kubernetes-cluster-names.txt": "kubernetes; list -f name",
        }
        captured: dict[str, CommandResult] = {}
        for path, statement in cmsh_commands.items():
            captured[path] = self.cmsh(statement, path)

        self.kubernetes_clusters = parse_cmsh_name_list(
            captured["bcm/kubernetes-cluster-names.txt"].stdout
        ) or parse_cmsh_name_list(captured["bcm/kubernetes-clusters.txt"].stdout)
        self.software_images = parse_cmsh_name_list(
            captured["bcm/software-image-names.txt"].stdout
        ) or parse_cmsh_name_list(captured["bcm/software-images.txt"].stdout)
        self.categories = parse_cmsh_name_list(
            captured["bcm/category-names.txt"].stdout
        ) or parse_cmsh_name_list(captured["bcm/categories.txt"].stdout)
        self.devices = parse_device_table(captured["bcm/device-fields.txt"].stdout)
        if not self.devices:
            self.devices = parse_default_device_table(
                captured["bcm/devices.txt"].stdout
            )

        discovery = {
            "kubernetes_clusters": self.kubernetes_clusters,
            "software_images": self.software_images,
            "categories": self.categories,
            "devices": [device.__dict__ for device in self.devices],
        }
        write_text(
            self.root / "collector" / "discovered-bcm-objects.json",
            json.dumps(discovery, indent=2),
        )

        for cluster in self.kubernetes_clusters:
            safe = safe_name(cluster)
            statements = {
                f"bcm/kubernetes-{safe}-definition.txt": f"kubernetes; use {cmsh_quote(cluster)}; show",
                f"bcm/kubernetes-{safe}-trusteddomains.txt": f"kubernetes; use {cmsh_quote(cluster)}; get trusteddomains",
                f"bcm/kubernetes-{safe}-labelsets.txt": f"kubernetes; use {cmsh_quote(cluster)}; labelsets; list",
            }
            for path, statement in statements.items():
                self.cmsh(statement, path)

        for image in self.software_images:
            self.cmsh(
                f"softwareimage; use {cmsh_quote(image)}; show",
                f"bcm/softwareimage-{safe_name(image)}-definition.txt",
            )
        for category in self.categories:
            self.cmsh(
                f"category; use {cmsh_quote(category)}; show",
                f"bcm/category-{safe_name(category)}-definition.txt",
            )

        for network in parse_cmsh_name_list(captured["bcm/network-names.txt"].stdout):
            self.cmsh(
                f"network; use {cmsh_quote(network)}; show",
                f"bcm/network-{safe_name(network)}-definition.txt",
            )
        for overlay in parse_cmsh_name_list(captured["bcm/overlay-names.txt"].stdout):
            self.cmsh(
                f"configurationoverlay; use {cmsh_quote(overlay)}; show",
                f"bcm/overlay-{safe_name(overlay)}-definition.txt",
            )
        for device in self.devices:
            if not is_switch_or_infrastructure(device):
                self.cmsh(
                    f"device; use {cmsh_quote(device.hostname)}; show",
                    f"bcm/device-{safe_name(device.hostname)}-definition.txt",
                )

    def kubernetes_shell(self, cluster: str, command: str) -> str:
        module_name = shlex.quote(f"kubernetes/{cluster}")
        return (
            "set +e; "
            "module purge >/dev/null 2>&1 || true; "
            f"module load {module_name} || exit $?; "
            f"{command}"
        )

    def collect_kubernetes(self) -> None:
        self.progress("[2/9] Collecting Kubernetes and installed-application state")
        if not self.kubernetes_clusters:
            write_text(
                self.root / "kubernetes" / "NO_CLUSTERS_DISCOVERED.txt",
                "No Kubernetes cluster names could be parsed from cmsh output.\n",
            )
            return

        commands = {
            "kubeconfig-endpoint.txt": "kubectl config view --minify --raw=false",
            "kubernetes-version.yaml": "kubectl version -o yaml",
            "nodes-wide.txt": "kubectl get nodes -o wide",
            "nodes.json": "kubectl get nodes -o json",
            "pods.json": "kubectl get pods -A -o json",
            "node-labels.txt": "kubectl get nodes --show-labels",
            "namespaces.txt": "kubectl get namespaces --show-labels",
            "kubeadm-config.yaml": "kubectl -n kube-system get configmap kubeadm-config -o yaml",
            "kube-system-configmaps.yaml": "kubectl -n kube-system get configmap -o yaml",
            "controllers-wide.txt": "kubectl get deployments,statefulsets,daemonsets -A -o wide",
            "live-workload-controllers.json": "kubectl get deployments,statefulsets,daemonsets -A -o json",
            "live-services-ingress-pdb.json": "kubectl get service,ingress,pdb -A -o json",
            "live-namespaced-rbac.json": "kubectl get serviceaccount,role,rolebinding -A -o json",
            "live-cluster-rbac.json": "kubectl get clusterrole,clusterrolebinding -o json",
            "live-admission-webhooks.json": "kubectl get mutatingwebhookconfiguration,validatingwebhookconfiguration -o json",
            "pods-wide.txt": "kubectl get pods -A -o wide",
            "configmaps-wide.txt": "kubectl get configmap -A -o wide",
            "pod-images.txt": (
                "kubectl get pods -A -o "
                "jsonpath='{range .items[*]}{.metadata.namespace}{\"\\t\"}"
                "{.metadata.name}{\"\\t\"}{.spec.nodeName}{\"\\t\"}"
                "{range .spec.initContainers[*]}{.image}{\",\"}{end}"
                "{range .spec.containers[*]}{.image}{\",\"}{end}{\"\\n\"}{end}'"
            ),
            "events.txt": "kubectl get events -A --sort-by=.metadata.creationTimestamp",
            "workload-disruption-and-limits.txt": "kubectl get pdb,resourcequota,limitrange -A -o wide",
            "scheduling-runtime-classes.yaml": "kubectl get priorityclass,runtimeclass -o yaml",
            "helm-releases.json": "helm list -A -o json",
            "crds.txt": "kubectl get crd",
            "crds.json": "kubectl get crd -o json",
            "crd-versions.txt": "kubectl get crd -o custom-columns='NAME:.metadata.name,API-VERSIONS:.spec.versions[*].name,STORED-VERSIONS:.status.storedVersions'",
            "api-resources.txt": "kubectl api-resources",
            "api-services.txt": "kubectl get apiservice",
            "admission-webhooks.txt": "kubectl get mutatingwebhookconfiguration,validatingwebhookconfiguration",
            "storage-classes-drivers.txt": "kubectl get storageclass,csidriver -o wide",
            "persistent-volumes.txt": "kubectl get pv -o wide",
            "persistent-volume-claims.txt": "kubectl get pvc -A -o wide",
            "snapshot-classes.txt": "kubectl get volumesnapshotclass",
            "ingress-classes.yaml": "kubectl get ingressclass -o yaml",
            "ingresses.yaml": "kubectl get ingress -A -o yaml",
            "services-wide.txt": "kubectl get service -A -o wide",
            "certificates.yaml": "kubectl get certificates,certificaterequests,issuers -A -o yaml",
            "cluster-issuers.yaml": "kubectl get clusterissuers -o yaml",
            "runaiconfig.yaml": "kubectl get runaiconfig -A -o yaml",
            "knative-serving.yaml": "kubectl get knativeserving -A -o yaml",
            "knative-domain.yaml": "kubectl get configmap config-domain -n knative-serving -o yaml",
            "metallb-addressing.yaml": "kubectl get ipaddresspools,l2advertisements,bgpadvertisements -A -o yaml",
            "ingress-nginx-resources.yaml": "kubectl get deployment,daemonset,service,configmap -A -l app.kubernetes.io/name=ingress-nginx -o yaml",
            "ingress-routing-summary.txt": "kubectl get ingress -A -o wide",
            "external-service-summary.txt": "kubectl get service -A -o wide",
        }

        for cluster in self.kubernetes_clusters:
            cluster_dir = self.root / "kubernetes" / safe_name(cluster)
            cluster_dir.mkdir(parents=True, exist_ok=True)
            captured: dict[str, CommandResult] = {}
            sanitized_json = {
                "live-workload-controllers.json",
                "live-services-ingress-pdb.json",
                "live-namespaced-rbac.json",
                "live-cluster-rbac.json",
                "live-admission-webhooks.json",
            }
            for filename, command in commands.items():
                result = self.execute_shell(self.kubernetes_shell(cluster, command))
                stdout_transform = None
                if filename in {"nodes.json", "pods.json", "crds.json"}:
                    stdout_transform = lambda text: redact_kubernetes_json(text, keep_status=True)
                elif filename in sanitized_json:
                    stdout_transform = redact_kubernetes_json
                elif filename.endswith((".yaml", ".yml")):
                    stdout_transform = redact_sensitive_yaml
                self.record(
                    cluster_dir.relative_to(self.root) / filename,
                    result,
                    stdout_transform=stdout_transform,
                    stderr_transform=redact_sensitive_yaml,
                )
                captured[filename] = result

            write_text(
                cluster_dir / "live-controller-ownership.tsv",
                summarize_kubernetes_controllers(
                    captured["live-workload-controllers.json"].stdout
                ),
            )

            self.collect_platform_resources(cluster, cluster_dir, captured["crds.json"])

            configmap_dir = cluster_dir / "referenced-configmaps-redacted"
            configmap_dir.mkdir(exist_ok=True)
            configmap_refs = extract_controller_configmap_refs(
                captured["live-workload-controllers.json"].stdout
            )
            for namespace, name in configmap_refs:
                command = (
                    "kubectl get configmap "
                    f"{shlex.quote(name)} -n {shlex.quote(namespace)} -o json"
                )
                result = self.execute_shell(self.kubernetes_shell(cluster, command))
                self.record(
                    configmap_dir.relative_to(self.root)
                    / f"{safe_name(namespace)}--{safe_name(name)}.json.txt",
                    result,
                    stdout_transform=redact_kubernetes_json,
                    stderr_transform=redact_sensitive_yaml,
                )
            write_text(
                configmap_dir / "REFERENCES.tsv",
                "namespace\tconfigmap\n"
                + "\n".join(f"{namespace}\t{name}" for namespace, name in configmap_refs)
                + ("\n" if configmap_refs else ""),
            )

            self.kubernetes_nodes.update(parse_kubernetes_node_names(
                captured["nodes-wide.txt"].stdout
            ))
            self.control_plane_nodes.update(parse_kubernetes_control_plane_names(
                captured["nodes-wide.txt"].stdout
            ))
            self.endpoint_names.update(extract_endpoint_names(
                captured["kubeconfig-endpoint.txt"].stdout
            ))
            self.endpoint_names.update(extract_ingress_hosts(
                captured["ingresses.yaml"].stdout
            ))
            self.endpoint_names.update(extract_knative_domains(
                captured["knative-domain.yaml"].stdout
            ))
            self.endpoint_names.update(extract_endpoint_names(
                captured["runaiconfig.yaml"].stdout
            ))

            if not self.skip_helm_values:
                releases = parse_helm_releases(captured["helm-releases.json"].stdout)
                helm_dir = cluster_dir / "helm-values-redacted"
                helm_dir.mkdir(exist_ok=True)
                for release, namespace in releases:
                    command = (
                        f"helm get values {shlex.quote(release)} "
                        f"-n {shlex.quote(namespace)} --all -o yaml"
                    )
                    result = self.execute_shell(self.kubernetes_shell(cluster, command))
                    self.record(
                        helm_dir.relative_to(self.root)
                        / f"{safe_name(namespace)}--{safe_name(release)}.yaml.txt",
                        result,
                        stdout_transform=redact_sensitive_yaml,
                        stderr_transform=redact_sensitive_yaml,
                    )

        write_text(
            self.root / "collector" / "discovered-kubernetes-nodes.txt",
            "\n".join(sorted(self.kubernetes_nodes)) + "\n",
        )

    def collect_platform_resources(
        self, cluster: str, cluster_dir: Path, crds: CommandResult
    ) -> None:
        """Collect installed networking/operator APIs, regardless of Helm ownership."""
        directory = cluster_dir / "platform-resources"
        directory.mkdir(exist_ok=True)
        resources = parse_platform_crds(crds.stdout)
        write_text(
            directory / "REQUESTED_RESOURCES.tsv",
            "resource\tscope\n" + "".join(f"{name}\t{scope}\n" for name, scope in resources),
        )
        if crds.returncode != 0:
            write_text(
                directory / "CRD_DISCOVERY_FAILED.txt",
                "CRD discovery failed; platform coverage is incomplete. See crds.json.\n",
            )
        elif not resources:
            write_text(
                directory / "NO_MATCHING_CRDS.txt",
                "No matching platform CRDs were found. Consult the API inventory.\n",
            )
        for name, scope in resources:
            namespace_flag = " -A" if scope == "Namespaced" else ""
            command = f"kubectl get {shlex.quote(name)}{namespace_flag} -o json"
            result = self.execute_shell(self.kubernetes_shell(cluster, command))
            self.record(
                directory.relative_to(self.root) / f"{safe_name(name)}.json.txt",
                result,
                stdout_transform=lambda text: redact_kubernetes_json(text, keep_status=True),
                stderr_transform=redact_sensitive_yaml,
            )
        self.record(
            directory.relative_to(self.root) / "spectrum-x-profile-configmaps.json.txt",
            self.execute_shell(self.kubernetes_shell(
                cluster,
                "kubectl get configmap -A -l "
                "network.nvidia.com/operator.nic-configuration.spectrum-x-profile -o json",
            )),
            stdout_transform=redact_kubernetes_json,
            stderr_transform=redact_sensitive_yaml,
        )

    def fetch_runai_pages(
        self, client: RunAIClient, path: str, *, paginated: bool
    ) -> APIResult:
        if not paginated:
            return client.request_json("GET", path)

        pages = []
        offset = 0
        seen_ids: set[str] = set()
        page_key = {
            "/api/v1/org-unit/projects": "projects",
            "/api/v1/org-unit/departments": "departments",
            "/api/v1/node-pools": "nodepools",
            "/api/v1/authorization/access-rules": "accessRules",
            "/api/v1/workloads": "workloads",
        }.get(urllib.parse.urlsplit(path).path)
        first_result: APIResult | None = None
        last_result: APIResult | None = None
        for _ in range(100):
            separator = "&" if "?" in path else "?"
            request_path = (
                f"{path}{separator}limit={RUNAI_API_LIMIT}&offset={offset}"
            )
            if page_key and "sortBy" not in urllib.parse.parse_qs(urllib.parse.urlsplit(path).query):
                request_path += "&sortBy=createdAt&sortOrder=asc"
            result = client.request_json("GET", request_path)
            first_result = first_result or result
            last_result = result
            if result.status != 200 or result.data is None:
                if not pages:
                    return result
                break
            pages.append(result.data)
            if page_key and isinstance(result.data, dict):
                ids = [str(item["id"]) for item in result.data.get(page_key, [])
                       if isinstance(item, dict) and item.get("id") is not None]
                if len(ids) != len(set(ids)) or seen_ids.intersection(ids):
                    result.error = "Pagination returned duplicate IDs; inventory may be incomplete"
                    break
                seen_ids.update(ids)
            next_offset = runai_next_offset(result.data, offset)
            if next_offset is None:
                break
            if next_offset <= offset:
                result.error = "Pagination returned a non-increasing next offset"
                break
            offset = next_offset

        assert first_result is not None and last_result is not None
        data: object = pages[0] if len(pages) == 1 else {"pages": pages}
        error = last_result.error
        if len(pages) == 100 and not error:
            error = "Pagination stopped after 100 pages"
        return APIResult(
            path,
            200 if pages else last_result.status,
            data,
            error,
            first_result.started,
            last_result.finished,
            timed_out=last_result.timed_out,
        )

    def collect_runai_candidates(
        self,
        client: RunAIClient,
        filename: str,
        candidates: Sequence[str],
        *,
        paginated: bool = False,
    ) -> object | None:
        attempts = []
        selected: APIResult | None = None
        for path in candidates:
            result = self.fetch_runai_pages(client, path, paginated=paginated)
            attempts.append(
                {
                    "path": path,
                    "status": result.status,
                    "error": result.error,
                    "started_utc": result.started,
                    "finished_utc": result.finished,
                    "timed_out": result.timed_out,
                }
            )
            selected = result
            if result.status == 200 and result.data is not None:
                break
            if result.status not in {404, 405}:
                break

        assert selected is not None
        document = {
            "source_url": self.runai_config.base_url if self.runai_config else "",
            "selected_path": (
                selected.path
                if selected.status == 200 and selected.data is not None
                else None
            ),
            "attempts": attempts,
            "complete": selected.status == 200 and selected.data is not None and not selected.error,
            "data": sanitize_runai_data(selected.data),
        }
        relative = Path("runai") / filename
        write_text(
            self.root / relative,
            json.dumps(document, indent=2, sort_keys=True) + "\n",
        )
        self.results.append(
            (
                str(relative),
                (0 if not selected.error else 1)
                if selected.status == 200 and selected.data is not None else selected.status,
                selected.timed_out,
            )
        )
        return selected.data if selected.status == 200 else None

    def collect_runai(self) -> None:
        self.progress("[3/9] Collecting credential-redacted Run:AI API state")
        if self.runai_config is None:
            write_text(
                self.root / "runai" / "RUNAI_COLLECTION_SKIPPED.txt",
                "Run:AI API collection was not requested.\n"
                f"Prompt status: {self.runai_prompt_status}\n",
            )
            return

        client = RunAIClient(self.runai_config)
        authentication = client.authenticate()
        self.runai_config.client_secret = ""
        client.client_secret = ""
        auth_document = {
            "source_url": self.runai_config.base_url,
            "auth_mode": self.runai_config.auth_mode,
            "status": "success" if authentication.status == 200 and client.token else "failed",
            "http_status": authentication.status,
            "error": authentication.error,
            "started_utc": authentication.started,
            "finished_utc": authentication.finished,
            "access_token_stored": False,
        }
        write_text(
            self.root / "runai" / "authentication.json",
            json.dumps(auth_document, indent=2, sort_keys=True) + "\n",
        )
        self.results.append(
            (
                "runai/authentication.json",
                0 if auth_document["status"] == "success" else authentication.status,
                authentication.timed_out,
            )
        )
        if not client.token:
            return

        endpoints = (
            ("clusters.json", ("/api/v1/clusters",), False),
            ("departments.json", ("/api/v1/org-unit/departments",), True),
            ("projects.json", ("/api/v1/org-unit/projects",), True),
            ("node-pools.json", ("/api/v1/node-pools",), True),
            (
                "department-node-pool-resources.json",
                ("/api/v1/org-unit/departments/node-pool-resources",),
                True,
            ),
            (
                "project-node-pool-resources.json",
                ("/api/v1/org-unit/projects/node-pool-resources",),
                True,
            ),
            ("policies.json", ("/api/v2/policy",), False),
            (
                "roles.json",
                ("/api/v2/authorization/roles", "/api/v1/authorization/roles"),
                False,
            ),
            (
                "workload-templates.json",
                ("/api/v1/workload-templates", "/api/v1/workloads-templates"),
                True,
            ),
            ("credentials.json", ("/api/v1/asset/credentials",), False),
            ("compute-assets.json", ("/api/v1/asset/compute",), False),
            ("datasource-assets.json", ("/api/v1/asset/datasource",), False),
            ("environment-assets.json", ("/api/v1/asset/environment",), False),
            (
                "workload-template-assets.json",
                ("/api/v1/asset/workload-template",),
                False,
            ),
            (
                "access-rules.json",
                ("/api/v1/authorization/access-rules",),
                True,
            ),
            ("workload-settings.json", ("/api/v2/workloads/settings",), False),
        )
        for filename, candidates, paginated in endpoints:
            self.collect_runai_candidates(
                client, filename, candidates, paginated=paginated
            )

        workloads = self.collect_runai_candidates(
            client, "active-workloads.json", ("/api/v1/workloads",), paginated=True
        )
        for workload_id, workload_name in extract_runai_inference_workloads(workloads):
            encoded = urllib.parse.quote(workload_id, safe="")
            stem = safe_name(f"{workload_name}-{workload_id}")
            self.collect_runai_candidates(
                client,
                f"inference-workloads/{stem}.json",
                (f"/api/v1/workloads/{encoded}",),
            )
            self.collect_runai_candidates(
                client,
                f"inference-workloads/{stem}-endpoints.json",
                (f"/api/v1/workloads/{encoded}/endpoints",),
            )

        idps = self.collect_runai_candidates(
            client, "identity-providers.json", ("/api/v1/idps",)
        )
        for alias in extract_runai_idp_aliases(idps):
            encoded = urllib.parse.quote(alias, safe="")
            self.collect_runai_candidates(
                client,
                f"identity-provider-details/{safe_name(alias)}.json",
                (f"/api/v1/idps/{encoded}",),
            )
            self.collect_runai_candidates(
                client,
                f"identity-provider-details/{safe_name(alias)}-mappers.json",
                (f"/api/v1/idps/{encoded}/mappers",),
            )

        write_text(
            self.root / "runai" / "README.txt",
            "Run:AI API responses are recursively redacted before storage.\n"
            "Credential and token values are intentionally omitted.\n"
            "Clusters include stable identifiers; departments/projects include quota data.\n"
            "Active workloads provide current inference configuration when present.\n"
            "HTTP 404/405 results identify endpoints unavailable in this Run:AI version.\n",
        )
        client.token = ""

    def collect_runai_backup(self) -> None:
        self.progress("Collecting private Run:ai restore backups (unredacted)")
        contexts = getattr(self.args, "runai_backup_context", None)
        if contexts:
            targets = [("context-" + context, context, None)
                       for context in unique_preserving_order(contexts)]
        elif getattr(self.args, "runai_backup_only", False):
            targets = [("current-context", None, None)]
        else:
            targets = [(cluster, None, cluster) for cluster in self.kubernetes_clusters]
        if not targets:
            self.backup_failed = True
            self.progress("No Kubernetes targets available for Run:ai backup")
        database_backups = 0
        runai_targets = 0
        for label, context, cluster in targets:
            backup = RunAIBackup(self, label, context=context, cluster=cluster)
            try:
                backup.run()
                database_backups += backup.report["status"] == "logical-backup-complete"
                runai_targets += backup.report["status"] != "skipped-no-runai"
            except Exception as exc:
                self.backup_failed = True
                # Never echo raw kubectl/Helm/SQL diagnostics into discovery output.
                backup.fail(str(exc))
                self.progress(f"Run:ai backup failed for {label}; private details: {backup.root}")
            self.runai_backups.append({"target": label, "status": backup.report["status"],
                                       "archive": str(backup.archive) if backup.archive.exists() else None})
        if (getattr(self.args, "runai_backup_only", False) or runai_targets) and not database_backups:
            self.backup_failed = True
            self.progress("No control-plane database backup produced; include its kube context")

    def select_hosts(self) -> tuple[list[str], list[str], list[str]]:
        dgx: set[str] = set()
        management: set[str] = set(self.control_plane_nodes)

        dgx_tokens = ("dgx", "b200", "b300", "gb200", "gb300", "h100", "h200", "a100", "gpu")
        management_tokens = (
            "head",
            "master",
            "k8s",
            "kube",
            "control",
            "admin",
            "slogin",
            "login",
            "management",
            "mgmt",
        )
        for device in self.devices:
            text = device.search_text
            if is_switch_or_infrastructure(device):
                continue
            if any(token in text for token in dgx_tokens):
                dgx.add(device.hostname)
            elif any(token in text for token in management_tokens):
                management.add(device.hostname)
            elif any(kind in device.device_type.lower() for kind in ("computenode", "physicalnode", "headnode")):
                management.add(device.hostname)
        management.update(self.kubernetes_nodes - dgx)

        local_name = socket.getfqdn() or socket.gethostname()
        if local_name:
            management.add(local_name)
        control_plane = dedupe_host_aliases(self.control_plane_nodes)
        return (
            dedupe_host_aliases(dgx),
            dedupe_host_aliases(management),
            control_plane,
        )

    def remote_result(self, host: str, script: str) -> CommandResult:
        command = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "LogLevel=ERROR",
            host,
            "/bin/bash",
            "-s",
        ]
        return self.execute(command, input_text=script, timeout=self.ssh_timeout)

    def collect_remote_group(
        self, hosts: Iterable[str], subdir: str, suffix: str, script: str
    ) -> None:
        unique_hosts = sorted({host for host in hosts if host})
        if not unique_hosts:
            write_text(
                self.root / subdir / f"NO_HOSTS_DISCOVERED-{suffix}.txt",
                "No matching hosts were discovered automatically.\n",
            )
            return
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {
                pool.submit(self.remote_result, host, script): host
                for host in unique_hosts
            }
            for future in concurrent.futures.as_completed(futures):
                host = futures[future]
                try:
                    result = future.result()
                except Exception as exc:  # defensive containment for one host
                    result = CommandResult(
                        f"ssh {host}", 125, "", f"Collector exception: {exc}\n",
                        now_utc(), now_utc()
                    )
                self.record(
                    f"{subdir}/{safe_name(host)}-{suffix}.txt",
                    result,
                )

    def collect_hosts(self) -> tuple[list[str], list[str]]:
        self.progress("[4/9] Collecting management, control-plane, and DGX host state")
        dgx_hosts, management_hosts, control_plane_hosts = self.select_hosts()
        selections = {
            "dgx_hosts": dgx_hosts,
            "management_hosts": management_hosts,
            "control_plane_hosts": control_plane_hosts,
            "detailed_dgx_hosts": dgx_hosts[:2],
        }
        write_text(
            self.root / "collector" / "selected-hosts.json",
            json.dumps(selections, indent=2),
        )
        if self.skip_remote:
            write_text(
                self.root / "hosts" / "REMOTE_COLLECTION_SKIPPED.txt",
                "Remote collection was disabled with --skip-remote.\n",
            )
            return dgx_hosts, control_plane_hosts

        self.collect_remote_group(
            management_hosts,
            "hosts",
            "platform-baseline",
            MANAGEMENT_BASELINE_SCRIPT,
        )
        self.collect_remote_group(
            control_plane_hosts,
            "hosts",
            "control-plane-baseline",
            CONTROL_PLANE_BASELINE_SCRIPT,
        )
        self.collect_remote_group(dgx_hosts, "dgx", "compact", DGX_COMPACT_SCRIPT)
        self.collect_remote_group(
            dgx_hosts[:2], "dgx", "detailed-network-baseline", DGX_DETAILED_SCRIPT
        )
        return dgx_hosts, control_plane_hosts

    def collect_storage(self, dgx_hosts: list[str], control_plane_hosts: list[str]) -> None:
        self.progress("[5/9] Collecting storage and identity client state")
        if self.skip_remote:
            return
        targets = dgx_hosts[:2] + control_plane_hosts[:1]
        self.collect_remote_group(targets, "storage", "storage-client", STORAGE_SCRIPT)

    def collect_airgap(self) -> None:
        self.progress("[6/9] Collecting air-gap repository and software-image state")
        self.collect_shell("airgap/head-node-repositories.txt", AIRGAP_HEAD_SCRIPT)

        image_roots = []
        base = Path("/cm/images")
        if base.is_dir():
            image_roots = sorted(path for path in base.iterdir() if path.is_dir())
        for image_root in image_roots:
            script = software_image_repository_script(image_root)
            self.collect_shell(
                f"airgap/softwareimage-{safe_name(image_root.name)}-repositories.txt",
                script,
            )

    def collect_dns_tls(self) -> None:
        self.progress("[7/9] Collecting discovered DNS and TLS endpoint state")
        names = sorted(
            name for name in self.endpoint_names
            if name and "*" not in name and is_probable_dns_name(name)
        )
        write_text(
            self.root / "dns-tls" / "discovered-endpoints.txt",
            "\n".join(names) + ("\n" if names else ""),
        )
        for name in names:
            dns_script = (
                f"getent ahosts {shlex.quote(name)}; "
                "if command -v dig >/dev/null 2>&1; then "
                "for record_type in A AAAA CNAME; do "
                f"dig +noall +answer {shlex.quote(name)} \"$record_type\"; "
                "done; fi"
            )
            self.collect_shell(
                f"dns-tls/{safe_name(name)}-dns.txt",
                dns_script,
            )
            tls_script = (
                f"timeout 15 openssl s_client -connect {shlex.quote(name + ':443')} "
                f"-servername {shlex.quote(name)} -showcerts </dev/null 2>/dev/null | "
                "openssl x509 -noout -subject -issuer -serial -dates "
                "-fingerprint -sha256"
            )
            self.collect_shell(
                f"dns-tls/{safe_name(name)}-certificate.txt",
                tls_script,
            )

    def scan_security(self) -> None:
        self.progress("[8/9] Scanning collected text for material requiring review")
        high_confidence = re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
            r"authorization:\s*bearer\s+\S+",
            re.IGNORECASE,
        )
        yaml_assignment = re.compile(
            r"^\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*[:=]\s*(.+)$"
        )
        json_assignment = re.compile(r'^\s*"([^"]+)":\s*(.+?)(?:,\s*)?$')
        critical = []
        review = []
        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or path.suffix in {".gz", ".zip", ".tgz", ".py"}:
                continue
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for number, line in enumerate(lines, 1):
                location = f"{path.relative_to(self.root)}:{number}"
                if high_confidence.search(line):
                    critical.append(location)
                    continue
                match = json_assignment.match(line) or yaml_assignment.match(line)
                if match and sensitive_key(match.group(1)):
                    value = match.group(2).strip().strip('"\'')
                    if value not in {
                        "<REDACTED>", "null", "~", "{}", "[]", "{", "["
                    }:
                        review.append(location)

        report = [
            "Review this archive through the approved customer security process before transfer.",
            "This discovery archive omits Kubernetes Secret contents and password databases.",
            "Separate private Run:ai backup archives intentionally retain Secrets and database data.",
            "",
            f"High-confidence secret markers: {len(critical)}",
        ]
        report.extend(f"  {item}" for item in critical)
        report.append("")
        report.append(f"Possible secret-valued keys requiring review: {len(review)}")
        report.extend(f"  {item}" for item in review)
        report.append("")
        write_text(self.root / "SECURITY_REVIEW.txt", "\n".join(report))
        self.security_findings = critical

    def finalize(self) -> None:
        self.progress("[9/9] Writing manifest and creating archive")
        summary = {
            "collector_version": VERSION,
            "finished_utc": now_utc(),
            "runai_backups": self.runai_backups,
            "runai_backup_failed": self.backup_failed,
            "commands_recorded": len(self.results),
            "nonzero_commands": sum(1 for _, rc, _ in self.results if rc != 0),
            "timed_out_commands": sum(1 for _, _, timed_out in self.results if timed_out),
            "kubernetes_clusters": self.kubernetes_clusters,
            "software_images": self.software_images,
            "categories": self.categories,
            "device_count": len(self.devices),
            "kubernetes_node_count": len(self.kubernetes_nodes),
            "discovered_endpoints": sorted(self.endpoint_names),
            "high_confidence_security_findings": len(self.security_findings),
            "runai_api_collection": self.runai_prompt_status,
        }
        write_text(
            self.root / "collector" / "collection-summary.json",
            json.dumps(summary, indent=2),
        )

        manifest_path = self.root / "SHA256SUMS"
        lines = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and path != manifest_path:
                lines.append(f"{sha256_file(path)}  {path.relative_to(self.root)}")
        write_text(manifest_path, "\n".join(lines) + "\n")

        if self.security_findings:
            raise RuntimeError(
                "High-confidence secret material was detected. No archive was "
                "created. Review SECURITY_REVIEW.txt in the partial output directory."
            )

        with tarfile.open(self.archive, "w:gz") as archive:
            archive.add(self.root, arcname=self.root.name)
        digest = sha256_file(self.archive)
        write_text(self.digest_file, f"{digest}  {self.archive.name}\n")

        self.progress("")
        self.progress("Collection complete.")
        self.progress(f"Archive: {self.archive}")
        self.progress(f"SHA-256: {self.digest_file}")
        self.progress(f"Commands with nonzero return codes: {summary['nonzero_commands']}")
        self.progress("Review SECURITY_REVIEW.txt before transferring the archive.")

        if not self.keep_directory:
            shutil.rmtree(self.root)

    def run(self) -> None:
        if getattr(self.args, "runai_backup_only", False):
            self.collect_runai_backup()
            if self.backup_failed:
                raise RuntimeError("Run:ai backup failed; see the private backup directory")
            return
        self.prepare()
        self.collect_bcm()
        self.collect_kubernetes()
        self.collect_runai()
        if not getattr(self.args, "skip_runai_backup", False):
            self.collect_runai_backup()
        dgx_hosts, control_plane_hosts = self.collect_hosts()
        self.collect_storage(dgx_hosts, control_plane_hosts)
        self.collect_airgap()
        self.collect_dns_tls()
        self.scan_security()
        self.finalize()
        if self.backup_failed:
            raise RuntimeError("Discovery completed, but Run:ai backup failed")


# This script runs inside the database container. Passwords never enter argv.
RUNAI_POSTGRES_AUTH = r"""
set -eu
if [ "${1:-}" = stdin-password ]; then
    IFS= read -r PGPASSWORD
elif [ -n "${POSTGRESQL_POSTGRES_PASSWORD:-}" ]; then
    PGPASSWORD=$POSTGRESQL_POSTGRES_PASSWORD
elif [ -n "${POSTGRES_POSTGRES_PASSWORD:-}" ]; then
    PGPASSWORD=$POSTGRES_POSTGRES_PASSWORD
elif [ -n "${POSTGRESQL_POSTGRES_PASSWORD_FILE:-}" ]; then
    PGPASSWORD=$(cat "$POSTGRESQL_POSTGRES_PASSWORD_FILE")
elif [ -n "${POSTGRESQL_PASSWORD_FILE:-}" ]; then
    PGPASSWORD=$(cat "$POSTGRESQL_PASSWORD_FILE")
elif [ -n "${POSTGRES_PASSWORD_FILE:-}" ]; then
    PGPASSWORD=$(cat "$POSTGRES_PASSWORD_FILE")
elif [ -n "${POSTGRES_PASSWORD:-}" ]; then
    PGPASSWORD=$POSTGRES_PASSWORD
elif [ -n "${POSTGRESQL_PASSWORD:-}" ]; then
    PGPASSWORD=$POSTGRESQL_PASSWORD
fi
export PGPASSWORD
"""


def runai_backup_profile(version: str) -> dict:
    match = re.fullmatch(r"v?(\d+)\.(\d+)(?:\.\d+)?(?:[-+].*)?", version)
    if not match or (int(match[1]), int(match[2])) < (2, 19):
        raise ValueError("Cannot select a backup profile: unknown or pre-2.19 version")
    release = (int(match[1]), int(match[2]))
    return {
        "version": version,
        "procedure": "postgres-logical-all-databases-and-helm-runtime-config",
        "documentation_status": "bundled-2.19.144-procedure-verified" if version == "2.19.144"
            else "2.19-lab-validation-required" if release == (2, 19)
            else "documented" if release in {(2, 20), (2, 21), (2, 23)}
            else "capability-detected-lab-validation-required",
        "cluster_helm_values_explicit_in_docs": release >= (2, 23),
        "validation_status": "lab-validated-logical-restore" if version == "2.19.144"
            else "not-lab-validated",
        "validated_patch": "2.19.144" if version == "2.19.144" else None,
        "source": "https://run-ai-docs.nvidia.com/self-hosted/"
            + ("2.19" if release == (2, 19) else "2.23/infrastructure-setup/procedures/cluster-restore"
               if release >= (2, 23) else "2.20/infrastructure-setup/procedures/cluster-restore"),
    }


class RunAIBackup:
    """Private, streaming restore exports kept outside the redacted inventory."""

    def __init__(self, collector: Collector, label: str, *, context=None, cluster=None):
        self.collector = collector
        self.args = collector.args
        self.context = context
        self.cluster = cluster
        self.root = collector.root.parent / (collector.root.name.replace(
            "superpod-discovery-", "runai-backup-", 1) + "--" + safe_name(label))
        self.archive = Path(str(self.root) + ".tar.gz")
        if self.archive.exists():
            raise FileExistsError("Backup archive already exists; wait for a new timestamp")
        self.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.timeout = getattr(self.args, "runai_backup_timeout", 3600)
        self.report = {"status": "in-progress", "started_utc": now_utc(),
                       "target": label, "steps": [],
                       "contains_unredacted_secrets": True,
                       "database_scope": "all databases and global roles (pg_dumpall)",
                       "metrics": "not-included", "physical_postgres_volume": "not-included"}
        write_text(self.root / "backup-manifest.json", json.dumps(self.report, indent=2))

    def command(self, command: Sequence[str]) -> list[str]:
        if self.context and command[0] in {"kubectl", "helm"}:
            command = [command[0], "--context" if command[0] == "kubectl"
                       else "--kube-context", self.context, *command[1:]]
        if self.cluster:
            return ["/bin/bash", "-lc", self.collector.kubernetes_shell(
                self.cluster, shlex.join(command))]
        return list(command)

    def export(self, filename: str, command: Sequence[str], *, input_text=None,
               database=False) -> Path:
        """Stream large dumps to disk; partial/failed files never become backups."""
        path = self.root / filename
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        partial = path.with_name(path.name + ".partial")
        error_path = path.with_name(path.name + ".stderr")
        rc = 127
        timed_out = False
        with partial.open("xb") as output, error_path.open("xb") as error:
            try:
                process = subprocess.Popen(self.command(command), stdout=output, stderr=error,
                                           stdin=subprocess.PIPE if input_text is not None
                                           else subprocess.DEVNULL, start_new_session=True)
                try:
                    process.communicate(None if input_text is None else input_text.encode(),
                                        timeout=self.timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    os.killpg(process.pid, signal.SIGKILL)
                    process.communicate()
                except BaseException:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.communicate()
                    raise
                rc = process.returncode
            except OSError:
                error.write(b"Unable to execute backup tool\n")
        step = {"file": filename, "returncode": rc, "timed_out": timed_out}
        self.report["steps"].append(step)
        if rc != 0 or timed_out or partial.stat().st_size == 0:
            raise RuntimeError("Backup export failed; private stderr retained")
        if database:
            with partial.open("rb") as stream:
                stream.seek(max(0, partial.stat().st_size - 8192))
                if b"PostgreSQL database cluster dump complete" not in stream.read():
                    raise RuntimeError("PostgreSQL dump missing completion marker")
        partial.rename(path)
        path.chmod(0o600)
        return path

    def fail(self, error: str) -> None:
        self.report.update(status="failed", finished_utc=now_utc(), error=error)
        write_text(self.root / "backup-manifest.json", json.dumps(self.report, indent=2))

    def run(self) -> None:
        releases_path = self.export("helm-releases.json", ["helm", "list", "-A", "-o", "json"])
        all_releases = json.loads(releases_path.read_text())
        if not isinstance(all_releases, list):
            raise ValueError("Helm release list was not an array")
        releases = [r for r in all_releases if isinstance(r, dict) and
                    (str(r.get("chart", "")).startswith(("runai-", "run-ai-")) or
                     r.get("name") in {"runai", "runai-cluster", "runai-backend"})]
        if not releases:
            if getattr(self.args, "runai_backup_only", False) or self.context:
                raise RuntimeError("No Run:ai Helm release found in requested target")
            self.report.update(status="skipped-no-runai", finished_utc=now_utc())
            write_text(self.root / "backup-manifest.json", json.dumps(self.report, indent=2))
            self.collector.progress(f"No Run:ai releases in {self.report['target']}; skipped")
            return
        backends = [r for r in releases if str(r.get("chart", "")).startswith("runai-backend-")
                    or r.get("name") == "runai-backend"]
        self.report["releases"] = releases
        for release in releases:
            version = str(release.get("app_version", ""))
            if not version:
                match = re.search(r"-(\d+\.\d+\.\d+(?:[-+].*)?)$", str(release.get("chart", "")))
                version = match[1] if match else ""
            release["backup_profile"] = runai_backup_profile(version)
            name, ns = str(release["name"]), str(release["namespace"])
            base = f"helm/{safe_name(ns)}--{safe_name(name)}"
            for suffix, operation in [("values.yaml", "values"), ("manifest.yaml", "manifest")]:
                self.export(base + "--" + suffix, ["helm", "get", operation, name, "-n", ns])
            self.export(base + "--values-all.yaml", ["helm", "get", "values", name, "-n", ns, "--all"])
            if release not in backends:
                self.export(f"clusters/{safe_name(ns)}--runaiconfig.yaml", ["kubectl", "get",
                            "runaiconfig", "runai", "-n", ns, "-o", "yaml"])
        for ns in sorted({str(r["namespace"]) for r in releases}):
            self.export(f"namespaces/{safe_name(ns)}--restore-resources.json", ["kubectl", "get",
                        "configmap,secret,serviceaccount,role,rolebinding,service,ingress,pvc",
                        "-n", ns, "-o", "json"])
        if not backends:
            self.report["database_scope"] = "not-included; cluster-only target"
            self.finish("cluster-configuration-only")
            return
        if len(backends) != 1:
            raise RuntimeError("A single self-hosted control plane is required for a full backup")
        ns = str(backends[0]["namespace"])
        pods_path = self.export("control-plane-pods.json", ["kubectl", "get", "pods", "-n", ns, "-o", "json"])
        pods = json.loads(pods_path.read_text())["items"]
        self.export("control-plane-pvcs.json", ["kubectl", "get", "pvc", "-n", ns, "-o", "json"])
        password_env = getattr(self.args, "runai_pg_password_env", None)
        password = os.environ.get(password_env, "") if password_env else None
        if password_env and not password:
            raise ValueError("Selected password environment variable is missing or empty")
        if password and ("\n" in password or "\r" in password):
            raise ValueError("Password stdin transport requires a single line")
        if getattr(self.args, "runai_external_postgres", False):
            self.report["postgres"] = {"mode": "external", "connection": "local PG environment/pgpass"}
            # libpq honors PGHOST/PGPORT/PGUSER/PGPASSFILE; never serialize these values.
            self.export("postgres/all-databases.sql", ["pg_dumpall", "--no-password"], database=True)
        else:
            candidates = []
            for pod in pods:
                if pod.get("status", {}).get("phase") != "Running":
                    continue
                for container in pod.get("spec", {}).get("containers", []):
                    image = str(container.get("image", ""))
                    selected_pod = getattr(self.args, "runai_pg_pod", None)
                    if (selected_pod == pod["metadata"]["name"] or
                            re.search(r"(?:^|/)(?:postgres|postgresql)(?=[:@/-]|$)", image)):
                        candidates.append((pod["metadata"]["name"], container["name"]))
            override = getattr(self.args, "runai_pg_pod", None)
            if override:
                candidates = [c for c in candidates if c[0] == override]
            container_override = getattr(self.args, "runai_pg_container", None)
            if container_override:
                candidates = [c for c in candidates if c[1] == container_override]
            if len(candidates) != 1:
                raise RuntimeError("PostgreSQL pod/container is absent or ambiguous; select explicitly or use external mode")
            pod, container = candidates[0]
            self.report["postgres"] = {"mode": "in-cluster", "pod": pod, "container": container}
            script = RUNAI_POSTGRES_AUTH + "\nexec pg_dumpall --no-password -U " + shlex.quote(
                getattr(self.args, "runai_pg_user", "postgres"))
            command = ["kubectl", "exec", "-n", ns, pod, "-c", container]
            if password is not None:
                command.append("-i")
            command += ["--", "sh", "-c", script, "backup",
                        "stdin-password" if password is not None else "pod-environment"]
            self.export("postgres/all-databases.sql", command,
                        input_text=None if password is None else password + "\n", database=True)
        metrics = getattr(self.args, "runai_metrics_backup", None)
        if metrics:
            # Accept an existing customer-created consistent snapshot export, never tar a live PV.
            with tarfile.open(metrics, "r:gz") as archive:
                if archive.next() is None:
                    raise ValueError("Metrics archive is empty")
            shutil.copyfile(metrics, self.root / "metrics-volume-backup.tar.gz")
            self.report["metrics"] = "operator-supplied-archive; consistency-and-coverage-require-restore-test"
        self.finish("logical-backup-complete")

    def finish(self, status: str) -> None:
        self.report.update(status=status, finished_utc=now_utc(),
                           full_disaster_recovery_verified=False)
        write_text(self.root / "backup-manifest.json", json.dumps(self.report, indent=2))
        write_text(self.root / "RESTORE.txt", RUNAI_RESTORE_NOTES)
        files = [p for p in sorted(self.root.rglob("*")) if p.is_file()]
        write_text(self.root / "SHA256SUMS", "".join(
            f"{sha256_file(p)}  {p.relative_to(self.root)}\n" for p in files))
        partial = Path(str(self.archive) + ".partial")
        with os.fdopen(os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
            with tarfile.open(fileobj=stream, mode="w:gz") as archive:
                archive.add(self.root, arcname=self.root.name)
        partial.rename(self.archive)
        self.archive.chmod(0o600)
        write_text(Path(str(self.archive) + ".sha256"),
                   f"{sha256_file(self.archive)}  {self.archive.name}\n")
        self.collector.progress(f"Private Run:ai backup ({status}): {self.archive}")
        if not self.collector.keep_directory:
            shutil.rmtree(self.root)


RUNAI_RESTORE_NOTES = """PRIVATE: This archive includes raw secrets, database data and role password hashes.
Keep it separate from redacted discovery; restrict access and encrypt for transfer/storage.
Verify the external SHA-256 and extracted SHA256SUMS before any restore.

This is a logical PostgreSQL cluster backup plus Helm values/manifests, namespace
configuration/secrets and full RunaiConfig objects. It does not back up host disks,
workload data, external object stores or PV bytes. Metrics are omitted unless an
operator supplies a consistent metrics-volume-backup.tar.gz. PVC specifications
are inventory, not volume backups. Do not claim full disaster recovery from this
archive alone. Custom namespace/rolebindings outside release namespaces must be
saved separately when automatic project namespace creation is disabled.

Validate restore in an isolated lab using the exact recorded Run:ai/chart and
PostgreSQL versions. Provision storage and reinstall the same control plane with
the saved Helm user overrides; use effective values as a reference. Reconcile
Secrets and site-specific dependencies securely before starting services.
Stop application writers during database restore. The all-databases.sql plain SQL
includes global roles and every accessible database, unlike a backend-only dump.
Use psql with ON_ERROR_STOP against a clean compatible server as an administrative
user, resolving bootstrap role/database conflicts deliberately. Do not blindly
apply namespace exports or Helm manifests: remove Kubernetes server-generated
metadata and reconcile installation-generated resources. The saved RunaiConfig
is a complete Kubernetes object (not a bare spec); clean metadata before apply.
Restore metrics volumes using the customer storage backup tool, reinstall/connect
clusters with their Helm values, reconcile namespace/rolebindings, then verify
projects, quotas, identities, workloads and metrics. No restore is performed by
the collector. Dumps are consistent per database, not atomic across databases;
coordinate a quiet window when cross-database consistency is required.
"""


MANAGEMENT_BASELINE_SCRIPT = r"""
set +e
date --iso-8601=seconds
hostname -f
hostnamectl
cat /etc/os-release
uname -a
dmidecode -s system-manufacturer
dmidecode -s system-product-name
dmidecode -s system-serial-number
dmidecode -s bios-version
lscpu
free -h
lsblk -e7 -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS,MODEL,SERIAL
findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS
lspci -nn
ip -br link
ip -br address
ip -d link
ip route show table all
ip rule
for f in /proc/net/bonding/*; do test -e "$f" && cat "$f"; done
resolvectl status 2>&1 || cat /etc/resolv.conf
timedatectl
cmha status 2>&1 || true
"""


CONTROL_PLANE_BASELINE_SCRIPT = r"""
set +e
date --iso-8601=seconds
hostname -f
cat /etc/os-release
uname -a
dpkg-query -W 2>&1 | grep -Ei 'kube(let|adm|ctl)|kubernetes|containerd|docker|cri-o|etcd|cm-etcd'
systemctl list-unit-files --state=enabled --no-pager | grep -Ei 'kube|containerd|docker|cri-o|etcd'
systemctl list-units --type=service --state=running --no-pager | grep -Ei 'kube|containerd|docker|cri-o|etcd'
kubeadm certs check-expiration 2>&1
crictl ps -a 2>&1
ss -lntup
ip -br address
ip route
findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS
"""


DGX_COMPACT_SCRIPT = r"""
set +e
hostname -f
cat /etc/dgx-release
uname -r
nvidia-smi --query-gpu=driver_version --format=csv,noheader | sort -u
dpkg-query -W -f='${binary:Package} ${Version}\n' 'doca-*' 2>&1 | sort
ofed_info -s 2>&1
dpkg-query -W -f='${binary:Package} ${Version}\n' 'nvidia-container-toolkit*' 2>&1
mlxfwmanager --query 2>&1
ip -br link
systemctl is-enabled spcx-dynamic-ports-rename.service spcx_ovs_flows.service spectrum-x.service spcx-post-boot.service 2>&1
systemctl is-active spcx-dynamic-ports-rename.service spcx_ovs_flows.service spectrum-x.service spcx-post-boot.service 2>&1
"""


DGX_DETAILED_SCRIPT = r"""
set +e
date --iso-8601=seconds
hostname -f
lspci -Dnn
nvidia-smi topo -m
ip -br link
ip -br address
ip -d link
ip route show table all
ip rule
rdma link
rdma dev
ibdev2netdev
ibstat
devlink dev show
devlink port show
mst status -v
mlxfwmanager --query
for iface in $(find /sys/class/net -mindepth 1 -maxdepth 1 -printf '%f\n' | sort); do
  ethtool -i "$iface" 2>&1
  ethtool -k "$iface" 2>&1
done
for iface in $(ibdev2netdev 2>/dev/null | awk '{print $5}' | sort -u); do
  mlnx_qos -i "$iface" 2>&1
  dcb -j app show dev "$iface" 2>&1
  dcb -j pfc show dev "$iface" 2>&1
  dcb -j ets show dev "$iface" 2>&1
done
systemctl status --no-pager spcx-dynamic-ports-rename.service spcx_ovs_flows.service spectrum-x.service spcx-post-boot.service 2>&1
systemctl cat spcx-dynamic-ports-rename.service spcx_ovs_flows.service spectrum-x.service spcx-post-boot.service 2>&1
systemctl show -p Id,LoadState,ActiveState,SubState,UnitFileState,WantedBy,RequiredBy,Requires,Wants,After,Before,ExecStart spcx-dynamic-ports-rename.service spcx_ovs_flows.service spectrum-x.service spcx-post-boot.service 2>&1
systemctl list-dependencies spcx-post-boot.service 2>&1
"""


STORAGE_SCRIPT = r"""
set +e
hostname -f
findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS
awk 'NF && $1 !~ /^#/ {print}' /etc/fstab
weka version 2>&1
weka status 2>&1
dpkg-query -W 2>&1 | grep -i weka
ibdev2netdev
rdma link
ip -br link
getent passwd | awk -F: '$6 ~ /^\/home\// {print $1 ":" $3 ":" $4 ":" $6 ":" $7}'
getent group
"""


AIRGAP_HEAD_SCRIPT = r"""
set +e
grep -RhsE '^[[:space:]]*(deb|deb-src|Types:|URIs:|Suites:|Components:|Architectures:|Signed-By:)' /etc/apt/sources.list /etc/apt/sources.list.d 2>&1
grep -Rhs . /etc/apt/preferences /etc/apt/preferences.d 2>&1
apt-mark showhold
grep -RhsE 'registry|mirror|endpoint|server|config_path' /etc/containerd /etc/docker 2>/dev/null | grep -vEi 'password|token|secret|auth' | head -n 2000
"""


def software_image_repository_script(image_root: Path) -> str:
    quoted = shlex.quote(str(image_root))
    return textwrap.dedent(
        f"""
        set +e
        root={quoted}
        cat "$root/etc/os-release"
        grep -RhsE '^[[:space:]]*(deb|deb-src|Types:|URIs:|Suites:|Components:|Architectures:|Signed-By:)' "$root/etc/apt/sources.list" "$root/etc/apt/sources.list.d" 2>&1
        grep -Rhs . "$root/etc/apt/preferences" "$root/etc/apt/preferences.d" 2>&1
        chroot "$root" apt-mark showhold 2>&1
        """
    )


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def is_switch_or_infrastructure(device: Device) -> bool:
    kind = device.device_type.lower()
    if any(token in kind for token in ("computenode", "physicalnode", "headnode")):
        return False
    if any(token in kind for token in ("switch", "pdu", "rack", "chassis")):
        return True
    return bool(re.search(
        r"(?:^|[-_.])(?:switch|spine|leaf|tor|oob|pdu)(?:[-_.0-9]|$)",
        device.hostname.lower(),
    ))


def parse_platform_crds(text: str) -> list[tuple[str, str]]:
    """Select installed platform CRDs; omit potentially huge policy-report APIs."""
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(document, dict):
        return []
    groups = {
        "mellanox.com", "sriovnetwork.openshift.io", "k8s.cni.cncf.io",
        "whereabouts.cni.cncf.io", "nfd.k8s-sigs.io", "kyverno.io",
        "crd.projectcalico.org", "projectcalico.org", "operator.tigera.io",
        "metallb.io", "nvidia.com",
    }
    resources = set()
    for item in document.get("items", []):
        if not isinstance(item, dict):
            continue
        spec = item.get("spec", {})
        group = str(spec.get("group", ""))
        name = str(item.get("metadata", {}).get("name", ""))
        scope = spec.get("scope", "")
        if group not in groups and not group.endswith(".nvidia.com"):
            continue
        if "report" in name.split(".", 1)[0]:
            continue
        if name and scope in {"Namespaced", "Cluster"}:
            resources.add((name, scope))
    return sorted(resources)


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def decode_timeout_stream(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def safe_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    return cleaned.strip("._-") or "unnamed"


def cmsh_quote(value: str) -> str:
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def parse_cmsh_name_list(output: str) -> list[str]:
    names = []
    skip_first_words = {
        "name", "hostname", "category", "softwareimage", "software", "type",
        "cluster", "kubernetes", "revision", "total", "configurationoverlay",
    }
    for raw in output.splitlines():
        line = raw.strip()
        lowered = line.lower()
        if not line or lowered.startswith(
            ("---", "===", "[", "warning:", "error", "command not found", "unable ",
             "usage:", "valid types:")
        ):
            continue
        first = line.split()[0].strip()
        if first.lower().rstrip(":") in skip_first_words:
            continue
        if set(first) <= {"-", "="} or first.startswith("("):
            continue
        if re.match(r"^[A-Za-z0-9_.-]+$", first):
            names.append(first)
    return unique_preserving_order(names)


def parse_device_table(output: str) -> list[Device]:
    devices = []
    for raw in output.splitlines():
        line = raw.strip()
        if not line or line.startswith(("---", "===", "[", "Warning:")):
            continue
        parts = (
            [part.strip() for part in raw.split("|")]
            if "|" in raw
            else re.split(r"\s+", line, maxsplit=3)
        )
        if not parts or parts[0].lower() in {"hostname", "name"}:
            continue
        if not re.match(r"^[A-Za-z0-9_.-]+$", parts[0]):
            continue
        values = parts + [""] * (4 - len(parts))
        software_image = re.sub(r"\s+\(category:[^)]+\)$", "", values[2])
        devices.append(Device(values[0], values[1], software_image, values[3]))
    return devices


def parse_default_device_table(output: str) -> list[Device]:
    """Parse BCM's default device table when custom field formatting fails."""
    devices = []
    for raw in output.splitlines():
        fields = raw.split()
        if len(fields) < 2:
            continue
        device_type, hostname = fields[:2]
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", device_type):
            continue
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", hostname):
            continue
        devices.append(Device(hostname=hostname, device_type=device_type))
    return devices


def parse_kubernetes_node_names(output: str) -> list[str]:
    names = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("NAME"):
            continue
        first = stripped.split()[0]
        if re.match(r"^[A-Za-z0-9_.-]+$", first):
            names.append(first)
    return unique_preserving_order(names)


def parse_kubernetes_control_plane_names(output: str) -> list[str]:
    names = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("NAME"):
            continue
        fields = stripped.split()
        if len(fields) < 3:
            continue
        roles = fields[2].lower().split(",")
        if any(role in {"control-plane", "master"} for role in roles):
            names.append(fields[0])
    return unique_preserving_order(names)


def parse_helm_releases(output: str) -> list[tuple[str, str]]:
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []
    releases = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and item.get("name") and item.get("namespace"):
                releases.append((str(item["name"]), str(item["namespace"])))
    return sorted(set(releases))


def extract_endpoint_names(output: str) -> set[str]:
    names = set()
    for match in re.finditer(r"https?://([^/:\s]+)", output):
        names.add(match.group(1).strip(".[]"))
    return names


def extract_ingress_hosts(output: str) -> set[str]:
    names = set()
    for match in re.finditer(r"^\s*-?\s*host:\s*['\"]?([^'\"\s]+)", output, re.MULTILINE):
        names.add(match.group(1).strip())
    return names


def extract_knative_domains(output: str) -> set[str]:
    names = set()
    for line in output.splitlines():
        match = re.match(r"^\s{2,}([^:#\s]+\.[^:#\s]+):\s*['\"]?['\"]?\s*$", line)
        if match:
            names.add(match.group(1))
    return names


def is_probable_dns_name(value: str) -> bool:
    return bool(
        len(value) <= 253
        and "." in value
        and re.fullmatch(r"[A-Za-z0-9.-]+", value)
        and not re.fullmatch(r"\d+(?:\.\d+){3}", value)
    )


def sensitive_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", key.lower())
    references = {
        "secretname", "existingsecret", "secretref", "secretkeyref",
        "certificatesecret", "tlssecret", "imagepullsecrets",
        "serviceaccounttoken", "automountserviceaccounttoken",
    }
    if normalized in references:
        return False
    sensitive = (
        "password", "passwd", "token", "apikey", "clientsecret", "secret", "privatekey",
        "secretkey", "accesskey", "credential", "ngcapikey", "dockerconfigjson",
    )
    if any(normalized == item or normalized.endswith(item) for item in sensitive):
        return True
    return normalized.endswith(("placeholder", "value", "literal")) and any(
        item in normalized for item in sensitive
    )


def redact_sensitive_yaml(text: str) -> str:
    output = []
    suppress_indent: int | None = None
    key_pattern = re.compile(r"^(\s*)([^:#][^:]*):(?:\s*(.*))?$")
    assignment_pattern = re.compile(
        r"^(\s*)([A-Za-z_][A-Za-z0-9_-]*)(\s*=\s*)(.*)$"
    )
    in_private_key = False

    for line in text.splitlines():
        if re.search(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", line):
            in_private_key = True
            output.append("<REDACTED PRIVATE KEY>")
            continue
        if in_private_key:
            if "-----END" in line and "PRIVATE KEY-----" in line:
                in_private_key = False
            continue

        indent = len(line) - len(line.lstrip(" "))
        if suppress_indent is not None:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if indent > suppress_indent:
                continue
            suppress_indent = None

        match = key_pattern.match(line)
        if match and sensitive_key(match.group(2).strip()):
            output.append(f"{match.group(1)}{match.group(2).strip()}: <REDACTED>")
            if not (match.group(3) or "").strip():
                suppress_indent = indent
            continue

        assignment = assignment_pattern.match(line)
        if assignment and sensitive_key(assignment.group(2)):
            output.append(
                f"{assignment.group(1)}{assignment.group(2)}{assignment.group(3)}<REDACTED>"
            )
            continue
        output.append(line)
    return "\n".join(output) + ("\n" if text.endswith("\n") else "")


def redact_cmsh_output(text: str) -> str:
    output = []
    for line in redact_sensitive_yaml(text).splitlines():
        match = re.match(r"^(\s*([A-Za-z][A-Za-z0-9_.-]*)\s{2,})(\S.*)$", line)
        if match and sensitive_key(match.group(2)):
            line = f"{match.group(1)}<REDACTED>"
        output.append(line)
    return "\n".join(output) + ("\n" if text.endswith("\n") else "")


def redact_kubernetes_json(text: str, *, keep_status: bool = False) -> str:
    """Remove noisy runtime state and redact literal secret-like values."""
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return redact_sensitive_yaml(text)

    def sanitize(value):
        if isinstance(value, list):
            return [sanitize(item) for item in value]
        if not isinstance(value, dict):
            return value

        result = {}
        env_name = str(value.get("name", ""))
        for key, item in value.items():
            if key == "managedFields" or (key == "status" and not keep_status):
                continue
            if key in {"data", "stringData"} and isinstance(item, dict):
                sanitized_data = {}
                for data_key, data_value in item.items():
                    if sensitive_key(data_key):
                        sanitized_data[data_key] = "<REDACTED>"
                    elif isinstance(data_value, str):
                        try:
                            embedded = json.loads(data_value)
                        except (json.JSONDecodeError, TypeError):
                            sanitized_data[data_key] = redact_sensitive_yaml(data_value)
                        else:
                            sanitized_data[data_key] = json.dumps(
                                sanitize(embedded), indent=2, sort_keys=True
                            )
                    else:
                        sanitized_data[data_key] = sanitize(data_value)
                result[key] = sanitized_data
            elif key == "binaryData":
                result[key] = "<OMITTED>"
            elif key == "value" and sensitive_key(env_name):
                result[key] = "<REDACTED>"
            elif sensitive_key(key) and not isinstance(item, (dict, list)):
                result[key] = "<REDACTED>"
            else:
                result[key] = sanitize(item)
        return result

    return json.dumps(sanitize(document), indent=2, sort_keys=True) + "\n"


def sanitize_runai_data(value):
    """Recursively remove credential material while retaining useful API state."""
    if isinstance(value, list):
        return [sanitize_runai_data(item) for item in value]
    if not isinstance(value, dict):
        if isinstance(value, str) and (
            re.search(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", value)
            or re.match(r"^\s*Bearer\s+\S+", value, re.IGNORECASE)
            or re.search(
                r"(?:^|[\s?&'\"])(?:--?)?(?:password|passwd|token|api[_-]?key|"
                r"client[_-]?secret|private[_-]?key|secret[_-]?key|access[_-]?key)"
                r"\s*[:=]\s*\S+",
                value,
                re.IGNORECASE,
            )
            or re.fullmatch(
                r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", value
            )
        ):
            return "<REDACTED>"
        return value

    result = {}
    env_name = str(value.get("name", ""))
    for key, item in value.items():
        if sensitive_key(str(key)):
            result[key] = "<REDACTED>"
        elif key == "value" and sensitive_key(env_name):
            result[key] = "<REDACTED>"
        else:
            result[key] = sanitize_runai_data(item)
    return result


def runai_next_offset(data: object, offset: int = 0) -> int | None:
    if not isinstance(data, dict):
        return None
    candidate = data.get("next")
    pagination = data.get("pagination")
    if candidate is None and isinstance(pagination, dict):
        candidate = pagination.get("next")
    if isinstance(candidate, int) and not isinstance(candidate, bool):
        return candidate
    if isinstance(candidate, str) and candidate.isdigit():
        return int(candidate)
    # The 2.19 node-pool API honors limit/offset but omits a next pointer.
    nodepools = data.get("nodepools")
    if isinstance(nodepools, list) and len(nodepools) >= RUNAI_API_LIMIT:
        return offset + len(nodepools)
    # In 2.19 access-rule totalRecords is the page count in live responses,
    # despite the schema naming. A full page needs a following request.
    total, count = data.get("totalRecords"), data.get("displayRecords")
    if (isinstance(total, int) and not isinstance(total, bool)
            and isinstance(count, int) and not isinstance(count, bool)
            and count > 0 and (offset + count < total
                or (isinstance(data.get("accessRules"), list)
                    and len(data["accessRules"]) == count
                    and count >= RUNAI_API_LIMIT))):
        return offset + count
    return None


def extract_runai_idp_aliases(data: object) -> list[str]:
    documents = []
    if isinstance(data, list):
        documents = data
    elif isinstance(data, dict):
        for key in ("entries", "idps", "items"):
            if isinstance(data.get(key), list):
                documents = data[key]
                break
        if not documents and isinstance(data.get("pages"), list):
            for page in data["pages"]:
                documents.extend(extract_runai_idp_aliases(page))
            return sorted(set(str(item) for item in documents if item))
    aliases = []
    for item in documents:
        if not isinstance(item, dict):
            continue
        for key in ("alias", "idp", "name"):
            candidate = item.get(key)
            if isinstance(candidate, str) and candidate:
                aliases.append(candidate)
                break
    return sorted(set(aliases))


def extract_runai_inference_workloads(data: object) -> list[tuple[str, str]]:
    documents = []
    if isinstance(data, list):
        documents = data
    elif isinstance(data, dict):
        if isinstance(data.get("workloads"), list):
            documents = data["workloads"]
        elif isinstance(data.get("pages"), list):
            results = []
            for page in data["pages"]:
                results.extend(extract_runai_inference_workloads(page))
            return sorted(set(results))
    results = []
    for item in documents:
        if not isinstance(item, dict):
            continue
        workload_type = str(item.get("type", ""))
        category = str(item.get("category", ""))
        if "inference" not in f"{workload_type} {category}".lower():
            continue
        workload_id = item.get("id")
        if isinstance(workload_id, str) and workload_id:
            name = str(item.get("name") or "inference")
            results.append((workload_id, name))
    return sorted(set(results))


def normalize_runai_url(value: str) -> str:
    candidate = value.strip()
    if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", candidate):
        candidate = f"https://{candidate}"
    parsed = urllib.parse.urlsplit(candidate)
    if parsed.scheme.lower() != "https":
        raise ValueError("Run:AI URL must use HTTPS")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Run:AI URL must contain a hostname and no credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("Run:AI URL must not contain a query string or fragment")
    normalized = urllib.parse.urlunsplit(
        ("https", parsed.netloc, parsed.path.rstrip("/"), "", "")
    )
    return normalized.rstrip("/")


def prompt_runai_config(skip_runai: bool, auth_mode: str = "client-credentials") -> tuple[RunAIConfig | None, str]:
    if skip_runai:
        return None, "skipped-with---skip-runai"
    try:
        answer = input(
            "Would you like to include Run:AI in the discovery collection? [Y/N]: "
        ).strip().lower()
    except EOFError:
        print("No interactive input was available; skipping Run:AI API collection.")
        return None, "skipped-non-interactive"
    while answer not in {"y", "yes", "n", "no"}:
        answer = input("Please enter Y or N: ").strip().lower()
    if answer in {"n", "no"}:
        return None, "declined-at-prompt"

    while True:
        try:
            base_url = normalize_runai_url(input("Run:AI URL: "))
            break
        except ValueError as exc:
            print(f"Invalid Run:AI URL: {exc}")
    client_id = ""
    while not client_id:
        client_id = input("Run:AI Application name: " if auth_mode == "app-token"
                          else "Run:AI client ID: ").strip()
        if not client_id:
            print("Run:AI client ID cannot be empty.")
    client_secret = ""
    while not client_secret:
        client_secret = getpass.getpass("Run:AI client secret (API token): ").strip()
        if not client_secret:
            print("Run:AI client secret cannot be empty.")
    return RunAIConfig(base_url, client_id, client_secret, auth_mode), "enabled"


def summarize_kubernetes_controllers(text: str) -> str:
    """Summarize live controller ownership and effective container images."""
    header = (
        "namespace\tkind\tname\tmanaged_by\thelm_release\thelm_namespace"
        "\tservice_account\timages\n"
    )
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return header + "<parse-error>\n"

    rows = []
    for item in document.get("items", []):
        metadata = item.get("metadata", {})
        labels = metadata.get("labels", {}) or {}
        annotations = metadata.get("annotations", {}) or {}
        pod_spec = item.get("spec", {}).get("template", {}).get("spec", {}) or {}
        images = []
        containers = pod_spec.get("initContainers", []) + pod_spec.get("containers", [])
        for container in containers:
            image = container.get("image")
            if image:
                images.append(str(image))
        fields = (
            metadata.get("namespace", ""),
            item.get("kind", ""),
            metadata.get("name", ""),
            labels.get("app.kubernetes.io/managed-by", ""),
            annotations.get("meta.helm.sh/release-name", ""),
            annotations.get("meta.helm.sh/release-namespace", ""),
            pod_spec.get("serviceAccountName", ""),
            ",".join(images),
        )
        rows.append("\t".join(str(field).replace("\t", " ") for field in fields))
    return header + "\n".join(sorted(rows)) + ("\n" if rows else "")


def extract_controller_configmap_refs(text: str) -> list[tuple[str, str]]:
    """Return ConfigMaps explicitly referenced by controller pod templates."""
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []

    references: set[tuple[str, str]] = set()
    for item in document.get("items", []):
        namespace = str(item.get("metadata", {}).get("namespace", "default"))
        pod_spec = item.get("spec", {}).get("template", {}).get("spec", {}) or {}
        for volume in pod_spec.get("volumes", []):
            name = (volume.get("configMap") or {}).get("name")
            if name:
                references.add((namespace, str(name)))
        containers = pod_spec.get("initContainers", []) + pod_spec.get("containers", [])
        for container in containers:
            for source in container.get("envFrom", []) or []:
                name = (source.get("configMapRef") or {}).get("name")
                if name:
                    references.add((namespace, str(name)))
            for variable in container.get("env", []) or []:
                name = (
                    (variable.get("valueFrom") or {})
                    .get("configMapKeyRef", {})
                    .get("name")
                )
                if name:
                    references.add((namespace, str(name)))
    return sorted(references)


def unique_preserving_order(values: Iterable[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def dedupe_host_aliases(values: Iterable[str]) -> list[str]:
    """Remove short-name/FQDN aliases, preferring the more specific FQDN."""
    selected: dict[str, str] = {}
    for value in sorted({item.strip().rstrip(".") for item in values if item.strip()}):
        key = value.split(".", 1)[0].lower()
        current = selected.get(key)
        if current is None or ("." in value and "." not in current):
            selected[key] = value
    return sorted(selected.values())


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("/tmp"),
        help="Parent directory for output (default: /tmp)",
    )
    parser.add_argument(
        "--max-workers", type=int, default=DEFAULT_WORKERS,
        help=f"Maximum concurrent SSH sessions (default: {DEFAULT_WORKERS})",
    )
    parser.add_argument(
        "--command-timeout", type=int, default=DEFAULT_COMMAND_TIMEOUT,
        help=f"Local command timeout in seconds (default: {DEFAULT_COMMAND_TIMEOUT})",
    )
    parser.add_argument(
        "--ssh-timeout", type=int, default=DEFAULT_SSH_TIMEOUT,
        help=f"Per-host SSH collection timeout in seconds (default: {DEFAULT_SSH_TIMEOUT})",
    )
    parser.add_argument(
        "--skip-remote", action="store_true",
        help="Skip SSH host collection; useful for initial lab validation",
    )
    parser.add_argument(
        "--skip-helm-values", action="store_true",
        help="Skip secret-redacted Helm values collection",
    )
    parser.add_argument(
        "--skip-runai", action="store_true",
        help=(
            "Skip the default interactive Run:AI API discovery prompt and do not "
            "request Run:AI credentials"
        ),
    )
    parser.add_argument(
        "--keep-directory", action="store_true",
        help="Keep the uncompressed collection directory after archiving",
    )
    parser.add_argument("--runai-auth-mode", choices=("client-credentials", "app-token"),
                        default="client-credentials",
                        help="API token flow: use app-token and the Application name for Run:ai 2.19")
    parser.add_argument("--runai-backup-only", action="store_true",
                        help="Only create private Run:ai backup(s); no BCM discovery or API prompt")
    parser.add_argument("--skip-runai-backup", action="store_true",
                        help="Skip the default private Run:ai backup during discovery")
    parser.add_argument("--runai-backup-context", action="append",
                        help="Explicit kube context to back up; repeat for multiple contexts")
    parser.add_argument("--runai-backup-timeout", type=int, default=3600,
                        help="Per-backup-command timeout seconds (default: 3600)")
    parser.add_argument("--runai-pg-pod", help="Select PostgreSQL pod when auto-detection is ambiguous")
    parser.add_argument("--runai-pg-container", help="Select PostgreSQL container")
    parser.add_argument("--runai-pg-user", default="postgres", help="In-pod PostgreSQL administrator")
    parser.add_argument("--runai-pg-password-env",
                        help="Name of local environment variable supplying in-pod DB password over stdin")
    parser.add_argument("--runai-external-postgres", action="store_true",
                        help="Use local pg_dumpall with PG* environment/pgpass for external PostgreSQL")
    parser.add_argument("--runai-metrics-backup", type=Path,
                        help="Include an existing consistent metrics volume tar.gz export")
    parser.add_argument("--version", action="version", version=VERSION)
    return parser.parse_args()


def preflight(args: argparse.Namespace) -> None:
    if args.runai_backup_only and args.skip_runai_backup:
        raise SystemExit("--runai-backup-only conflicts with --skip-runai-backup")
    if args.runai_backup_timeout < 1:
        raise SystemExit("--runai-backup-timeout must be positive")
    if not args.runai_backup_only and os.geteuid() != 0:
        raise SystemExit("Run this collector as root on the primary BCM head node.")
    if args.max_workers < 1:
        raise SystemExit("--max-workers must be at least 1")
    if not args.runai_backup_only and not shutil.which("cmsh"):
        raise SystemExit("cmsh was not found. Run this collector on a BCM head node.")
    if not args.runai_backup_only and not args.skip_remote and not shutil.which("ssh"):
        raise SystemExit("ssh was not found; use --skip-remote only for lab diagnostics.")
    if args.runai_backup_only:
        for tool in ("kubectl", "helm"):
            if not shutil.which(tool):
                raise SystemExit(f"{tool} is required for Run:ai backup")
    if args.runai_external_postgres and args.runai_pg_password_env:
        raise SystemExit("External PostgreSQL uses PG* environment/pgpass, not --runai-pg-password-env")
    if args.runai_external_postgres and not shutil.which("pg_dumpall"):
        raise SystemExit("External PostgreSQL backup requires local pg_dumpall")
    try:
        args.output_root.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise SystemExit(
            f"Cannot create or use output directory {args.output_root}: {exc}"
        ) from exc


def main() -> int:
    args = parse_args()
    preflight(args)
    os.umask(0o077)
    collector = None
    try:
        args.runai_config, args.runai_prompt_status = prompt_runai_config(
            args.skip_runai or args.runai_backup_only, args.runai_auth_mode
        )
        collector = Collector(args)
        collector.run()
    except KeyboardInterrupt:
        print("\nCollection interrupted. Partial output was left in place.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"Collection failed: {exc}", file=sys.stderr)
        if collector is not None and collector.root.exists():
            print(f"Partial output: {collector.root}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
