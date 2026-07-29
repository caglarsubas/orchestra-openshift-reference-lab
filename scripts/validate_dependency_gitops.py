#!/usr/bin/env python3
"""Validate the dependency-plane GitOps floor remains impossible to activate."""

from __future__ import annotations

import re
import sys
from typing import Any, NoReturn

try:
    from scripts.validate_repository import ROOT, load_json
except ModuleNotFoundError:
    from validate_repository import ROOT, load_json


GITOPS_ROOT = ROOT / "gitops" / "dependencies" / "reference-lab"
NAMESPACES = {
    "orchestra-services-gitops",
    "orchestra-cert-manager",
    "orchestra-postgres",
    "orchestra-clickhouse",
    "orchestra-jetstream",
    "orchestra-valkey",
    "orchestra-vault",
    "orchestra-harbor",
    "orchestra-keycloak",
    "orchestra-observability",
    "orchestra-synthetic",
}
DESTINATION_NAMESPACES = NAMESPACES - {"orchestra-services-gitops"}
EXPECTED_RENDERED_COUNTS = {
    "AppProject": 1,
    "Namespace": len(NAMESPACES),
    "NetworkPolicy": len(NAMESPACES),
}
BOOTSTRAP_REPOSITORY = (
    "oci://europe-west1-docker.pkg.dev/"
    "ORCHESTRA_SERVICES_PROJECT_REQUIRED/orchestra-bootstrap/charts"
)
SOURCE_VERIFICATION_DIGEST = (
    "sha256:75539cd9e8b0fce8e556b7d3cd8a7437d2e6f26525e96639085feff431478ed8"
)


def fail(code: str) -> NoReturn:
    raise ValueError(code)


def validate_project(project: dict[str, Any]) -> None:
    if (
        project.get("apiVersion") != "argoproj.io/v1alpha1"
        or project.get("kind") != "AppProject"
    ):
        fail("dependency_gitops_project_identity_invalid")
    metadata = project.get("metadata")
    spec = project.get("spec")
    if not isinstance(metadata, dict) or not isinstance(spec, dict):
        fail("dependency_gitops_project_shape_invalid")
    annotations = metadata.get("annotations")
    if (
        metadata.get("name") != "orchestra-dependencies"
        or metadata.get("namespace") != "orchestra-services-gitops"
        or not isinstance(annotations, dict)
        or annotations.get("orchestra.prometa.ai/activation") != "blocked"
        or annotations.get("orchestra.prometa.ai/dependency-bom")
        != "orchestra-dependencies-2026-07-21.1"
        or annotations.get("orchestra.prometa.ai/dependency-admission-digest")
        != "sha256:73282faf172793398120509087930691e362f2290d4b60cc7f13ef4f99bf4219"
        or annotations.get("orchestra.prometa.ai/dependency-source-verification-digest")
        != SOURCE_VERIFICATION_DIGEST
        or spec.get("sourceRepos") != [BOOTSTRAP_REPOSITORY]
        or spec.get("syncWindows")
        != [
            {
                "kind": "deny",
                "schedule": "0 0 * * *",
                "duration": "24h",
                "applications": ["*"],
                "manualSync": False,
            }
        ]
        or spec.get("orphanedResources") != {"warn": True}
    ):
        fail("dependency_gitops_project_contract_invalid")
    destinations = spec.get("destinations")
    if (
        not isinstance(destinations, list)
        or {
            item.get("namespace")
            for item in destinations
            if isinstance(item, dict)
            and item.get("server") == "https://kubernetes.default.svc"
        }
        != DESTINATION_NAMESPACES
    ):
        fail("dependency_gitops_project_destinations_invalid")


def field(document: str, name: str) -> str | None:
    match = re.search(rf"(?m)^{re.escape(name)}:\s*([^\n]+)$", document)
    return match.group(1).strip() if match else None


def metadata_name(document: str) -> str | None:
    match = re.search(
        r"(?m)^metadata:\s*\n(?:^[ \t]+[^\n]+\n)*?^[ \t]+name:\s*([^\n]+)$", document
    )
    return match.group(1).strip() if match else None


def metadata_namespace(document: str) -> str | None:
    match = re.search(
        r"(?m)^metadata:\s*\n(?:^[ \t]+[^\n]+\n)*?^[ \t]+namespace:\s*([^\n]+)$",
        document,
    )
    return match.group(1).strip() if match else None


def validate_rendered(content: str) -> None:
    documents = [
        item.strip() for item in re.split(r"(?m)^---\s*$", content) if item.strip()
    ]
    counts: dict[str, int] = {}
    namespace_names: set[str] = set()
    denied_namespaces: set[str] = set()
    for document in documents:
        kind = field(document, "kind")
        if not kind:
            fail("dependency_gitops_rendered_identity_invalid")
        counts[kind] = counts.get(kind, 0) + 1
        if kind in {"Secret", "Application", "ApplicationSet"}:
            fail(f"dependency_gitops_forbidden_object:{kind}")
        if kind == "Namespace":
            name = metadata_name(document)
            if name:
                namespace_names.add(name)
            if document.count("pod-security.kubernetes.io/enforce: restricted") != 1:
                fail("dependency_gitops_namespace_security_invalid")
        if kind == "NetworkPolicy":
            if (
                metadata_name(document) != "default-deny-all"
                or "podSelector: {}" not in document
                or "- Ingress" not in document
                or "- Egress" not in document
            ):
                fail("dependency_gitops_network_policy_invalid")
            namespace = metadata_namespace(document)
            if namespace:
                denied_namespaces.add(namespace)
    if counts != EXPECTED_RENDERED_COUNTS:
        fail("dependency_gitops_rendered_inventory_invalid")
    if namespace_names != NAMESPACES or denied_namespaces != NAMESPACES:
        fail("dependency_gitops_namespace_inventory_invalid")


def main() -> int:
    validate_project(load_json(GITOPS_ROOT / "project.json"))
    rendered = sys.stdin.read()
    if not rendered.strip():
        fail("dependency_gitops_rendered_input_required")
    validate_rendered(rendered)
    print(
        "dependency_gitops_valid "
        f"namespaces={len(NAMESPACES)} applications=0 activation=blocked"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
