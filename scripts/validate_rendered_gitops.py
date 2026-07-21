#!/usr/bin/env python3
"""Validate the deterministic Kustomize output without contacting a cluster."""

from __future__ import annotations

import re
import sys


EXPECTED_NAMESPACES = {
    "orchestra-platform",
    "orchestra-runtime",
    "orchestra-model",
    "orchestra-synthetic",
    "orchestra-external-secrets",
    "orchestra-observability",
}
EXPECTED_COUNTS = {
    "Namespace": 6,
    "NetworkPolicy": 6,
    "ResourceQuota": 6,
    "StorageClass": 1,
}


def field(document: str, name: str) -> str | None:
    match = re.search(rf"(?m)^{re.escape(name)}:\s*([^\n]+)$", document)
    return match.group(1).strip() if match else None


def main() -> int:
    content = sys.stdin.read()
    documents = [
        item.strip() for item in re.split(r"(?m)^---\s*$", content) if item.strip()
    ]
    if len(documents) != sum(EXPECTED_COUNTS.values()):
        raise ValueError("gitops_document_count_invalid")

    counts: dict[str, int] = {}
    namespaces: set[str] = set()
    for document in documents:
        api_version = field(document, "apiVersion")
        kind = field(document, "kind")
        if not api_version or not kind or "\nmetadata:\n" not in f"\n{document}\n":
            raise ValueError("gitops_document_identity_invalid")
        if kind == "Secret" or re.search(r"(?mi)^\s*(stringData|data):\s*$", document):
            raise ValueError("gitops_secret_material_forbidden")
        counts[kind] = counts.get(kind, 0) + 1
        if kind == "Namespace":
            name = re.search(r"(?m)^  name:\s*([^\n]+)$", document)
            if not name:
                raise ValueError("gitops_namespace_name_missing")
            namespaces.add(name.group(1).strip())
            for level in ("audit", "enforce", "warn"):
                if f"pod-security.kubernetes.io/{level}: restricted" not in document:
                    raise ValueError(f"gitops_namespace_psa_missing:{level}")
        if kind == "NetworkPolicy":
            if (
                "podSelector: {}" not in document
                or "- Egress" not in document
                or "- Ingress" not in document
            ):
                raise ValueError("gitops_default_deny_invalid")
        if kind == "StorageClass":
            required = (
                "provisioner: pd.csi.storage.gke.io",
                "replication-type: regional-pd",
                "allowVolumeExpansion: true",
                "volumeBindingMode: WaitForFirstConsumer",
                "reclaimPolicy: Retain",
            )
            if any(item not in document for item in required):
                raise ValueError("gitops_storage_class_invalid")

    if counts != EXPECTED_COUNTS or namespaces != EXPECTED_NAMESPACES:
        raise ValueError("gitops_inventory_invalid")
    print("gitops_render_valid documents=19 defaultDenyNamespaces=6")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
