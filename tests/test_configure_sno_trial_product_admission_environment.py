from __future__ import annotations

import copy
import json
import stat
import tempfile
import unittest
from pathlib import Path
from typing import Any

from scripts.configure_sno_trial_product_admission_environment import (
    GithubApiError,
    PLAN_CONTROLS,
    apply_plan,
    build_plan,
    payload_digest,
    read_plan,
    validate_plan,
    verify_environment,
    write_plan,
)


class FakeGithub:
    def __init__(self) -> None:
        self.token = "fixture-admin-token-1234567890"
        self.repository = {
            "id": 1307302690,
            "full_name": "caglarsubas/orchestra-openshift-reference-lab",
            "private": True,
            "visibility": "private",
            "default_branch": "main",
            "archived": False,
            "owner": {"id": 37515097, "login": "owner-fixture"},
        }
        self.reviewer = {
            "id": 24681012,
            "login": "reviewer-fixture",
            "type": "User",
        }
        self.permission = {
            "permission": "read",
            "role_name": "triage",
            "user": copy.deepcopy(self.reviewer),
        }
        self.environment: dict[str, Any] | None = None
        self.branches: list[dict[str, Any]] = []
        self.next_branch_id = 500
        self.secrets: list[dict[str, Any]] = []
        self.mutations: list[tuple[str, str, dict[str, Any] | None]] = []
        self.environment_put_status: int | None = None

    def ready(self) -> None:
        self.environment = {
            "id": 987654,
            "name": "sno-trial-product-artifact-admission",
            "deployment_branch_policy": {
                "protected_branches": False,
                "custom_branch_policies": True,
            },
            "protection_rules": [
                {
                    "id": 1,
                    "type": "required_reviewers",
                    "prevent_self_review": True,
                    "reviewers": [
                        {
                            "type": "User",
                            "reviewer": copy.deepcopy(self.reviewer),
                        }
                    ],
                },
                {"id": 2, "type": "branch_policy"},
            ],
        }
        self.branches = [{"id": 499, "name": "main", "type": "branch"}]

    def __call__(
        self,
        method: str,
        path: str,
        token: str,
        body: dict[str, Any] | None,
    ) -> Any:
        if token != self.token:
            raise AssertionError("unexpected token")
        if method != "GET":
            self.mutations.append((method, path, copy.deepcopy(body)))
        if method == "GET" and path == (
            "/repos/caglarsubas/orchestra-openshift-reference-lab"
        ):
            return copy.deepcopy(self.repository)
        if method == "GET" and path == "/users/reviewer-fixture":
            return copy.deepcopy(self.reviewer)
        if method == "GET" and "/collaborators/" in path:
            return copy.deepcopy(self.permission)
        if "/environments/sno-trial-product-artifact-admission" not in path:
            raise AssertionError(f"unexpected path: {path}")

        if method == "GET" and path.endswith("/secrets?per_page=100"):
            return {
                "total_count": len(self.secrets),
                "secrets": copy.deepcopy(self.secrets),
            }
        if (
            method == "GET"
            and "/deployment-branch-policies" not in path
            and "/secrets" not in path
        ):
            if self.environment is None:
                raise GithubApiError(404)
            return copy.deepcopy(self.environment)
        if method == "GET" and path.endswith(
            "/deployment-branch-policies?per_page=100"
        ):
            return {
                "total_count": len(self.branches),
                "branch_policies": copy.deepcopy(self.branches),
            }
        if method == "PUT" and "/deployment-branch-policies/" not in path:
            if self.environment_put_status is not None:
                raise GithubApiError(self.environment_put_status)
            assert body is not None
            self.environment = {
                "id": 987654,
                "name": "sno-trial-product-artifact-admission",
                "deployment_branch_policy": copy.deepcopy(
                    body["deployment_branch_policy"]
                ),
                "protection_rules": [
                    {
                        "id": 1,
                        "type": "required_reviewers",
                        "prevent_self_review": body["prevent_self_review"],
                        "reviewers": [
                            {
                                "type": reviewer["type"],
                                "reviewer": copy.deepcopy(self.reviewer),
                            }
                            for reviewer in body["reviewers"]
                        ],
                    },
                    {"id": 2, "type": "branch_policy"},
                ],
            }
            return copy.deepcopy(self.environment)
        if method == "DELETE" and "/deployment-branch-policies/" in path:
            policy_id = int(path.rsplit("/", 1)[1])
            self.branches = [
                branch for branch in self.branches if branch["id"] != policy_id
            ]
            return None
        if method == "POST" and path.endswith("/deployment-branch-policies"):
            assert body == {"name": "main", "type": "branch"}
            created = {"id": self.next_branch_id, **body}
            self.next_branch_id += 1
            self.branches.append(created)
            return copy.deepcopy(created)
        raise AssertionError(f"unexpected request: {method} {path}")


class ProductAdmissionEnvironmentBootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.github = FakeGithub()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.token_path = self.directory / "github-token"
        self.token_path.write_text(self.github.token, encoding="ascii")
        self.token_path.chmod(0o600)

    def build(self) -> dict[str, Any]:
        return build_plan(
            self.token_path,
            "reviewer-fixture",
            request=self.github,
        )

    def test_missing_environment_plan_is_payload_free_and_digest_bound(self) -> None:
        plan = self.build()
        encoded = json.dumps(plan)
        self.assertEqual(plan["status"], "MISSING")
        self.assertEqual(
            plan["operations"],
            [
                "upsert-protected-environment",
                "create-main-branch-policy",
                "verify-exact-contract",
            ],
        )
        self.assertEqual(plan["controls"], PLAN_CONTROLS)
        self.assertNotIn("reviewer-fixture", encoded)
        self.assertNotIn("24681012", encoded)
        self.assertEqual(
            plan["reviewerIdentityDigest"],
            payload_digest({"type": "User", "id": 24681012}),
        )
        validate_plan(plan)

    def test_ready_environment_produces_no_mutation_operations(self) -> None:
        self.github.ready()
        plan = self.build()
        self.assertEqual(plan["status"], "READY")
        self.assertEqual(plan["operations"], [])
        evidence = verify_environment(self.token_path, request=self.github)
        self.assertEqual(evidence["reviewerCount"], 1)
        self.assertTrue(evidence["preventSelfReview"])

    def test_owner_and_non_collaborator_cannot_be_planned(self) -> None:
        self.github.reviewer["id"] = 37515097
        self.github.permission["user"]["id"] = 37515097
        with self.assertRaisesRegex(ValueError, "owner_reviewer_forbidden"):
            self.build()

        self.github.reviewer["id"] = 24681012
        self.github.permission["user"]["id"] = 24681012
        self.github.permission["permission"] = "none"
        with self.assertRaisesRegex(ValueError, "repository_access_required"):
            self.build()

    def test_plan_file_is_create_only_private_and_tamper_evident(self) -> None:
        plan = self.build()
        path = self.directory / "plan.json"
        write_plan(path, plan)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(read_plan(path), plan)
        with self.assertRaisesRegex(ValueError, "output_exists"):
            write_plan(path, plan)

        changed = copy.deepcopy(plan)
        changed["status"] = "READY"
        path.write_text(json.dumps(changed), encoding="ascii")
        with self.assertRaisesRegex(ValueError, "digest_mismatch"):
            read_plan(path)

        path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "permissions_invalid"):
            read_plan(path)

        path.unlink()
        target = self.directory / "target.json"
        target.write_text(json.dumps(plan), encoding="ascii")
        target.chmod(0o600)
        path.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "symlink_forbidden"):
            read_plan(path)

    def test_existing_environment_secrets_block_planning(self) -> None:
        self.github.ready()
        self.github.secrets = [
            {
                "name": "FORBIDDEN_FIXTURE",
                "created_at": "2026-07-28T00:00:00Z",
                "updated_at": "2026-07-28T00:00:00Z",
            }
        ]
        with self.assertRaisesRegex(ValueError, "secrets_forbidden"):
            self.build()
        self.assertEqual(self.github.mutations, [])

    def test_missing_environment_apply_creates_exact_protection(self) -> None:
        plan = self.build()
        path = self.directory / "plan.json"
        write_plan(path, plan)
        evidence = apply_plan(
            self.token_path,
            path,
            "reviewer-fixture",
            plan["planDigest"],
            request=self.github,
        )
        self.assertEqual(evidence["reviewerCount"], 1)
        self.assertEqual([branch["name"] for branch in self.github.branches], ["main"])
        methods = [method for method, _, _ in self.github.mutations]
        self.assertEqual(methods, ["PUT", "POST"])
        put_body = self.github.mutations[0][2]
        self.assertEqual(
            put_body,
            {
                "wait_timer": 0,
                "prevent_self_review": True,
                "reviewers": [{"type": "User", "id": 24681012}],
                "deployment_branch_policy": {
                    "protected_branches": False,
                    "custom_branch_policies": True,
                },
            },
        )

    def test_drifted_environment_replaces_extra_branch_policy(self) -> None:
        self.github.ready()
        self.github.environment["protection_rules"][0]["prevent_self_review"] = False
        self.github.branches.append({"id": 501, "name": "release/*", "type": "branch"})
        plan = self.build()
        self.assertEqual(plan["status"], "DRIFTED")
        path = self.directory / "plan.json"
        write_plan(path, plan)
        apply_plan(
            self.token_path,
            path,
            "reviewer-fixture",
            plan["planDigest"],
            request=self.github,
        )
        self.assertEqual(
            self.github.branches,
            [{"id": 499, "name": "main", "type": "branch"}],
        )
        self.assertEqual(
            [method for method, _, _ in self.github.mutations],
            ["PUT", "DELETE"],
        )

    def test_apply_refuses_changed_state_before_mutation(self) -> None:
        plan = self.build()
        path = self.directory / "plan.json"
        write_plan(path, plan)
        self.github.permission["permission"] = "write"
        with self.assertRaisesRegex(ValueError, "plan_stale"):
            apply_plan(
                self.token_path,
                path,
                "reviewer-fixture",
                plan["planDigest"],
                request=self.github,
            )
        self.assertEqual(self.github.mutations, [])

    def test_apply_requires_explicit_matching_digest(self) -> None:
        plan = self.build()
        path = self.directory / "plan.json"
        write_plan(path, plan)
        with self.assertRaisesRegex(ValueError, "expected_plan_digest_mismatch"):
            apply_plan(
                self.token_path,
                path,
                "reviewer-fixture",
                "sha256:" + "0" * 64,
                request=self.github,
            )
        self.assertEqual(self.github.mutations, [])

    def test_private_plan_limitation_fails_closed(self) -> None:
        plan = self.build()
        path = self.directory / "plan.json"
        write_plan(path, plan)
        self.github.environment_put_status = 422
        with self.assertRaisesRegex(ValueError, "required_reviewers_unavailable"):
            apply_plan(
                self.token_path,
                path,
                "reviewer-fixture",
                plan["planDigest"],
                request=self.github,
            )
        self.assertEqual(
            [method for method, _, _ in self.github.mutations],
            ["PUT"],
        )


if __name__ == "__main__":
    unittest.main()
