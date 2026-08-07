"""Validate workflow safety, action pins, and the reviewed action inventory."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import yaml

SHA = re.compile(r"^[0-9a-f]{40}$")
ALLOWED_RUNNERS = {"ubuntu-24.04", "windows-2025"}
REQUIRED_WORKFLOWS = {
    "benchmark-scheduled.yml",
    "ci-essential.yml",
    "codeql.yml",
    "real-model-benchmark.yml",
    "release.yml",
    "security.yml",
}
APPROVED_ACTION_REPOSITORIES = {
    "actions/attest",
    "actions/attest-build-provenance",
    "actions/checkout",
    "actions/download-artifact",
    "actions/setup-python",
    "actions/upload-artifact",
    "github/codeql-action",
    "gitleaks/gitleaks-action",
    "sigstore/gh-action-sigstore-python",
    "softprops/action-gh-release",
}


class WorkflowLoader(yaml.SafeLoader):
    pass


# YAML 1.1 treats `on` as a boolean. GitHub Actions uses YAML 1.2 semantics.
for first_character, resolvers in list(WorkflowLoader.yaml_implicit_resolvers.items()):
    WorkflowLoader.yaml_implicit_resolvers[first_character] = [
        item for item in resolvers if item[0] != "tag:yaml.org,2002:bool"
    ]
WorkflowLoader.add_implicit_resolver(  # type: ignore[no-untyped-call]
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|false)$", re.IGNORECASE),
    list("tTfF"),
)


def _load(path: Path) -> dict[str, Any]:
    payload = yaml.load(
        path.read_text(encoding="utf-8"),
        Loader=WorkflowLoader,  # noqa: S506 - this derives only from SafeLoader
    )
    if not isinstance(payload, dict):
        raise ValueError(f"invalid YAML mapping: {path.name}")
    return payload


def _action_inventory(root: Path) -> tuple[set[tuple[str, str]], list[str]]:
    payload = _load(root / ".github" / "actions-lock.yml")
    errors: list[str] = []
    if payload.get("lock_version") != 1 or not isinstance(payload.get("actions"), list):
        return set(), ["action inventory has an invalid schema"]
    pins: set[tuple[str, str]] = set()
    ids: set[str] = set()
    for entry in payload["actions"]:
        if not isinstance(entry, dict):
            errors.append("action inventory entry is not a mapping")
            continue
        identifier = entry.get("id")
        repository = entry.get("repository")
        sha = entry.get("sha")
        if not isinstance(identifier, str) or identifier in ids:
            errors.append("action inventory IDs must be unique strings")
        else:
            ids.add(identifier)
        if not isinstance(repository, str) or repository.count("/") != 1:
            errors.append(f"invalid action repository in inventory: {identifier}")
        elif repository not in APPROVED_ACTION_REPOSITORIES:
            errors.append(f"unapproved action repository in inventory: {repository}")
        elif entry.get("owner") != repository.split("/", 1)[0]:
            errors.append(f"action owner mismatch in inventory: {identifier}")
        if not isinstance(sha, str) or not SHA.fullmatch(sha):
            errors.append(f"invalid action SHA in inventory: {identifier}")
        else:
            pins.add((str(repository), sha))
        for required in (
            "owner",
            "release",
            "url",
            "purpose",
            "date_verified",
            "security_review_status",
            "security_notes",
            "workflows",
        ):
            if required not in entry:
                errors.append(f"action inventory entry {identifier} lacks {required}")
        if not str(entry.get("security_review_status", "")).startswith("reviewed"):
            errors.append(f"action inventory entry {identifier} is not security reviewed")
    return pins, errors


def validate_workflows(root: Path) -> list[str]:
    workflow_root = root / ".github" / "workflows"
    paths = sorted(workflow_root.glob("*.yml"))
    errors: list[str] = []
    present = {path.name for path in paths}
    if present != REQUIRED_WORKFLOWS:
        errors.append(f"workflow set differs from reviewed set: {sorted(present)}")
    inventory, inventory_errors = _action_inventory(root)
    errors.extend(inventory_errors)
    for path in paths:
        workflow_actions: set[tuple[str, str]] = set()
        try:
            workflow = _load(path)
        except (OSError, ValueError, yaml.YAMLError) as exc:
            errors.append(str(exc))
            continue
        triggers = workflow.get("on")
        if not isinstance(triggers, dict) or "workflow_dispatch" not in triggers:
            errors.append(f"{path.name}: workflow_dispatch is required")
        permissions = workflow.get("permissions")
        if not isinstance(permissions, dict) or permissions.get("contents") != "read":
            errors.append(f"{path.name}: root permissions must grant only baseline contents: read")
        concurrency = workflow.get("concurrency")
        if not isinstance(concurrency, dict) or "group" not in concurrency:
            errors.append(f"{path.name}: bounded concurrency is required")
        concurrency_mapping = concurrency if isinstance(concurrency, dict) else {}
        if path.name == "release.yml":
            if concurrency_mapping.get("cancel-in-progress") is not False:
                errors.append("release.yml: release runs must not be cancelled in progress")
            if isinstance(triggers, dict) and "pull_request" in triggers:
                errors.append("release.yml: releases must never run for pull requests")
        elif concurrency_mapping.get("cancel-in-progress") is not True:
            errors.append(f"{path.name}: stale non-release runs must be cancelled")
        jobs = workflow.get("jobs")
        if not isinstance(jobs, dict):
            errors.append(f"{path.name}: jobs mapping is required")
            continue
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                errors.append(f"{path.name}/{job_name}: invalid job")
                continue
            if not isinstance(job.get("timeout-minutes"), int):
                errors.append(f"{path.name}/{job_name}: timeout-minutes is required")
            runner = job.get("runs-on")
            if isinstance(runner, str):
                if runner not in ALLOWED_RUNNERS and "matrix.os" not in runner:
                    errors.append(f"{path.name}/{job_name}: unsupported runner {runner}")
            elif runner != ["self-hosted", "securedact-models"]:
                errors.append(f"{path.name}/{job_name}: unsupported runner labels")
            steps = job.get("steps")
            if not isinstance(steps, list) or not steps:
                errors.append(f"{path.name}/{job_name}: steps are required")
                continue
            first = steps[0]
            if (
                not isinstance(first, dict)
                or "run" not in first
                or "Repository steps started" not in str(first.get("name"))
                or "SECUREDACT_CI_STEPS_STARTED=1" not in str(first.get("run"))
            ):
                errors.append(
                    f"{path.name}/{job_name}: first step must be the runner-start sentinel"
                )
            for step in steps:
                if not isinstance(step, dict) or "uses" not in step:
                    continue
                action = str(step["uses"])
                if action.startswith("./"):
                    local_path = root / action.removeprefix("./")
                    if not local_path.exists():
                        errors.append(f"{path.name}: local action path does not exist: {action}")
                    continue
                if "@" not in action:
                    errors.append(f"{path.name}: action has no immutable pin: {action}")
                    continue
                uses_path, sha = action.rsplit("@", 1)
                repository = "/".join(uses_path.split("/")[:2])
                if not SHA.fullmatch(sha):
                    errors.append(f"{path.name}: action is not pinned to a full SHA: {action}")
                    continue
                workflow_actions.add((repository, sha))
                if (repository, sha) not in inventory:
                    errors.append(f"{path.name}: action is absent from inventory: {action}")
        if path.name == "ci-essential.yml":
            essential = {repo for repo, _sha in workflow_actions}
            source = path.read_text(encoding="utf-8")
            if essential != {"actions/checkout", "actions/setup-python"}:
                errors.append(
                    "ci-essential.yml: essential action set must be checkout and setup-python"
                )
            if "secrets." in source or "upload-artifact" in source:
                errors.append(
                    "ci-essential.yml: essential CI must not use secrets or artifact actions"
                )
        if path.name == "release.yml" and isinstance(triggers, dict):
            push = triggers.get("push")
            if not isinstance(push, dict) or push.get("tags") != ["v*.*.*"]:
                errors.append(
                    "release.yml: release push trigger must be semantic version tags only"
                )
            if "release_metadata.py validate" not in path.read_text(encoding="utf-8"):
                errors.append("release.yml: manual runs must retain annotated-tag validation")
        if isinstance(triggers, dict) and "pull_request" in triggers:
            source = path.read_text(encoding="utf-8")
            if "secrets." in source or "contents: write" in source or "id-token: write" in source:
                errors.append(f"{path.name}: pull-request workflow has unsafe secret/write access")
    return sorted(set(errors))


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    errors = validate_workflows(root)
    if errors:
        print("Workflow validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("Workflow and action inventory validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
