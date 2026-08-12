#!/usr/bin/env python3
from __future__ import annotations

import ast
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "chronos-policy.json"


def _call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""


def _violations(path: Path, code: str, policy: dict[str, object]) -> list[dict[str, object]]:
    tree = ast.parse(code, filename=str(path))
    rules = policy["rules"]
    rule = rules[0]
    forbidden = set(rule["forbid_calls"])
    required = rule["require_keyword"]
    findings: list[dict[str, object]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        if name in forbidden:
            findings.append({
                "rule_id": rule["id"],
                "kind": rule["kind"],
                "path": str(path.relative_to(ROOT)),
                "line": node.lineno,
                "reason": f"forbidden non-group-aware split call: {name}",
            })
        if name == required["call"] and not any(
            keyword.arg == required["keyword"] for keyword in node.keywords
        ):
            findings.append({
                "rule_id": rule["id"],
                "kind": rule["kind"],
                "path": str(path.relative_to(ROOT)),
                "line": node.lineno,
                "reason": "cross_validate is missing the required groups argument",
            })
    return findings


def main() -> int:
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    paths = [ROOT / value for value in policy["coverage"]["supported_paths"]]
    missing = [str(path.relative_to(ROOT)) for path in paths if not path.is_file()]
    findings: list[dict[str, object]] = []
    for path in paths:
        if path.is_file():
            findings.extend(_violations(path, path.read_text(encoding="utf-8"), policy))
    result = {
        "schema": "chronos.ci-evaluation.v1",
        "policy_id": policy["policy_id"],
        "policy_state": policy["state"],
        "coverage": {
            "mode": policy["coverage"]["mode"],
            "eligible_supported_files": len(paths),
            "analyzed_supported_files": len(paths) - len(missing),
            "missing_supported_files": missing,
        },
        "status": "FAIL" if findings or missing else "PASS",
        "blocking_findings": findings,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    for finding in findings:
        print(
            f"::error file={finding['path']},line={finding['line']}::"
            f"{finding['rule_id']}: {finding['reason']}"
        )
    return 2 if findings or missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
