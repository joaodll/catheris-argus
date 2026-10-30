"""Print the scanner role's own policies as plain IAM JSON, for a scanning identity that is not
the CloudFormation role: the test IAM user of ADR-0024, or an SSO permission set.

Attach the two AWS managed policies (SecurityAudit, job-function/ViewOnlyAccess) and create one
customer managed policy from each document printed here. Each stays under IAM's 6,144-character
limit for a managed policy; together they are too large for one inline user policy (2,048).
The documents come from scanner-role.yaml, so they never drift from what `lint` checks.

    docker compose run --rm policy-check python print_policies.py /work/scanner-role.yaml
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import yaml

from check_readonly import CfnLoader

MANAGED_POLICY_LIMIT = 6144  # characters, whitespace not counted


def policies(template: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Each customer managed policy of the template, by resource name, as an IAM document."""
    return {
        name: res["Properties"]["PolicyDocument"]
        for name, res in template.get("Resources", {}).items()
        if res.get("Type") == "AWS::IAM::ManagedPolicy"
    }


def compact(document: dict[str, Any]) -> str:
    return json.dumps(document, separators=(",", ":"))


def main(paths: list[str]) -> int:
    if len(paths) != 1:
        print("usage: print_policies.py TEMPLATE", file=sys.stderr)
        return 2
    template = yaml.load(Path(paths[0]).read_text(), Loader=CfnLoader)  # noqa: S506 - SafeLoader subclass
    for name, document in policies(template).items():
        print(f"# Argus{name.removesuffix('Policy')} ({len(compact(document))} characters)")
        print(json.dumps(document, indent=2))
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
