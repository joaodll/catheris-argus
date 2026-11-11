"""The pinned Prowler's AWS checks and compliance frameworks, as Argus ships them
(prowler_checks_aws.txt, prowler_frameworks_aws.txt). They bound what Collection settings may
skip, and give the frameworks a run that skips something passes, so its compliance stays
complete (owner, 2026-11-10). The worker image's build checks both against the installed
Prowler."""

from functools import cache
from importlib import resources


def _lines(name: str) -> tuple[str, ...]:
    text = (resources.files("argus.collection") / name).read_text()
    return tuple(
        line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")
    )


@cache
def prowler_checks() -> tuple[str, ...]:
    return _lines("prowler_checks_aws.txt")


@cache
def prowler_services() -> tuple[str, ...]:
    """A check's service is the first word of its id (true of every check in 5.48.0)."""
    return tuple(sorted({check.split("_", 1)[0] for check in prowler_checks()}))


@cache
def prowler_frameworks() -> tuple[str, ...]:
    return _lines("prowler_frameworks_aws.txt")
