#!/opt/prowler/bin/python -I
"""Starts Prowler's own entry point unchanged (installed as /opt/prowler/bin/prowler-argus).

One addition: botocore's line for each retry it makes ("Retry needed, retrying request after
delay of: ...", botocore.retries.standard, DEBUG) is let out, so Argus can count AWS's retries
in the scan's live log (owner, 2026-11-19). Nothing else of botocore at DEBUG passes: at DEBUG
it also prints requests and answers whole, which never leave the process. Prowler's own level
(--log-level) applies to everything else.
"""

import logging
import sys


class _RetriesOnly(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno > logging.DEBUG or record.getMessage().startswith("Retry needed")


retries = logging.getLogger("botocore.retries.standard")
retries.setLevel(logging.DEBUG)
retries.addFilter(_RetriesOnly())

from prowler.__main__ import prowler  # noqa: E402 - after the logger is set up

sys.argv[0] = "prowler"
sys.exit(prowler())
