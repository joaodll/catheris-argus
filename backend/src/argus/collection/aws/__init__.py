"""The AWS source: Prowler, CloudFox and Steampipe export against one account, read-only.

Public interface:
    AwsSource     the source an AWS connection collects with
    access_for()  what a run needs to reach the account, read from the database
    missing_tools()  the tools whose binary this image does not carry (ADR-0046)
"""

from argus.collection.aws.access import AwsAccess, access_for
from argus.collection.aws.source import AwsSource
from argus.collection.aws.tools import missing_tools

__all__ = ["AwsAccess", "AwsSource", "access_for", "missing_tools"]
