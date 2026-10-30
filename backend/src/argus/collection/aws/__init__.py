"""The AWS source: Prowler, CloudFox and Steampipe export against one account, read-only.

Public interface:
    AwsSource     the source an AWS connection collects with
    access_for()  what a run needs to reach the account, read from the database
"""

from argus.collection.aws.access import AwsAccess, access_for
from argus.collection.aws.source import AwsSource

__all__ = ["AwsAccess", "AwsSource", "access_for"]
