"""Which source collects for a connection kind."""

from typing import Literal

from argus.collection.aws import AwsSource
from argus.collection.collect import Source
from argus.collection.synthetic.source import SyntheticSource


def source_for(kind: Literal["demo", "aws"]) -> Source:
    if kind == "demo":
        return SyntheticSource()
    return AwsSource()
