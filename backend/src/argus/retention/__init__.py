"""Retention: what history Argus keeps (design: six months in Postgres; raw output a year in
S3, regenerable synthetic raw only briefly).

    run_retention()  drops snapshot/event/metric partitions older than the retention window,
                     deletes configurations no snapshot or resource points to any more, and
                     prunes demo (synthetic) raw runs older than their short window.

The windows are administration settings (UI), each bounded by the environment.
"""

from argus.retention.job import RetentionResult, run_retention

__all__ = ["RetentionResult", "run_retention"]
