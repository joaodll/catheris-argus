"""Reports on Kubernetes (ADR-0047 round 5): the store each claimed report is built into, and the
check a report Job makes before it claims anything."""

from pathlib import Path

from argus.core.aws import NoWebIdentityError, web_identity_s3_client
from argus.reports import pdf
from argus.reports.model import ClaimedReport, ReportRefusedError
from argus.reports.store import ReportStore, ReportStoreUnavailableError, S3ReportStore, StoreFor

NOT_ON_S3 = "This report was requested where reports are kept on a local volume. Request it again."


def s3_store_for(scratch: Path) -> StoreFor:
    """The bucket recorded on each report, through this pod's IRSA role; files are written in
    `scratch` first."""

    def store_for(report: ClaimedReport) -> ReportStore:
        if report.storage_bucket is None or report.storage_region is None:
            raise ReportRefusedError(NOT_ON_S3)
        try:
            client = web_identity_s3_client(report.storage_region)
        except NoWebIdentityError as exc:
            raise ReportStoreUnavailableError(str(exc)) from exc
        return S3ReportStore(client, report.storage_bucket, scratch)

    return store_for


def renderer_present() -> bool:
    """Whether this image carries the PDF renderer: a report Job on an image without it would
    claim a PDF only to fail it."""
    return Path(pdf.RENDER_PYTHON).is_file() and Path(pdf.RENDER_SCRIPT).is_file()
