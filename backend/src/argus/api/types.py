"""Value types more than one router shares, so routers never import each other."""

from typing import Literal

# The clouds Argus knows. Only AWS is covered yet; GCP and OCI are accepted so a filter reads
# the same once they are (frontend/src/providers.ts).
Provider = Literal["aws", "gcp", "oci"]
