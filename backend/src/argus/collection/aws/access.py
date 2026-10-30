"""How the worker reaches one AWS account for one run.

access_for() reads what a run needs from the database: the connection's auth and, for a role,
the platform identity. AwsAccess.credentials() turns that into keys for the tools, calling STS
when the connection assumes a role. The two steps are apart so that no database transaction
is open during the STS call, and so that the call happens inside collect(), where a failure
becomes a failed run in the Runs tab rather than a silent request error.
"""

from dataclasses import dataclass, field

from sqlalchemy import Connection

from argus import connections
from argus.connections import AwsAuth, ConnectionRow
from argus.core import aws
from argus.core.aws import SessionCredentials
from argus.settings import read_identity_credentials


@dataclass(frozen=True)
class AwsAccess:
    auth: AwsAuth
    # The platform identity's access key when it has one; None means the ambient chain.
    identity: SessionCredentials | None = field(default=None, repr=False)

    def credentials(self, *, session_name: str) -> SessionCredentials:
        if self.auth.method == "access_key":
            if not self.auth.access_key_id or not self.auth.secret_access_key:
                raise ValueError("the connection's access key is incomplete")
            return SessionCredentials(
                self.auth.access_key_id, self.auth.secret_access_key, self.auth.session_token
            )
        if not self.auth.role_arn or not self.auth.external_id:
            raise ValueError("the connection's role ARN or ExternalId is missing")
        return aws.assume_role(
            role_arn=self.auth.role_arn,
            external_id=self.auth.external_id,
            session_name=session_name,
            credentials=self.identity,
        )


def access_for(conn: Connection, connection: ConnectionRow) -> AwsAccess:
    auth = connections.open_auth(conn, connection)
    if auth.method == "access_key":
        return AwsAccess(auth)
    return AwsAccess(auth, read_identity_credentials(conn))
