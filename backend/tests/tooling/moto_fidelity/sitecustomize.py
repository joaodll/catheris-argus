"""Loaded by the dev-only moto service at start (compose.yaml, PYTHONPATH): two places where
moto 5.1.4 answers unlike AWS, so the pinned tools fail on the emulator where they would not on
AWS (found 2026-10-21, the exposure scenario).

- A stopped or terminated instance's StateTransitionReason: moto writes "User initiated
  (<time> UTC)", AWS "User initiated (<time> GMT)". The Steampipe plugin parses only AWS's form
  into state_transition_time, and one unparsable row fails the whole aws_ec2_instance export.
- An instance launched with network interfaces: moto lists no security groups on the instance
  itself, AWS lists its interfaces' groups (Prowler's exposure checks read only those).
- Lambda's event source mappings: moto finds the operation by its own (older) API model, whose
  path ends in a slash that neither botocore nor the Go SDK sends any more.
"""

from moto.awslambda.responses import LambdaResponse
from moto.ec2.models import instances


def _aws_reason(name: str) -> None:
    original = getattr(instances.Instance, name)

    def patched(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        result = original(self, *args, **kwargs)
        self._reason = self._reason.replace(" UTC)", " GMT)")
        return result

    setattr(instances.Instance, name, patched)


for _name in ("stop", "terminate"):
    _aws_reason(_name)


def _groups(self):  # type: ignore[no-untyped-def]
    groups = []
    for group in [*self.security_groups, *(g for n in self.nics.values() for g in n._group_set)]:
        if group not in groups:
            groups.append(group)
    return groups


instances.Instance.dynamic_group_list = property(_groups)

_find_action = LambdaResponse._get_action_from_method_and_request_uri


def _with_slash(self, method: str, request_uri: str) -> str:  # type: ignore[no-untyped-def]
    if request_uri.endswith("/event-source-mappings"):
        request_uri += "/"
    return _find_action(self, method, request_uri)


LambdaResponse._get_action_from_method_and_request_uri = _with_slash
