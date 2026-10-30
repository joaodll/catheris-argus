"""Requirement titles and sections across Prowler's compliance CSV layouts (5.44.0, 5.45.0), and
5.45.0's quoting of cells a spreadsheet would read as a formula."""

import csv
import io

import pytest

from argus.collection.synthetic.prowler import _QuotingWriter, _sanitize_csv_value
from argus.findings.prowler import _code, _requirements, _unquote

MITRE = (
    "PROVIDER;DESCRIPTION;ACCOUNTID;REGION;ASSESSMENTDATE;REQUIREMENTS_ID;REQUIREMENTS_NAME;"
    "REQUIREMENTS_DESCRIPTION;REQUIREMENTS_TACTICS;REQUIREMENTS_SUBTECHNIQUES;STATUS;CHECKID;"
    "FRAMEWORK;NAME\r\n"
    "aws;d;123456789012;us-east-1;2026-10-16;T1040;Network Sniffing;Adversaries may sniff;"
    "Credential Access|Discovery;;FAIL;vpc_flow_logs_enabled;MITRE-ATTACK;MITRE ATT&CK\r\n"
    "aws;d;123456789012;us-east-1;2026-10-16;T1190;Exploit Public-Facing Application;"
    "Adversaries may attempt;Initial Access;;PASS;elbv2_waf_acl_attached;MITRE-ATTACK;"
    "MITRE ATT&CK\r\n"
)
ISO = (
    "REQUIREMENTS_ID;REQUIREMENTS_NAME;REQUIREMENTS_DESCRIPTION;REQUIREMENTS_ATTRIBUTES_CATEGORY;"
    "STATUS;CHECKID\r\n"
    "A.5.1;Policies for information security;Information security policy;A.5 Organizational "
    "controls;PASS;iam_password_policy\r\n"
)
THREATSCORE = (
    "REQUIREMENTS_ID;REQUIREMENTS_DESCRIPTION;REQUIREMENTS_ATTRIBUTES_TITLE;"
    "REQUIREMENTS_ATTRIBUTES_SECTION;STATUS;CHECKID\r\n"
    "1.1.1;Long text;Root has MFA;1. IAM;FAIL;iam_root_mfa_enabled\r\n"
)


def test_mitre_techniques_are_named_and_grouped_under_their_first_tactic() -> None:
    _, rows = _requirements("mitre_attack_aws", MITRE, quoted=False)
    by_id = {r.requirement_id: r for r in rows}
    assert by_id["T1040"].title == "Network Sniffing"
    assert by_id["T1040"].section == "Credential Access"
    assert by_id["T1040"].description == "Adversaries may sniff"
    assert by_id["T1190"].section == "Initial Access"


def test_iso_requirements_use_their_name_and_category() -> None:
    _, [row] = _requirements("iso27001_2022_aws", ISO, quoted=False)
    assert row.title == "Policies for information security"
    assert row.section == "A.5 Organizational controls"


def test_threatscore_keeps_its_own_title_and_section() -> None:
    _, [row] = _requirements("prowler_threatscore_aws", THREATSCORE, quoted=False)
    assert (row.title, row.section) == ("Root has MFA", "1. IAM")


@pytest.mark.parametrize(
    ("written", "meant"),
    [
        ("'- IAM User account root", "- IAM User account root"),
        ("'=HYPERLINK(x)", "=HYPERLINK(x)"),
        ("'+1 555", "+1 555"),
        ("'@sum", "@sum"),
        ("'\tindented", "\tindented"),
        ("'  - leading spaces", "  - leading spaces"),
        ("'-inf", "-inf"),
        ("' -1", " -1"),
        # Never quoted by Prowler, so read as written.
        ("-1", "-1"),
        ("'-1", "'-1"),
        ("'quoted text", "'quoted text"),
        ("plain", "plain"),
        ("", ""),
    ],
    ids=[
        "dash",
        "formula",
        "plus",
        "at",
        "tab",
        "spaces-dash",
        "minus-inf",
        "padded-number",
        "signed-number",
        "quoted-number",
        "own-quote",
        "plain",
        "empty",
    ],
)
def test_unquote_reads_what_prowler_meant(written: str, meant: str) -> None:
    assert _unquote(written) == meant


@pytest.mark.parametrize(
    "value",
    [
        "- a",
        "=1+1",
        "+x",
        "@x",
        "\tx",
        "\rx",
        "   -x",
        "-1",
        "1.5",
        "-1e3",
        " -1",
        "nan",
        "-inf",
        "x",
    ],
    ids=[
        "dash",
        "eq",
        "plus",
        "at",
        "tab",
        "cr",
        "spaces",
        "neg",
        "num",
        "exp",
        "pad",
        "nan",
        "inf",
        "x",
    ],
)
def test_quoting_and_unquoting_round_trip(value: str) -> None:
    """The synthetic source quotes as Prowler 5.45.0 does; the adapter undoes it exactly."""
    assert _unquote(_sanitize_csv_value(value)) == value


QUOTED_THREATSCORE_ROW = {
    "REQUIREMENTS_ID": "1.1.1",
    "REQUIREMENTS_DESCRIPTION": "- Ensure root has MFA",
    "REQUIREMENTS_ATTRIBUTES_TITLE": "=Root has MFA",
    "REQUIREMENTS_ATTRIBUTES_SECTION": "1. IAM",
    "STATUS": "FAIL",
    "CHECKID": "iam_root_mfa_enabled",
}


def _quoted_csv(row: dict[str, str]) -> str:
    buffer = io.StringIO()
    writer = _QuotingWriter(buffer, fieldnames=list(row), delimiter=";", lineterminator="\r\n")
    writer.writeheader()
    writer.writerow(row)
    return buffer.getvalue()


def test_a_5_45_compliance_csv_reads_as_prowler_meant_it() -> None:
    text = _quoted_csv(QUOTED_THREATSCORE_ROW)
    assert "'- Ensure root has MFA" in text  # quoted on the way out, as Prowler 5.45.0 writes
    _, [row] = _requirements("prowler_threatscore_aws", text, quoted=True)
    assert (row.description, row.title) == ("- Ensure root has MFA", "=Root has MFA")
    # A 5.44.0 file is read as written: that version never quoted.
    _, [raw] = _requirements("prowler_threatscore_aws", text, quoted=False)
    assert raw.description == "'- Ensure root has MFA"


def test_a_5_45_findings_csv_gives_the_code_as_prowler_meant_it() -> None:
    row = {
        "CHECK_ID": "s3_check",
        "REMEDIATION_CODE_CLI": "-- see the console",
        "RESOURCE_DETAILS": "=x",
    }
    code = _code(_quoted_csv(row), quoted=True)
    assert code == {"s3_check": {"code_cli": "-- see the console"}}
    assert (
        list(csv.reader(io.StringIO(_quoted_csv(row)), delimiter=";"))[1][1]
        == "'-- see the console"
    )
