"""The report renderer (ADR-0047, round 2): a report's JSON context in, its PDF out.

It runs in its own venv (/opt/report-render) as a separate process that Argus starts with an
environment built from nothing (argus.core.process.run_isolated): it holds no database password,
no keyring and no cloud credential. The context carries names and tags from scanned clouds, so:

- resource limits are set before anything reads the input;
- Jinja2 escapes every value (autoescape, StrictUndefined) and no template marks anything safe;
- WeasyPrint fetches nothing: every URL a document names is refused and counted. Fonts are system
  fonts found by family name, so no document needs a fetch.

Usage:
    render.py              the context on stdin; the PDF to $HOME/out; "pages=N" on stdout
    render.py --self-test  run at image build: hostile values are escaped, nothing is fetched
    render.py --measure    a worst-case context at the caps: time, peak memory, pages, bytes
"""

import json
import os
import resource
import sys
import time
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined
from weasyprint import HTML
from weasyprint.urls import URLFetcher

TEMPLATES = Path(__file__).resolve().parent / "templates"
KINDS = ("misconfigurations", "vulnerabilities", "resource-problems")
ADDRESS_SPACE = 2 << 30  # 2 GiB: a worst-case render peaked at 605 MiB resident (2026-11-11)
CPU_SECONDS = 600
FILE_SIZE = 256 << 20  # no file it writes, the PDF included, can outgrow Argus's 200 MB cap by much
SEVERITIES = ("critical", "high", "medium", "low", "informational")


def limit() -> None:
    resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_SPACE, ADDRESS_SPACE))
    resource.setrlimit(resource.RLIMIT_CPU, (CPU_SECONDS, CPU_SECONDS))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_SIZE, FILE_SIZE))


class RefuseAll(URLFetcher):
    """Every URL is refused, and remembered so a test can see it was asked for."""

    def __init__(self) -> None:
        super().__init__(allowed_protocols=set(), allow_redirects=False)
        self.refused: list[str] = []

    def fetch(self, url: str, headers: Any = None) -> Any:
        self.refused.append(url)
        raise ValueError("Argus's report renderer fetches nothing")


def _number(value: Any) -> str:
    return f"{value:,}" if isinstance(value, int) else str(value)


def _web_link(url: Any) -> str:
    """A link the PDF may carry: http or https only. The context already checks this; the
    renderer checks again, as the last thing between a scanned cloud's text and the document."""
    if isinstance(url, str) and url.lower().startswith(("https://", "http://")):
        return url
    return ""


BAR_UNITS = 1000


def _check_bar(shares: Any) -> None:
    """The share bar's numbers go into SVG attributes: integers only, inside the bar, adding up
    to the whole. Anything else is refused, so no text from the context reaches the drawing."""
    if not isinstance(shares, list):
        raise ValueError("shares: not a list")
    x = 0
    for share in shares:
        start, width = share.get("x"), share.get("width")
        if type(start) is not int or type(width) is not int or start != x or width < 0:
            raise ValueError("shares: not whole units in order")
        if share.get("severity") not in SEVERITIES:
            raise ValueError("shares: unknown severity")
        x += width
    if shares and x != BAR_UNITS:
        raise ValueError("shares: the parts do not make the whole")


def render_html(context: dict[str, Any]) -> str:
    kind = context["kind"]
    if kind not in KINDS:
        raise ValueError(f"unknown report kind: {kind!r}")
    _check_bar(context["shares"])
    env = Environment(
        loader=FileSystemLoader(TEMPLATES),
        autoescape=True,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["num"] = _number
    env.filters["web_link"] = _web_link
    return env.get_template(f"{kind.replace('-', '_')}.html").render(ctx=context)


def render_pdf(html: str) -> tuple[bytes, int, list[str]]:
    fetcher = RefuseAll()
    document = HTML(string=html, base_url=None, url_fetcher=fetcher).render()
    return document.write_pdf(), len(document.pages), fetcher.refused


# ---- fixtures for --self-test and --measure --------------------------------------------------

HOSTILE = "<script>alert(1)</script><img src=http://169.254.169.254/x> url(file:///etc/passwd) \"'&"


FACTS = {
    "cve": "CVE-2026-0001",
    "cvss": 9.8,
    "epss": 0.42,
    "exploit": True,
    "package": "openssl",
    "installed": "1.0.2k",
    "fixed": None,
    "fix_available": "NO",
    "scanner": "aws-inspector",
}


def _where(i: int, text: str) -> dict[str, Any]:
    """A resource as a by-resource block or the named list shows it."""
    return {
        "name": f"{text}-{i}" if i % 4 else None,
        "uid": f"arn:aws:ec2:us-east-1:123456789012:instance/i-{i:017x}",
        "account": text,
        "account_id": "123456789012",
        "region": "us-east-1" if i % 3 else None,
        "type": "aws_ec2_instance",
        "type_words": text,
        "vpc_id": "vpc-0abc" if i % 2 else None,
    }


def _chips(text: str) -> list[dict[str, Any]]:
    return [
        {"severity": "critical", "letter": "C", "count": 2},
        {"severity": text, "letter": "x", "count": 1},
    ]


def _cve(i: int, text: str, *, described: bool) -> dict[str, Any]:
    return {
        "severity": SEVERITIES[i % 5],
        "tool": "vulnerabilities",
        "check_id": f"check_{i}",
        "title": text,
        "first_seen": "2026-10-01",
        "facts": dict(FACTS, package=text),
        "description": f"{text} " * 4 if described else None,
    }


def sample(kind: str, *, blocks: int, rows: int, text: str, others: int = 1) -> dict[str, Any]:
    """A context in the shape argus.reports.pdf.build_context makes (problems.build_context for
    the by-resource kind), every string set to text."""
    if kind == "resource-problems":
        return sample_problems(blocks=blocks, rows=rows, text=text, others=others)
    per_block = max(rows // max(blocks, 1), 1)
    base = {
        "report_id": 7,
        "kind": kind,
        "requested_by": text,
        "generated_at": "2026-11-11 12:00",
        "scope": text,
        "total": blocks * per_block * 3,
        "listed": blocks * per_block,
        "truncated": True,
        "data_through": "2026-11-10",
        "data_through_differs": True,
        "account_names": [text, "prod"],
        "severities": [{"severity": s, "count": 3, "in_scope": s != "low"} for s in SEVERITIES],
        "by_account": [
            {
                "name": text,
                "account_id": "123456789012",
                "findings": 9,
                "data_through": None,
                "regions": [{"region": text, "findings": 7}, {"region": None, "findings": 2}],
                "more_regions": 3,
            }
        ],
        "more_accounts": 2,
        "by_type": [
            {
                "type": text if i == 0 else f"AwsType{i}",
                "words": text,
                "resources": 4,
                "counts": [3, 0, 2, 0, 1],
                "total": 6,
            }
            for i in range(25 if rows else 1)
        ],
        "more_types": 3,
        "shares": [
            {"severity": "critical", "x": 0, "width": 189, "percent": 18.9},
            {"severity": "high", "x": 189, "width": 324, "percent": 32.4},
            {"severity": "medium", "x": 513, "width": 297, "percent": 29.7},
            {"severity": "informational", "x": 810, "width": 190, "percent": 19.0},
        ],
        "resources": max(rows, 1) * 2,
        "common": [
            {
                "severity": SEVERITIES[i % 5],
                "title": text,
                "tool": "prowler",
                "check_id": f"check_{i}",
                "resources": 40 - i,
                "accounts": 2,
            }
            for i in range(min(blocks, 10))
        ],
    }
    if kind == "vulnerabilities":  # by resource (owner, 2026-11-20)
        return {
            **base,
            "caps": {"per_block": 40, "total": 5000, "blocks": 300},
            "blocks": [
                {
                    **_where(b, text),
                    "chips": _chips(text),
                    "total": per_block * 2,
                    "lines": [
                        _cve(b * per_block + i, text, described=bool(i % 2))
                        for i in range(per_block)
                    ],
                    "more": per_block,
                }
                for b in range(blocks)
            ],
            "others": [
                {**_where(i, text), "chips": _chips(text), "total": 3} for i in range(others)
            ],
            "more_others": 7 if others else 0,
        }

    def row(i: int) -> dict[str, Any]:
        return {
            "account": text,
            "account_id": "123456789012",
            "region": "us-east-1",
            "type": "AwsEc2Instance",
            "type_words": text,
            "name": f"{text}-{i}",
            "uid": f"arn:aws:ec2:us-east-1:123456789012:instance/i-{i:017x}",
            "result": None if i % 3 == 0 else f"{text} " * 3,
            "first_seen": "2026-10-01",
        }

    return {
        **base,
        "caps": {"per_block": 25, "total": 5000},
        "blocks": [
            {
                "tool": "prowler",
                "check_id": f"check_{b}",
                "title": text,
                "severity": SEVERITIES[b % 5],
                "count": per_block * 3,
                "resources": per_block * 3,
                "accounts": 2,
                "risk": f"{text} " * 20 if b % 3 else None,
                "description": text,
                "fix": text,
                "fix_link": "javascript:alert(1)" if b == 1 else "https://docs.aws.amazon.com/",
                "code": [{"label": "CLI", "text": f"aws ec2 modify --name '{text}'"}],
                "rows": [row(b * per_block + i) for i in range(per_block)],
                "more": per_block * 2,
            }
            for b in range(blocks)
        ],
        "others": [
            {
                "severity": "low",
                "check_id": f"check_x{i}",
                "title": text,
                "count": 1,
                "tool": "prowler",
            }
            for i in range(others)
        ],
        "more_others": 7 if others else 0,
    }


def sample_problems(*, blocks: int, rows: int, text: str, others: int) -> dict[str, Any]:
    """A by-resource context (argus.reports.problems.build_context), every string set to text."""
    base = sample("misconfigurations", blocks=0, rows=0, text=text, others=0)
    per = max(rows // max(blocks, 1), 1)
    chips = _chips(text)

    def problem(i: int) -> dict[str, Any]:
        return {
            "severity": SEVERITIES[i % 5],
            "tool": "prowler",
            "check_id": f"check_{i}",
            "title": text,
            "result": f"{text} " * 3,
            "first_seen": "2026-10-01",
            "facts": None,
        }

    return {
        **base,
        "kind": "resource-problems",
        "total": blocks * per * 2,
        "listed": blocks * per,
        "caps": {"per_block": 40, "total": 5000, "blocks": 300},
        "by_source": {"misconfiguration": [2, 3, 1, 0, 0], "vulnerability": [1, 0, 4, 0, 1]},
        "by_type": [{**t, "misconfigurations": 4, "vulnerabilities": 2} for t in base["by_type"]],
        "blocks": [
            {
                **_where(b, text),
                "chips": {"misconfiguration": chips, "vulnerability": chips[:1]},
                "total": per * 2,
                "misconfigurations": [problem(b * per + i) for i in range((per + 1) // 2)],
                "vulnerabilities": [
                    _cve(b * per + i, text, described=False) for i in range(per // 2)
                ],
                "more": per,
            }
            for b in range(blocks)
        ],
        "reference": [
            {
                "tool": "vulnerabilities" if r % 2 else "prowler",
                "check_id": f"check_{r}",
                "title": text,
                "severity": SEVERITIES[r % 5],
                "resources": 3,
                "risk": None if r % 2 else f"{text} " * 20,
                "description": text,
                "fix": text,
                "fix_link": "javascript:alert(1)" if r == 1 else "https://docs.aws.amazon.com/",
                "code": [{"label": "CLI", "text": f"aws ec2 modify --name '{text}'"}],
                "facts": dict(FACTS) if r % 2 else None,
            }
            for r in range(min(blocks, 300))
        ],
        "more_reference": 2,
        "others": [
            {
                **_where(i, text),
                "chips": chips,
                "total": 3,
                "misconfigurations": 2,
                "vulnerabilities": 1,
            }
            for i in range(others)
        ],
        "more_others": 7 if others else 0,
    }


class SelfTestError(Exception):
    pass


def _check(ok: bool, message: str) -> None:
    """The self-test's assertion, which python -O cannot remove."""
    if not ok:
        raise SelfTestError(message)


def self_test() -> None:
    for name in TEMPLATES.iterdir():
        body = name.read_text()
        _check("|safe" not in body.replace(" ", ""), f"{name.name} marks a value safe")
        _check("autoescape" not in body, f"{name.name} changes autoescaping")
    for kind in KINDS:
        html = render_html(sample(kind, blocks=4, rows=40, text=HOSTILE))
        _check("<script>" not in html and "<img src=http" not in html, "a value reached the markup")
        _check("&lt;script&gt;alert(1)&lt;/script&gt;" in html, "a value was not escaped")
        _check("url(file:///etc/passwd)" not in _styles(html), "a value reached the styles")
        _check('href="javascript:' not in html, "a link other than http(s) reached the markup")
        _, pages, refused = render_pdf(html)
        _check(refused == [], f"the renderer was asked to fetch {refused}")
        _check(pages >= 3, f"{kind}: {pages} pages")
        bad = sample(kind, blocks=1, rows=1, text="x")
        for shares in (
            [{"severity": "critical", "x": 0, "width": "100%", "percent": 1}],
            [{"severity": "critical", "x": 0, "width": 999, "percent": 1}],
            [{"severity": HOSTILE, "x": 0, "width": 1000, "percent": 1}],
        ):
            try:
                render_html({**bad, "shares": shares})
            except ValueError:
                continue
            raise SelfTestError(f"a share bar of {shares!r} was drawn")
        empty = sample(kind, blocks=0, rows=0, text="none")
        empty = {**empty, "total": 0, "listed": 0, "shares": []}
        _, empty_pages, _ = render_pdf(render_html(empty))
        _check(empty_pages >= 2, f"{kind} empty: {empty_pages} pages")
    print("self-test passed")


def _styles(html: str) -> str:
    start, end = html.find("<style>"), html.find("</style>")
    return html[start:end]


def measure() -> None:
    for kind in KINDS:
        started = time.perf_counter()
        context = sample(kind, blocks=300, rows=5000, text="prod-web-instance " * 3, others=1000)
        pdf, pages, _ = render_pdf(render_html(context))
        seconds = time.perf_counter() - started
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
        size = len(pdf) / 1e6
        print(f"{kind}: {pages} pages, {size:.2f} MB in {seconds:.1f} s; peak {peak:.0f} MiB")


def main(argv: list[str]) -> int:
    limit()
    if argv == ["--self-test"]:
        self_test()
        return 0
    if argv == ["--measure"]:
        measure()
        return 0
    if argv:
        print("usage: render.py [--self-test | --measure]", file=sys.stderr)
        return 2
    context = json.load(sys.stdin)
    pdf, pages, refused = render_pdf(render_html(context))
    Path(os.environ["HOME"], "out").write_bytes(pdf)
    print(f"pages={pages} refused={len(refused)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
