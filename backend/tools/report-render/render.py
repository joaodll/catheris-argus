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
KINDS = ("misconfigurations", "vulnerabilities")
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


def render_html(context: dict[str, Any]) -> str:
    kind = context["kind"]
    if kind not in KINDS:
        raise ValueError(f"unknown report kind: {kind!r}")
    env = Environment(
        loader=FileSystemLoader(TEMPLATES),
        autoescape=True,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["num"] = _number
    env.filters["web_link"] = _web_link
    return env.get_template(f"{kind}.html").render(ctx=context)


def render_pdf(html: str) -> tuple[bytes, int, list[str]]:
    fetcher = RefuseAll()
    document = HTML(string=html, base_url=None, url_fetcher=fetcher).render()
    return document.write_pdf(), len(document.pages), fetcher.refused


# ---- fixtures for --self-test and --measure --------------------------------------------------

HOSTILE = "<script>alert(1)</script><img src=http://169.254.169.254/x> url(file:///etc/passwd) \"'&"


def sample(kind: str, *, blocks: int, rows: int, text: str, others: int = 1) -> dict[str, Any]:
    """A context in the shape argus.reports.pdf.build_context makes, every string set to text."""

    def row(i: int) -> dict[str, Any]:
        return {
            "account": text,
            "account_id": "123456789012",
            "region": "us-east-1",
            "type": "aws_ec2_instance",
            "name": f"{text}-{i}",
            "uid": f"arn:aws:ec2:us-east-1:123456789012:instance/i-{i:017x}",
            "first_seen": "2026-10-01",
            "installed": "1.0.2k" if kind == "vulnerabilities" else None,
        }

    per_block = max(rows // max(blocks, 1), 1)
    return {
        "report_id": 7,
        "kind": kind,
        "requested_by": text,
        "generated_at": "2026-11-11 12:00",
        "scope": text,
        "total": blocks * per_block * 3,
        "listed": blocks * per_block,
        "truncated": True,
        "caps": {"per_block": 25, "total": 5000},
        "data_through": "2026-11-10",
        "data_through_differs": True,
        "account_names": [text, "prod"],
        "severities": [{"severity": s, "count": 3, "in_scope": s != "low"} for s in SEVERITIES],
        "by_account": [
            {"name": text, "account_id": "123456789012", "findings": 9, "data_through": None}
        ],
        "more_accounts": 2,
        "by_type": [{"type": text, "findings": 9}],
        "more_types": 0,
        "blocks": [
            {
                "tool": "prowler",
                "check_id": f"check_{b}",
                "title": text,
                "severity": SEVERITIES[b % 5],
                "count": per_block * 3,
                "accounts": 2,
                "risk": f"{text} " * 20 if b % 3 else None,
                "description": text,
                "fix": text,
                "links": ["https://example.com/a"],
                "fix_link": "javascript:alert(1)" if b == 1 else "https://docs.aws.amazon.com/",
                "code": [{"label": "CLI", "text": f"aws ec2 modify --name '{text}'"}],
                "facts": {
                    "cve": "CVE-2026-0001",
                    "cvss": 9.8,
                    "epss": 0.42,
                    "exploit": True,
                    "package": text,
                    "installed": "1.0.2k",
                    "fixed": None,
                    "fix_available": "NO",
                    "scanner": "aws-inspector",
                }
                if kind == "vulnerabilities"
                else None,
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
        empty = sample(kind, blocks=0, rows=0, text="none")
        _, empty_pages, _ = render_pdf(render_html({**empty, "total": 0, "listed": 0}))
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
