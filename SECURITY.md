# Security policy

Argus holds a map of how to attack the clouds it scans, and credentials to read them. Security
reports are taken seriously.

## Reporting a vulnerability

Report it privately, through GitHub: on the repository's **Security** tab, choose **Report a
vulnerability**. **Do not open a public issue or pull request** for a vulnerability.

Please include:

- what is affected (component, file, version or commit)
- how to reproduce it, with the steps or a proof of concept
- what an attacker gains
- any fix you suggest

## What to expect

Argus is maintained by one person, so these are best-effort targets:

- an acknowledgement within 7 days
- an assessment, and a plan or a fix, within 30 days for a confirmed issue
- credit in the fix's release notes, unless you prefer otherwise

Please give a reasonable time to fix the issue before you disclose it.

## Supported versions

Argus is pre-1.0. Security fixes go to the `main` branch, and to the latest release once releases
are published.

## Scope

**In scope:**

- any way to make Argus write to, or act on, a scanned cloud account
- exposure of a stored credential, an ExternalId, or a secret value found while scanning
- bypassing sign-in, the session, CSRF protection or the sign-in limits
- reading or changing data through the API without the right session
- escaping the fixed scan Job templates on Kubernetes, or a NetworkPolicy gap in the chart
- the supply chain of the images this repository builds

**Out of scope:** vulnerabilities in Prowler, CloudFox or Steampipe themselves; please report those
to their projects. If one of them is reachable through Argus in a way the tool's authors did not
intend, that part is in scope.

## How Argus is protected

The [security model](docs/security-model.md) describes what Argus guarantees, how, and its known
limits.
