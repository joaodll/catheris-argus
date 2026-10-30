# CatherIs Argus documentation

**Owner:** `documentation-writer` · each page names its own owner

Start with the page for what you want to do.

| You want to | Read |
| --- | --- |
| See what Argus does, on your own machine, with synthetic data | [Getting started](getting-started.md) |
| Run it on one host with Docker Compose | [Runbook: Docker Compose](runbook.md) |
| Run it on Kubernetes with the Helm chart | [Runbook: Kubernetes](runbook-kubernetes.md) |
| Scan your AWS accounts | [Connecting AWS accounts](connect-aws.md) |
| Look up an environment variable, a setting or a chart value | [Configuration](configuration.md) |
| Judge whether Argus is safe to run, and how it protects what it holds | [Security model](security-model.md) |
| Understand how it is built and why | [Design](design.md) and the [architecture decision records](adr/README.md) |
| Contribute a change | [CONTRIBUTING.md](../CONTRIBUTING.md) |
| Report a vulnerability | [SECURITY.md](../SECURITY.md) |

## The engineering record

These pages are the working record of how Argus was built. They are kept as written, dated, so
you can follow why things are the way they are. They are accurate about decisions and history,
but they are not user guides. They also refer to the roles and the build process the project
uses (for example, the "owner skill" named on each page).

| Folder | What it holds |
| --- | --- |
| [`design.md`](design.md) | The single design document: goals, data model, rules, security, deployment, roadmap, risks |
| [`adr/`](adr/README.md) | One record per decision that is expensive to reverse, with the options rejected and what would justify revisiting it |
| [`gates/`](gates/) | Each phase's exit check: the procedure and its result |
| [`spikes/`](spikes/) | Time-boxed investigations, such as learning a tool's output format |
| [`ui/`](ui/) | The design system and the specification of every screen |
