# depwatch

depwatch looks at the dependencies in a Python project and tells you which ones are actually worth worrying about.

## The problem

A normal project pulls in dozens or hundreds of open-source packages. You install them once and forget about them. But some are abandoned, some are maintained by a single person who has moved on, and some have known security holes. You usually only find out when something breaks. Nothing makes it easy to look at a `requirements.txt` and see where the real risk is.

## What it does

You give it a `requirements.txt`. It collects public data about every dependency — known vulnerabilities, how recently it was released, how many people maintain it, how widely it is used, and its license — and turns that into one risk score per package. Then it ranks them, so the few that need your attention sit at the top instead of being buried in a list of a hundred.

## Why this one

Most tools that do something like this either cost money or check a single repository at a time. depwatch reads your whole dependency list in one go, runs on public data, and is free.

## Installing it

From source, with [uv](https://docs.astral.sh/uv/):

```
git clone https://github.com/Tim-tran1406/depwatch
cd depwatch
uv sync
```

That gives you the `depwatch` command inside the project's environment (`uv run depwatch ...`). Once it is published to PyPI you will also be able to `pip install depwatch`.

## Using it

Point it at a requirements file:

```
depwatch scan requirements.txt
```

You get a short report with the riskiest packages at the top and the one finding that drives each one:

```
╭─ depwatch ──────────────────────────────────────────────────╮
│ Scanned 13 package(s) from requirements.txt                  │
│ 1 high-risk  ·  top risk driver: vulnerabilities  ·  scan #1 │
╰──────────────────────────────────────────────────────────────╯
 #  Package       Version  Type        Risk           Key finding
 1  urllib3       1.26.5   direct      HIGH      0.35  11 known vulnerabilities
 2  itsdangerous  2.2.0    transitive  MODERATE  0.24  last released 794 days ago
 3  requests      2.31.0   direct      MODERATE  0.24  3 known vulnerabilities
7 package(s) look low-risk.
```

Healthy packages are not listed one by one — they are summarised, so the focus stays on the few that matter.

A few options:

- `--format {table,json,markdown,html,sarif}` — choose the output. `json` is handy for piping into other tools; `html` produces a self-contained page; `sarif` is what GitHub code scanning reads.
- `--output report.html` — write the report to a file instead of the screen.
- `--limit 20` — show more of the risky packages.
- `--fail-on {off,moderate,high,critical}` — exit with an error when the worst package reaches that band. This is what makes it useful in CI.
- `--no-save` — do not record the scan in the local database.

Every scan is saved to a small DuckDB database (`data/depwatch.duckdb`) so you can keep a history of runs.

## In your CI

depwatch ships as a GitHub Action, so it can check dependencies on every pull request and block one that adds a risky package. Add this to a workflow:

```yaml
permissions:
  contents: read
  security-events: write   # lets depwatch post findings to code scanning

jobs:
  depwatch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Tim-tran1406/depwatch@v1
        with:
          requirements: requirements.txt
          fail-on: high
```

It does three things: uploads each risky dependency to code scanning, so it shows up as an inline annotation on the pull request and in the Security tab; writes a table of the risky dependencies into the run summary; and fails the check if anything reaches the `fail-on` band (set `fail-on: off` to report without blocking). Code scanning is free on public repositories.

## How the score works

Each package is scored from 0 (safe) to 1 (risky) on five signals:

- **Vulnerabilities** — known security advisories against the pinned version.
- **Maintenance** — how long since the last release.
- **Bus factor** — how many people contribute, since a single maintainer is fragile.
- **Adoption** — how widely it is downloaded.
- **License** — permissive, copyleft, unusual, or missing.

The overall score is a weighted blend of the five. That means one bad signal is deliberately diluted by the others, so the score is a broad measure of health rather than a single alarm. The specific finding — for example "11 known vulnerabilities" — is always shown next to the package, so nothing important hides behind the average.

Vulnerabilities get one exception: a package with a known high- or critical-severity vulnerability is floored at that risk level, because a known exploit should not be hidden by otherwise-good health. Severity comes from the real CVSS score of each advisory, not a flat guess.

## A shareable report

`--format html` builds a single self-contained page (styles included, nothing external to host). A GitHub Pages workflow generates this for the sample project and publishes it; to use it on your own repository, enable Pages once under **Settings → Pages → Source: "GitHub Actions"**.

## Where the data comes from

All of it is public and free, with no account required:

- [deps.dev](https://deps.dev) — the dependency graph, licenses, advisories and project signals.
- [OSV.dev](https://osv.dev) — known vulnerabilities.
- [PyPI](https://pypi.org) — release dates and metadata.
- [pypistats.org](https://pypistats.org) — download counts.
- [GitHub](https://github.com) — contributor counts. Works without a token; set `DEPWATCH_GITHUB_TOKEN` to raise the rate limit on large projects.

## Developing

```
uv sync
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy src
uv run pytest
```

The test suite stubs out the network, so it is fast and deterministic; a separate live check exercises the real APIs.

## License

MIT. See [LICENSE](LICENSE).
