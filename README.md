# Vulnerability Triage Pipeline

`vuln_triage.py` takes machine-readable output from **Trivy** (container or filesystem JSON) and **SonarQube** (issues JSON), maps everything into one normalized finding shape, deduplicates overlapping hits (especially by CVE), and assigns each finding to **BLOCK**, **TRACK**, or **IGNORE**. It writes a JSON report plus a Markdown summary suitable for humans and for CI gates. The problem it solves is repeated, incompatible scan formats across tools: you get one prioritized remediation view and a single policy for when the pipeline should fail versus when work should land in a backlog.

## Triage logic

Classifications are applied after normalization. **Severity** comes from the tool (Trivy severities as-is; Sonar **BLOCKER** and **CRITICAL** map to critical, **MAJOR** to high, **MINOR** to medium, **INFO** to info). **Fix availability** is conservative: for Trivy CVE rows, a non-empty **FixedVersion** counts as a fix; for SonarQube, **`quickFixAvailable: true`** counts as a fix (missing or false means no automated fix signal for gating).

| Category | When it applies | Typical use |
|----------|-----------------|-------------|
| **BLOCK** | **Critical or high** severity **and** a fix is considered available. | Fail the pipeline so releases do not ship while fixable critical/high issues remain. |
| **TRACK** | **Critical or high without** a fix signal; **all medium** severities (with or without fix). | Backlog, sprint work, or POA&M-style tracking—urgent but not an automatic gate if the tool cannot point at a fix. |
| **IGNORE** | **Low**, **info**, and **unknown** severities. | Logged in the report for audit and dashboards; not used to fail the gate. |

The script exits **1** if there is at least one **BLOCK** finding (for CI integration). It exits **0** if there are only **TRACK** and/or **IGNORE** findings.

Deduplication prefers **CVE identity** when present so the same vulnerability from multiple scans collapses to one row; otherwise a stable fingerprint of title and location is used.

## Sample Markdown output

The job writes `vuln_triage_summary.md` next to `vuln_triage_report.json`. The Markdown is representative of what you will see in practice (values below are illustrative):

```markdown
# Vulnerability triage summary

Generated: `2026-03-30T20:15:02.123456+00:00`

## Inputs

- **trivy**: /builds/acme/payments-svc/trivy-report.json
- **sonarqube**: /builds/acme/payments-svc/sonarqube-issues.json

## Counts by category

| Category | Count | Meaning |
|----------|-------|---------|
| BLOCK | 2 | Critical/High with fix — fail pipeline |
| TRACK | 7 | High without fix, medium (backlog) |
| IGNORE | 14 | Low/Info — log only |

**Unique findings (after dedup):** 23

## Pipeline-blocking issues (BLOCK)

| Severity | Title | Location | CVE | Tool |
|----------|-------|----------|-----|------|
| high | curl: IPv6 address parser buffer overflow | registry.internal/acme/api:1.9.0 (debian 12) (libcurl4) | CVE-2024-38527 | trivy |
| critical | Deserializing with pickle is insecure | flask-payments-api:src/services/cache_loader.py:61 | — | sonarqube |

## Prioritized remediation table (BLOCK + TRACK)

| Category | Severity | Fix? | Title | Location | CVE | Tool |
|----------|----------|------|-------|----------|-----|------|
| BLOCK | critical | yes | Deserializing with pickle is insecure | flask-payments-api:src/services/cache_loader.py:61 | — | sonarqube |
| BLOCK | high | yes | curl: IPv6 address parser buffer overflow | registry.internal/acme/api:1.9.0 (debian 12) (libcurl4) | CVE-2024-38527 | trivy |
| TRACK | high | no | openssh: slow key exchange allows CPU exhaustion | registry.internal/acme/api:1.9.0 (debian 12) (openssh-client) | CVE-2025-22869 | trivy |
| TRACK | high | no | This URL is built from a user-controlled value | flask-payments-api:src/clients/webhook_client.py:39 | — | sonarqube |
| ... | ... | ... | ... | ... | ... | ... |

## Full JSON

Structured data is written to `vuln_triage_report.json` in the output directory.
```

## Setup and usage

### Requirements

- **Python 3.9+** (stdlib only; no `pip install` required for the script itself.)

### Local run

From the repository root:

```bash
python3 vuln_triage.py \
  --trivy /path/to/trivy-report.json \
  --sonarqube /path/to/sonarqube-issues.json \
  --output-dir ./out
```

You can pass **`--trivy`** multiple times for separate Trivy reports (e.g. image plus filesystem). **`--sonarqube`** is repeatable as well. Outputs:

- `out/vuln_triage_report.json` — full structured report, including `pipeline_blocking_issues` and per-category lists.
- `out/vuln_triage_summary.md` — the Markdown summary.

Use **`-v`** for debug logging.

Example inputs shaped like real tool output live under **`fixtures/`** (see `fixtures/trivy_results.json` and `fixtures/sonarqube_results.json`).

### GitLab CI

This repo includes a drop-in job definition: **`ci/vuln_triage.gitlab-ci.yml`**.

1. Add a **`security_triage`** (or equivalent) stage **after** your Trivy and SonarQube scan jobs.
2. Include the file from **`.gitlab-ci.yml`**:

   ```yaml
   include:
     - local: 'ci/vuln_triage.gitlab-ci.yml'
   ```

3. Rename **`needs:`** entries **`trivy_scan`** and **`sonarqube_scan`** to match your job names.
4. Ensure upstream jobs publish artifacts whose paths match **`VULN_TRIAGE_TRIVY_JSON`** and **`VULN_TRIAGE_SONAR_JSON`** (defaults: `trivy-report.json` and `sonarqube-issues.json`), or override those variables in CI/CD settings.
5. Keep **`vuln_triage.py`** at the repo root or adjust the job’s script.

The job uploads **`vuln_triage_summary.md`** and **`vuln_triage_report.json`** as job artifacts (`when: always` so a failed gate still leaves the reports in the UI). Exit code **1** from the script fails the job when **BLOCK** findings exist.

## DevSecOps, ATO evidence, and DoD continuous monitoring

Scanners such as Trivy and SonarQube produce raw evidence that a system was assessed against known weaknesses and secure coding expectations. That raw output is difficult to use as **authorization package** material unless it is summarized, deduplicated, and tied to a consistent severity and remediation story. This script does not replace an assessor or a POA&M system; it **aggregates** scanner output into a single report that maps cleanly to recurring control narratives: what was found, what blocks release, what is tracked for remediation, and what is informational.

In **DoD / RMF-style** workflows, continuous monitoring (ConMon) expects ongoing visibility into security-relevant changes and defect backlog. A generated **JSON** artifact is easy to archive next to pipeline metadata, attach to a **POA&M** export, or feed dashboards. The **Markdown** summary is what operators and ISSOs actually read during triage. **BLOCK** versus **TRACK** gives you a defensible split between “gate failed because a fixable critical/high issue was present” and “work remains but the pipeline did not pretend an unfixed issue could be auto-resolved.” That distinction matters when you explain scan results to approvers or when you reconcile pipeline history with **ATO** (or continuous ATO) evidence that the program exercised automated security checks on each release.

If you need stricter policy (for example, failing on unfixed critical issues as well), treat this script as the aggregation layer and add an explicit policy step or wrapper that reads `vuln_triage_report.json` and applies organization-specific rules on top.
