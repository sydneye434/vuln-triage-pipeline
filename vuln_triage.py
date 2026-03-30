#!/usr/bin/env python3
"""
Vulnerability triage: ingest Trivy and SonarQube JSON, normalize, deduplicate,
categorize for pipeline/backlog, and emit JSON + Markdown reports.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Normalized schema (single internal representation for all tools)
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    """Unified severity so triage rules compare apples to apples."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class TriageCategory(str, Enum):
    """
    Pipeline and backlog semantics:

    BLOCK — Fail CI/CD: only when severity is critical or high AND a fix exists.
    We deliberately do not block on unfixed critical/high issues because the
    pipeline cannot remediate them automatically; those go to TRACK for owners.

    TRACK — Backlog / sprint: high without a fix (still urgent), medium with a
    fix (actionable improvement), and medium without a fix (not listed in the
    spec but treated as backlog-worthy between IGNORE and BLOCK tiers).

    IGNORE — Noise for gating: low and informational findings; still logged for
    audit and optional dashboards.
    """

    BLOCK = "BLOCK"
    TRACK = "TRACK"
    IGNORE = "IGNORE"


@dataclass(frozen=True)
class NormalizedFinding:
    tool: str
    severity: Severity
    title: str
    location: str
    cve_id: str | None
    fix_available: bool
    description: str
    # Provenance for debugging and Markdown (not part of dedup identity)
    source_refs: dict[str, Any] = field(default_factory=dict)


def _truncate(text: str, max_len: int = 4000) -> str:
    text = text.strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _normalize_severity_trivy(raw: str | None) -> Severity:
    if not raw:
        return Severity.UNKNOWN
    m = raw.strip().upper()
    mapping = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "UNKNOWN": Severity.UNKNOWN,
    }
    return mapping.get(m, Severity.UNKNOWN)


def _normalize_severity_sonar(raw: str | None) -> Severity:
    """
    Sonar uses BLOCKER, CRITICAL, MAJOR, MINOR, INFO.
    Map to coarse buckets aligned with triage expectations.
    """
    if not raw:
        return Severity.UNKNOWN
    m = raw.strip().upper()
    mapping = {
        "BLOCKER": Severity.CRITICAL,
        "CRITICAL": Severity.CRITICAL,
        "MAJOR": Severity.HIGH,
        "MINOR": Severity.MEDIUM,
        "INFO": Severity.INFO,
    }
    return mapping.get(m, Severity.UNKNOWN)


# ---------------------------------------------------------------------------
# Triage rules (single place to change policy)
# ---------------------------------------------------------------------------


def categorize_finding(f: NormalizedFinding) -> TriageCategory:
    """
    Apply bucket rules from product/security policy:

    BLOCK:
      critical or high severity AND fix_available.
      Rationale: pipeline gate should only fail when automation can apply or
      verify a fix; otherwise teams get red builds with no remediation path.

    TRACK:
      - high severity without fix (still needs owner attention),
      - medium with fix (backlog remediation),
      - critical without fix (same as high without fix — urgent TRACK),
      - medium without fix (not in the one-line spec; we TRACK so medium
        issues are not silently dropped between HIGH and LOW).

    IGNORE:
      low, info, and unknown severities (treated as non-gating noise).
    """
    sev = f.severity
    fix = f.fix_available

    if sev in (Severity.LOW, Severity.INFO):
        return TriageCategory.IGNORE

    if sev == Severity.UNKNOWN:
        return TriageCategory.IGNORE

    # Critical / High
    if sev in (Severity.CRITICAL, Severity.HIGH):
        if fix:
            return TriageCategory.BLOCK
        return TriageCategory.TRACK

    # Medium
    if sev == Severity.MEDIUM:
        return TriageCategory.TRACK

    return TriageCategory.IGNORE


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

CVE_RE = re.compile(
    r"\bCVE-\d{4}-\d{4,}\b",
    re.IGNORECASE,
)


def extract_cve_from_text(text: str) -> str | None:
    m = CVE_RE.search(text or "")
    if not m:
        return None
    return m.group(0).upper()


def dedup_key(f: NormalizedFinding) -> str:
    """
    Prefer CVE-based identity so the same vulnerability from Trivy (image) and
    Trivy (fs) or repeated Sonar references collapses to one row.

    If no CVE, hash stable title + location + tool-agnostic fingerprint so
    identical SAST issues across branches still merge when the scanner repeats.
    """
    if f.cve_id:
        return f"cve:{f.cve_id.strip().upper()}"

    loc = f.location.strip().lower()
    title = f.title.strip().lower()
    payload = f"{title}|{loc}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return f"fp:{digest}"


def merge_findings(a: NormalizedFinding, b: NormalizedFinding) -> NormalizedFinding:
    """
    When two records share a dedup key, keep the higher severity, OR fix if
    either scan proves a fix path, and concatenate provenance.
    """
    order = {
        Severity.UNKNOWN: 0,
        Severity.INFO: 1,
        Severity.LOW: 2,
        Severity.MEDIUM: 3,
        Severity.HIGH: 4,
        Severity.CRITICAL: 5,
    }
    sev = a.severity if order[a.severity] >= order[b.severity] else b.severity
    fix = a.fix_available or b.fix_available
    tools = {a.tool, b.tool}
    merged_refs = {
        "merged_from": sorted(tools),
        "sources": [a.source_refs, b.source_refs],
    }
    title = a.title if len(a.title) >= len(b.title) else b.title
    desc = _truncate(f"{a.description}\n---\n{b.description}", 8000)
    loc = a.location if len(a.location) <= len(b.location) else b.location
    cve = a.cve_id or b.cve_id
    return NormalizedFinding(
        tool=",".join(sorted(tools)),
        severity=sev,
        title=title,
        location=loc,
        cve_id=cve,
        fix_available=fix,
        description=desc,
        source_refs=merged_refs,
    )


def deduplicate(findings: Iterable[NormalizedFinding]) -> list[NormalizedFinding]:
    buckets: dict[str, NormalizedFinding] = {}
    for f in findings:
        k = dedup_key(f)
        if k not in buckets:
            buckets[k] = f
        else:
            buckets[k] = merge_findings(buckets[k], f)
    return list(buckets.values())


# ---------------------------------------------------------------------------
# Trivy JSON (container image, filesystem, repo — SchemaVersion 2 Results[])
# ---------------------------------------------------------------------------


def _trivy_vuln_to_finding(
    vuln: dict[str, Any],
    target: str,
    pkg_name: str | None,
) -> NormalizedFinding | None:
    vid = vuln.get("VulnerabilityID") or vuln.get("vulnerabilityID")
    cve = vid if vid and str(vid).upper().startswith("CVE-") else None
    if not cve:
        cve = extract_cve_from_text(str(vuln.get("Title", "") + " " + str(vuln.get("Description", ""))))

    fixed = vuln.get("FixedVersion") or vuln.get("fixedVersion")
    fix_available = bool(fixed and str(fixed).strip())

    title = vuln.get("Title") or vuln.get("VulnerabilityID") or "Trivy vulnerability"
    desc = vuln.get("Description") or ""
    pkg = pkg_name or vuln.get("PkgName") or ""
    loc = f"{target} ({pkg})" if pkg else target

    return NormalizedFinding(
        tool="trivy",
        severity=_normalize_severity_trivy(vuln.get("Severity")),
        title=str(title),
        location=loc,
        cve_id=cve,
        fix_available=fix_available,
        description=_truncate(str(desc)),
        source_refs={"target": target, "package": pkg, "raw_id": vid},
    )


def _trivy_misconfig_to_finding(
    mc: dict[str, Any],
    target: str,
) -> NormalizedFinding | None:
    tid = mc.get("ID") or mc.get("id") or "misconfiguration"
    title = mc.get("Title") or tid
    desc = mc.get("Description") or ""
    sev = _normalize_severity_trivy(mc.get("Severity"))
    # Misconfigs: "fixed" if resolution or status implies pass after change
    fix_available = bool(mc.get("Resolution") or mc.get("CauseMetadata"))

    return NormalizedFinding(
        tool="trivy",
        severity=sev,
        title=str(title),
        location=str(target),
        cve_id=None,
        fix_available=fix_available,
        description=_truncate(str(desc)),
        source_refs={"misconfig_id": tid, "target": target},
    )


def parse_trivy_json(data: dict[str, Any], path: str) -> list[NormalizedFinding]:
    out: list[NormalizedFinding] = []
    results = data.get("Results") or data.get("results") or []
    for res in results:
        target = res.get("Target") or res.get("target") or path
        for vuln in res.get("Vulnerabilities") or res.get("vulnerabilities") or []:
            pkg = vuln.get("PkgName")
            f = _trivy_vuln_to_finding(vuln, str(target), pkg)
            if f:
                out.append(f)
        for mc in res.get("Misconfigurations") or res.get("misconfigurations") or []:
            f = _trivy_misconfig_to_finding(mc, str(target))
            if f:
                out.append(f)
    return out


def load_trivy_file(path: Path) -> list[NormalizedFinding]:
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    return parse_trivy_json(data, str(path))


# ---------------------------------------------------------------------------
# SonarQube (issues export / api response with "issues" array)
# ---------------------------------------------------------------------------


def parse_sonarqube_json(data: Any, path: str) -> list[NormalizedFinding]:
    out: list[NormalizedFinding] = []
    if isinstance(data, list):
        issues = data
    else:
        issues = (data or {}).get("issues") or (data or {}).get("Issues") or []

    for issue in issues:
        if not isinstance(issue, dict):
            continue
        msg = issue.get("message") or issue.get("Message") or ""
        comp = issue.get("component") or issue.get("Component") or ""
        line = issue.get("line") or issue.get("Line")
        rule = issue.get("rule") or issue.get("ruleKey") or ""
        sev = _normalize_severity_sonar(issue.get("severity") or issue.get("Severity"))

        loc = f"{comp}"
        if line is not None:
            loc = f"{comp}:{line}"

        cve = extract_cve_from_text(str(msg) + " " + str(rule))
        tags = issue.get("tags") or []
        if isinstance(tags, list) and tags:
            cve = cve or extract_cve_from_text(" ".join(str(t) for t in tags))

        # Sonar: only mark fix when the scanner reports an automated quick fix.
        # Treat missing field as unknown → False so we do not inflate BLOCK counts.
        qf = issue.get("quickFixAvailable")
        fix_available = qf is True

        title = str(msg)[:500] or str(rule) or "SonarQube issue"
        desc_parts = [f"Rule: {rule}", f"Message: {msg}"]
        f = NormalizedFinding(
            tool="sonarqube",
            severity=sev,
            title=title,
            location=loc,
            cve_id=cve,
            fix_available=fix_available,
            description=_truncate("\n".join(desc_parts)),
            source_refs={"file": path, "key": issue.get("key")},
        )
        out.append(f)
    return out


def load_sonarqube_file(path: Path) -> list[NormalizedFinding]:
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    return parse_sonarqube_json(data, str(path))


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def findings_to_json_serializable(findings: list[NormalizedFinding]) -> list[dict[str, Any]]:
    rows = []
    for f in findings:
        d = asdict(f)
        d["severity"] = f.severity.value
        rows.append(d)
    return rows


def build_report(
    findings: list[NormalizedFinding],
    inputs: dict[str, list[str]],
) -> dict[str, Any]:
    by_cat: dict[str, list[NormalizedFinding]] = {
        TriageCategory.BLOCK.value: [],
        TriageCategory.TRACK.value: [],
        TriageCategory.IGNORE.value: [],
    }
    for f in findings:
        cat = categorize_finding(f)
        by_cat[cat.value].append(f)

    # Sort BLOCK/TRACK by severity then title for stable, reviewer-friendly output
    order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
        Severity.UNKNOWN: 5,
    }

    def sort_key(x: NormalizedFinding) -> tuple[int, str]:
        return (order.get(x.severity, 99), x.title.lower())

    for k in by_cat:
        by_cat[k].sort(key=sort_key)

    blockers = [f for f in by_cat[TriageCategory.BLOCK.value]]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inputs": inputs,
        "summary": {
            "total_unique": len(findings),
            TriageCategory.BLOCK.value: len(by_cat[TriageCategory.BLOCK.value]),
            TriageCategory.TRACK.value: len(by_cat[TriageCategory.TRACK.value]),
            TriageCategory.IGNORE.value: len(by_cat[TriageCategory.IGNORE.value]),
        },
        "pipeline_blocking_issues": findings_to_json_serializable(blockers),
        "findings_by_category": {
            TriageCategory.BLOCK.value: findings_to_json_serializable(by_cat[TriageCategory.BLOCK.value]),
            TriageCategory.TRACK.value: findings_to_json_serializable(by_cat[TriageCategory.TRACK.value]),
            TriageCategory.IGNORE.value: findings_to_json_serializable(by_cat[TriageCategory.IGNORE.value]),
        },
        "all_findings_deduplicated": findings_to_json_serializable(findings),
    }


def render_markdown(report: dict[str, Any]) -> str:
    s = report["summary"]
    lines: list[str] = []
    lines.append("# Vulnerability triage summary\n")
    lines.append(f"Generated: `{report['generated_at']}`\n")

    lines.append("## Inputs\n")
    for label, paths in report["inputs"].items():
        lines.append(f"- **{label}**: {', '.join(paths) if paths else '(none)'}\n")

    lines.append("## Counts by category\n")
    lines.append("| Category | Count | Meaning |")
    lines.append("|----------|-------|---------|")
    lines.append(f"| BLOCK | {s['BLOCK']} | Critical/High with fix — fail pipeline |")
    lines.append(f"| TRACK | {s['TRACK']} | High without fix, medium (backlog) |")
    lines.append(f"| IGNORE | {s['IGNORE']} | Low/Info — log only |")
    lines.append("")
    lines.append(f"**Unique findings (after dedup):** {s['total_unique']}\n")

    lines.append("## Pipeline-blocking issues (BLOCK)\n")
    blockers = report["pipeline_blocking_issues"]
    if not blockers:
        lines.append("*None — pipeline would not be failed on vulnerability gates.*\n")
    else:
        lines.append("| Severity | Title | Location | CVE | Tool |")
        lines.append("|----------|-------|----------|-----|------|")
        for row in blockers:
            cve = row.get("cve_id") or "—"
            title = str(row["title"]).replace("|", "\\|")
            loc = str(row["location"]).replace("|", "\\|")
            lines.append(
                f"| {row['severity']} | {title} | {loc} | {cve} | {row['tool']} |"
            )
        lines.append("")

    lines.append("## Prioritized remediation table (BLOCK + TRACK)\n")
    combined = (
        report["findings_by_category"]["BLOCK"]
        + report["findings_by_category"]["TRACK"]
    )
    if not combined:
        lines.append("*No BLOCK or TRACK findings.*\n")
    else:
        lines.append("| Category | Severity | Fix? | Title | Location | CVE | Tool |")
        lines.append("|----------|----------|------|-------|----------|-----|------|")
        for cat in ("BLOCK", "TRACK"):
            for row in report["findings_by_category"][cat]:
                cve = row.get("cve_id") or "—"
                fix = "yes" if row.get("fix_available") else "no"
                title = str(row["title"]).replace("|", "\\|")
                loc = str(row["location"]).replace("|", "\\|")
                lines.append(
                    f"| {cat} | {row['severity']} | {fix} | {title} | {loc} | {cve} | {row['tool']} |"
                )
        lines.append("")

    lines.append("## Full JSON\n")
    lines.append("Structured data is written to `vuln_triage_report.json` in the output directory.\n")
    return "\n".join(lines)


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Normalize Trivy + SonarQube scans, deduplicate, triage, emit reports.",
    )
    p.add_argument(
        "--trivy",
        action="append",
        default=[],
        metavar="FILE",
        help="Trivy JSON report (repeatable). Container or filesystem scan output.",
    )
    p.add_argument(
        "--sonarqube",
        action="append",
        default=[],
        metavar="FILE",
        help="SonarQube JSON (issues export or API-shaped document). Repeatable.",
    )
    p.add_argument(
        "--output-dir",
        "-o",
        required=True,
        type=Path,
        help="Directory for vuln_triage_report.json and vuln_triage_summary.md",
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Debug logging",
    )
    return p.parse_args(argv)


def collect_findings(trivy_paths: list[str], sonar_paths: list[str]) -> list[NormalizedFinding]:
    all_findings: list[NormalizedFinding] = []
    for raw in trivy_paths:
        p = Path(raw)
        if not p.is_file():
            raise FileNotFoundError(f"Trivy file not found: {p}")
        LOG.info("Parsing Trivy: %s", p)
        all_findings.extend(load_trivy_file(p))
    for raw in sonar_paths:
        p = Path(raw)
        if not p.is_file():
            raise FileNotFoundError(f"SonarQube file not found: {p}")
        LOG.info("Parsing SonarQube: %s", p)
        all_findings.extend(load_sonarqube_file(p))
    return all_findings


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )
    out_dir: Path = args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    trivy_paths = list(args.trivy or [])
    sonar_paths = list(args.sonarqube or [])
    if not trivy_paths and not sonar_paths:
        LOG.error("Provide at least one --trivy or --sonarqube input file.")
        return 2

    findings = collect_findings(trivy_paths, sonar_paths)
    LOG.info("Loaded %s raw findings", len(findings))

    deduped = deduplicate(findings)
    LOG.info("After deduplication: %s unique findings", len(deduped))

    inputs = {
        "trivy": [str(Path(p).resolve()) for p in trivy_paths],
        "sonarqube": [str(Path(p).resolve()) for p in sonar_paths],
    }
    report = build_report(deduped, inputs)

    json_path = out_dir / "vuln_triage_report.json"
    md_path = out_dir / "vuln_triage_summary.md"

    with json_path.open("w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    LOG.info("Wrote %s", json_path)

    md = render_markdown(report)
    with md_path.open("w", encoding="utf-8") as fh:
        fh.write(md)
    LOG.info("Wrote %s", md_path)

    # Non-zero exit if pipeline should fail (BLOCK present)
    block_count = report["summary"][TriageCategory.BLOCK.value]
    if block_count:
        LOG.warning("BLOCK findings: %s — exiting with code 1 for pipeline gate", block_count)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
