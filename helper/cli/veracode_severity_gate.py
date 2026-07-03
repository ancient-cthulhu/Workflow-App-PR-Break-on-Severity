#!/usr/bin/env python3
"""Veracode severity gate.

Parses Veracode scan output and fails the build when findings meet or exceed a
configurable severity threshold, adding severity-based gating on top of the
agent-based SCA scan and the IaC/Secrets scan, which gate on platform policy.

Two modes:
  --mode iac   Parses Veracode CLI `veracode scan --format json` output
               (keys: vulnerabilities.matches[], secrets[], configs[]).
  --mode sca   Parses the agent-based SCA action output. Accepts either the
               text report (scaResults.txt) or the JSON report (scaResults.json).

Threshold accepts a named level (critical|high|medium|low|info) or a CVSS number
in [0, 10]. A number does an exact CVSS comparison where a finding carries a
score, and a band comparison otherwise.

Exit codes:
  0  evaluated successfully, no finding at or above the threshold (or --warn-only)
  1  one or more findings at or above the threshold
  2  the gate could not evaluate (missing/empty/invalid input, invalid
     threshold, or a results-count reconciliation mismatch). Fails closed so a
     broken scan never silently passes. Use --allow-missing to treat a missing
     input file as a pass instead.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

# Exit codes.
EXIT_PASS = 0
EXIT_GATED = 1
EXIT_ERROR = 2

# Rank scale. Higher is more severe. These labels are explicit severity signals.
SIGNAL_RANK: Dict[str, int] = {
    "info": 0, "informational": 0, "none": 0, "negligible": 0,
    "low": 1,
    "medium": 2, "moderate": 2,
    "high": 3,
    "critical": 4, "very high": 4,
}
# Labels that carry no usable signal (escalated to a category floor instead of 0).
NON_SIGNAL_LABELS = {"", "unknown", "undefined", "unassigned"}

RANK_TO_BAND = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}
BANDS = ["critical", "high", "medium", "low", "info"]

# Category floors applied only when a finding has no usable severity signal at
# all (no recognized label and no CVSS). Secrets are inherently sensitive.
FLOOR_SECRET = SIGNAL_RANK["high"]
FLOOR_DEFAULT = SIGNAL_RANK["medium"]

MAX_DETAIL_ROWS = 200


class GateError(Exception):
    """Raised for any condition that prevents a trustworthy evaluation."""


def cvss_to_label(score: Any) -> str:
    """Map a CVSS base score to a qualitative band (CVSS v3 banding)."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "unknown"
    if s != s:  # NaN
        return "unknown"
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0.0:
        return "low"
    return "info"


def label_rank(label: Optional[str]) -> Optional[int]:
    """Rank for an explicit severity label, or None if it carries no signal."""
    key = (label or "").strip().lower()
    if key in NON_SIGNAL_LABELS:
        return None
    return SIGNAL_RANK.get(key)


def cvss_rank(cvss: Any) -> Optional[int]:
    """Rank derived from a CVSS score, or None if no usable score is present."""
    if cvss is None:
        return None
    return SIGNAL_RANK.get(cvss_to_label(cvss))


def sanitize(text: Optional[str], limit: int) -> str:
    """Make a finding string safe for a Markdown table cell and for logs.

    Collapses newlines/tabs (which would split table rows or be parsed as
    workflow commands), neutralizes a leading '::', escapes pipes, truncates.
    """
    s = (text or "")
    s = s.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    s = re.sub(r"\s+", " ", s).strip()
    if s.startswith("::"):
        s = s.replace("::", ": ", 1)
    if len(s) > limit:
        s = s[: limit - 1].rstrip() + "\u2026"
    return s.replace("|", "\\|")


# --------------------------------------------------------------------------- #
# Presentation helpers (paths, links, severity dots)
# --------------------------------------------------------------------------- #
BAND_DOT = {"critical": "\U0001f534", "high": "\U0001f7e0", "medium": "\U0001f7e1",
            "low": "\U0001f535", "info": "\u26aa"}

# Build-system and runner prefixes to strip so a path becomes repo-relative.
_PATH_PREFIXES = [
    re.compile(r"^__w/[^/]+/[^/]+/"),                 # GitHub container runner
    re.compile(r"^home/[^/]+/work/[^/]+/[^/]+/"),     # GitHub hosted runner
    re.compile(r"^github/workspace/"),
    re.compile(r"^runner/work/[^/]+/[^/]+/"),
    re.compile(r"^source-code/"),                     # Veracode packaged root
    re.compile(r"^veracode_artifact_directory/"),
]


def clean_path(path: Optional[str]) -> str:
    """Reduce an absolute build path to a readable, repo-relative one."""
    p = (path or "").replace("\\", "/").strip().lstrip("/")
    if not p or p.upper() == "UNKNOWN":
        return ""
    changed = True
    while changed:
        changed = False
        for pat in _PATH_PREFIXES:
            new = pat.sub("", p)
            if new != p:
                p, changed = new, True
    return p


def github_blob_url(file: str, line: Optional[int]) -> Optional[str]:
    repo = os.environ.get("SCAN_REPO")
    # BLOB_REF (e.g. a branch) overrides HEAD_SHA when the scan's SHA is not a
    # browsable commit (the SAST pipeline dispatch can carry a non-browsable SHA).
    ref = os.environ.get("BLOB_REF") or os.environ.get("HEAD_SHA")
    if not (repo and ref and file):
        return None
    base = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    url = f"{base}/{repo}/blob/{ref}/{file}"
    if line:
        url += f"#L{line}"
    return url


def id_url(ident: Optional[str]) -> Optional[str]:
    s = (ident or "").strip()
    m = re.match(r"^CWE-(\d+)$", s, re.IGNORECASE)
    if m:
        return f"https://cwe.mitre.org/data/definitions/{m.group(1)}.html"
    if re.match(r"^CVE-\d{4}-\d+$", s, re.IGNORECASE):
        return f"https://nvd.nist.gov/vuln/detail/{s.upper()}"
    if re.match(r"^(DS|AVD)[-A-Za-z0-9]*\d", s):
        return f"https://avd.aquasec.com/misconfig/{s.lower()}"
    return None


def _md_link(text: str, url: Optional[str], limit: int) -> str:
    safe = sanitize(text, limit)
    if url and safe:
        return f"[{safe}]({url})"
    return safe


def finding_location_cell(f: "Finding") -> str:
    """A readable, linked location for one finding."""
    if f.file:
        disp = f.file + (f":{f.line}" if f.line else "")
        return _md_link(disp, github_blob_url(f.file, f.line), 80)
    if f.location:
        return sanitize(f.location, 80)
    return "\u2014"  # em dash placeholder for unknown


def finding_id_cell(f: "Finding") -> str:
    return _md_link(f.ident, id_url(f.ident), 40) if f.ident else "\u2014"


def _fetch_tree_paths(api: str, repo: str, ref: str, token: str) -> Dict[str, str]:
    """Map lowercased repo paths to their real-case path, for one ref."""
    try:
        _, data = _gh_request(
            api, "GET", f"/repos/{repo}/git/trees/{ref}?recursive=1", token)
    except Exception:  # noqa: BLE001 - best-effort
        return {}
    out: Dict[str, str] = {}
    for entry in (data.get("tree") or []):
        if entry.get("type") == "blob":
            p = entry.get("path") or ""
            if p:
                out[p.lower()] = p
    return out


def correct_file_cases(findings: Sequence["Finding"]) -> None:
    """Fix finding file paths to the repo's real case so blob links resolve.

    Some scanners (SAST on .NET) report lowercased paths, but GitHub blob URLs
    are case-sensitive. This looks up the actual tree once and rewrites paths.
    Best-effort: on any failure the original paths are kept.
    """
    if not any(f.file for f in findings):
        return
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("SCAN_REPO")
    ref = os.environ.get("BLOB_REF") or os.environ.get("HEAD_SHA")
    if not (token and repo and ref):
        return
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    tree = _fetch_tree_paths(api, repo, ref, token)
    if not tree:
        return
    for f in findings:
        if f.file:
            real = tree.get(f.file.lower())
            if real:
                f.file = real


class Finding:
    __slots__ = ("category", "severity", "ident", "title", "location", "cvss",
                 "floor", "file", "line")

    def __init__(
        self,
        category: str,
        severity: Optional[str],
        ident: Optional[str],
        title: Optional[str],
        location: Optional[str],
        cvss: Any = None,
        floor: int = FLOOR_DEFAULT,
        file: Optional[str] = None,
        line: Optional[int] = None,
    ) -> None:
        self.category = category
        self.severity = severity  # raw; may be None or an unknown string
        self.ident = ident or ""
        self.title = title or ""
        self.location = location or ""
        self.cvss = cvss
        self.floor = floor
        self.file = file or ""      # repo-relative source path, when known
        self.line = line            # 1-based line number, when known

    @property
    def effective_rank(self) -> int:
        """Severity rank used for gating and counting.

        The maximum of the explicit label rank and the CVSS-derived rank, so a
        finding labelled 'Unknown' but carrying a high CVSS is not under-rated.
        If neither signal is present, the category floor applies so a finding is
        never silently treated as informational.
        """
        ranks = [r for r in (label_rank(self.severity), cvss_rank(self.cvss))
                 if r is not None]
        return max(ranks) if ranks else self.floor

    @property
    def band(self) -> str:
        return RANK_TO_BAND[self.effective_rank]


# --------------------------------------------------------------------------- #
# IaC / Secrets / Container (Veracode CLI JSON)
# --------------------------------------------------------------------------- #
def _cvss_from_match(vuln: Dict[str, Any]) -> Optional[float]:
    for c in (vuln.get("cvss") or []):
        metrics = c.get("metrics") or {}
        base = metrics.get("baseScore")
        if base is not None:
            try:
                return float(base)
            except (TypeError, ValueError):
                return None
    return None


def parse_iac(data: Any) -> List[Finding]:
    if not isinstance(data, dict):
        raise GateError("IaC results are not a JSON object.")
    findings: List[Finding] = []

    vulns = data.get("vulnerabilities") or {}
    for m in vulns.get("matches") or []:
        v = m.get("vulnerability") or {}
        art = m.get("artifact") or {}
        score = _cvss_from_match(v)
        loc = f"{art.get('name', '')} {art.get('version', '')}".strip()
        findings.append(Finding(
            "Vulnerability", v.get("severity"), v.get("id"),
            v.get("description") or v.get("id"), loc, score, FLOOR_DEFAULT))

    for s in data.get("secrets") or []:
        line = s.get("StartLine") or s.get("startLine")
        target = s.get("Target") or s.get("target") or ""
        loc = target if not line else f"{target}:{line}"
        findings.append(Finding(
            "Secret",
            s.get("Severity") or s.get("severity"),
            s.get("RuleID") or s.get("ruleID"),
            s.get("Title") or s.get("RuleID") or s.get("Category") or "Exposed secret",
            loc, None, FLOOR_SECRET,
            file=clean_path(target), line=line if isinstance(line, int) else None))

    for c in data.get("configs") or []:
        if str(c.get("Status", "FAIL")).upper() == "PASS":
            continue
        cause = c.get("CauseMetadata") or {}
        provider = cause.get("Provider", "")
        target = c.get("Target", "")
        start = cause.get("StartLine")
        loc = target if provider in ("", target) else f"{provider}: {target}"
        findings.append(Finding(
            "Misconfiguration", c.get("Severity") or c.get("severity"),
            c.get("ID"), c.get("Title") or c.get("Message"), loc, None, FLOOR_DEFAULT,
            file=clean_path(target),
            line=start if isinstance(start, int) else None))

    return findings


# --------------------------------------------------------------------------- #
# SCA (agent-based) - JSON report
# --------------------------------------------------------------------------- #
def _resolve_library(data: Dict[str, Any], ref: str) -> str:
    try:
        parts = ref.strip("/").split("/")
        ridx = int(parts[parts.index("records") + 1])
        lidx = int(parts[parts.index("libraries") + 1])
        lib = data["records"][ridx]["libraries"][lidx]
        return lib.get("name") or lib.get("coordinate1") or ""
    except (ValueError, KeyError, IndexError, TypeError):
        return ""


def parse_sca_json(data: Any) -> List[Finding]:
    if not isinstance(data, dict):
        raise GateError("SCA results are not a JSON object.")
    findings: List[Finding] = []
    for record in data.get("records") or []:
        for v in record.get("vulnerabilities") or []:
            score = v.get("cvss3Score")
            if score is None:
                score = v.get("cvssScore")
            libname = ""
            for lib in (v.get("libraries") or []):
                ref = (lib.get("_links") or {}).get("ref", "")
                libname = _resolve_library(data, ref) or libname
            findings.append(Finding(
                "Vulnerability", cvss_to_label(score),
                v.get("cve") or v.get("title"), v.get("title"), libname, score))
    return findings


# --------------------------------------------------------------------------- #
# SCA (agent-based) - text report (scaResults.txt)
# --------------------------------------------------------------------------- #
ISSUE_ROW = re.compile(
    r"^\s*(\d{6,})\s+"
    r"(Vulnerability|Outdated Library)\s+"
    r"(\d+(?:\.\d+)?)\s+"
    r"(.*?)\s{2,}"
    r"(\S.*\S)\s*$"
)
SUMMARY_ROW = re.compile(
    r"^\s*(Critical|High|Medium|Low)\s+Risk\s+Vulnerabilities\s+(\d+)\s*$",
    re.IGNORECASE,
)


def parse_sca_summary(text: str) -> Optional[int]:
    """Total vulnerabilities reported in the agent summary, or None if absent."""
    total = 0
    seen = False
    for line in text.splitlines():
        m = SUMMARY_ROW.match(line)
        if m:
            seen = True
            total += int(m.group(2))
    return total if seen else None


def parse_sca_text(text: str, include_outdated: bool = False) -> List[Finding]:
    findings: List[Finding] = []
    in_issues = False
    for line in text.splitlines():
        if line.strip().startswith("Issue ID") and "Severity" in line:
            in_issues = True
            continue
        if not in_issues:
            continue
        if line.strip().startswith("Full Report Details"):
            break
        m = ISSUE_ROW.match(line)
        if not m:
            continue
        issue_id, itype, cvss, desc, lib = m.groups()
        if itype == "Outdated Library" and not include_outdated:
            continue
        findings.append(Finding(
            "Vulnerability" if itype == "Vulnerability" else "Outdated Library",
            cvss_to_label(cvss), issue_id, desc.strip(), lib.strip(), float(cvss)))
    return findings


# --------------------------------------------------------------------------- #
# Pipeline (Veracode static pipeline scan) - results.json / filtered_results.json
# --------------------------------------------------------------------------- #
# Veracode SAST severity scale (numeric) -> our band.
# 5 Very High, 4 High, 3 Medium, 2 Low, 1 Very Low, 0 Informational.
PIPELINE_SEVERITY = {5: "critical", 4: "high", 3: "medium", 2: "low",
                     1: "low", 0: "info"}


def parse_pipeline(data: Any) -> List[Finding]:
    if not isinstance(data, dict):
        raise GateError("Pipeline results are not a JSON object.")
    findings: List[Finding] = []
    for f in data.get("findings") or []:
        try:
            band = PIPELINE_SEVERITY.get(int(f.get("severity")))
        except (TypeError, ValueError):
            band = None
        src = (f.get("files") or {}).get("source_file") or {}
        rel = clean_path(src.get("file", ""))
        try:
            line = int(src.get("line")) if src.get("line") else None
        except (TypeError, ValueError):
            line = None
        loc = (rel + (f":{line}" if line else "")) if rel else ""
        cwe = f.get("cwe_id")
        ident = f"CWE-{cwe}" if cwe not in (None, "") else (
            f.get("issue_type_id") or str(f.get("issue_id") or ""))
        title = f.get("issue_type") or f.get("display_text") or f.get("title")
        findings.append(Finding("Flaw", band, ident, title, loc, None,
                                FLOOR_DEFAULT, file=rel, line=line))
    return findings


# --------------------------------------------------------------------------- #
# Threshold handling
# --------------------------------------------------------------------------- #
class Threshold:
    """A validated gate threshold: either a numeric CVSS cut or a label rank."""

    def __init__(self, raw: str) -> None:
        self.raw = str(raw).strip()
        self.numeric: Optional[float] = None
        key = self.raw.lower()
        if key in SIGNAL_RANK:
            self.rank = SIGNAL_RANK[key]
            return
        try:
            value = float(self.raw)
        except ValueError:
            raise GateError(
                f"Invalid threshold '{raw}'. Use one of "
                f"{sorted(set(SIGNAL_RANK))} or a CVSS number in [0, 10].")
        if value != value or value < 0.0 or value > 10.0:
            raise GateError(
                f"Invalid threshold '{raw}'. A numeric threshold must be a "
                f"finite value in [0, 10].")
        self.numeric = value
        self.rank = SIGNAL_RANK[cvss_to_label(value)]

    def gates(self, finding: Finding) -> bool:
        if self.numeric is not None and finding.cvss is not None:
            # Exact CVSS comparison when the finding carries a score.
            try:
                return float(finding.cvss) >= self.numeric
            except (TypeError, ValueError):
                pass
        # Label thresholds, and numeric thresholds against findings with no
        # usable score (misconfigurations, secrets), use the band/rank.
        return finding.effective_rank >= self.rank


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
SCAN_LABEL = {
    "sca": "Software Composition Analysis",
    "iac": "IaC & Secrets",
    "pipeline": "Static Analysis (Pipeline Scan)",
}


def _finding_row(f: "Finding") -> str:
    sev = f"{BAND_DOT.get(f.band, '')} {f.band.capitalize()}"
    if f.cvss is not None:
        sev += f" ({f.cvss})"
    return (f"| {sev} | {sanitize(f.category, 20)} | {finding_id_cell(f)} | "
            f"{sanitize(f.title, 100)} | {finding_location_cell(f)} |")


def _findings_table(findings: Sequence["Finding"]) -> List[str]:
    rows = ["| Severity | Type | ID | Finding | Location |",
            "|:--|:--|:--|:--|:--|"]
    rows += [_finding_row(f) for f in findings]
    return rows


def _rows_within_budget(rows: Sequence[str], budget: int) -> Tuple[List[str], int]:
    """Return as many leading rows as fit in `budget` characters, and the count."""
    kept: List[str] = []
    used = 0
    for r in rows:
        if used + len(r) + 1 > budget:
            break
        kept.append(r)
        used += len(r) + 1
    return kept, len(kept)


# GitHub hard limit for a comment body / check-run output is 65536 chars.
GH_TEXT_LIMIT = 65536


def extract_report_url(raw: str) -> Optional[str]:
    """Pull the Veracode platform report URL out of a text report, if present."""
    m = re.search(r"https://[^\s\"']*analysiscenter\.veracode\.com/[^\s\"']+",
                  raw or "")
    return m.group(0) if m else None


def _counts_table(findings: Sequence["Finding"]) -> Tuple[List[str], Dict[str, int]]:
    counts = {b: 0 for b in BANDS}
    for f in findings:
        counts[f.band] += 1
    rows = [
        "| " + " | ".join(f"{BAND_DOT[b]} {b.capitalize()}" for b in BANDS)
        + " | Total |",
        "|:--:|:--:|:--:|:--:|:--:|:--:|",
        "| " + " | ".join(str(counts[b]) for b in BANDS)
        + f" | **{len(findings)}** |",
    ]
    return rows, counts


def build_report(findings: Sequence[Finding], threshold: Threshold,
                 mode: str) -> Tuple[str, int]:
    gating = sorted((f for f in findings if threshold.gates(f)),
                    key=lambda x: -x.effective_rank)
    label = SCAN_LABEL.get(mode, mode.upper())
    verdict = "FAILED" if gating else "PASSED"

    lines = [f"## Veracode {label} severity gate \u2014 {verdict}", "",
             f"Threshold **{threshold.raw}** (fail at this level or higher) \u00b7 "
             f"{len(findings)} finding(s) \u00b7 {len(gating)} at or above threshold",
             ""]
    counts_rows, _ = _counts_table(findings)
    lines += counts_rows
    lines.append("")

    if gating:
        lines.append(f"### {len(gating)} finding(s) at or above threshold")
        lines.append("")
        header = ["| Severity | Type | ID | Finding | Location |",
                  "|:--|:--|:--|:--|:--|"]
        all_rows = [_finding_row(f) for f in gating[:MAX_DETAIL_ROWS]]
        # Keep the whole report comfortably under GitHub's text limit.
        budget = GH_TEXT_LIMIT - len("\n".join(lines)) - 2000
        kept, shown = _rows_within_budget(all_rows, budget)
        lines += header + kept
        if shown < len(gating):
            lines.append("")
            lines.append(f"_Showing the {shown} highest-severity of "
                         f"{len(gating)} findings. See the run or full report "
                         f"for the rest._")
    else:
        lines.append("No findings at or above the threshold.")
    lines.append("")
    return "\n".join(lines), len(gating)


def emit(report: str) -> None:
    print(report)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        try:
            with open(summary, "a", encoding="utf-8") as fh:
                fh.write(report + "\n")
        except OSError as exc:  # never let summary I/O change the gate verdict
            print(f"::warning::Could not write job summary: {exc}")


# --------------------------------------------------------------------------- #
# Pull request scan-summary comment (optional, best-effort)
# --------------------------------------------------------------------------- #
# Each scan keeps its OWN sticky comment, identified by a per-scan marker. A
# scan only ever reads and writes its own comment, so the three scans
# (pipeline, sca, iac) never touch a shared body and cannot clobber or block one
# another, even when they run concurrently as separate workflows.
SECTION_TITLES = SCAN_LABEL  # alias: same scan labels


def _comment_marker(sid: str) -> str:
    return f"<!-- veracode-scan-summary:{sid} -->"


def build_comment_section(sid: str, findings: Sequence[Finding],
                          threshold: "Threshold", gated: int,
                          run_url: Optional[str],
                          report_url: Optional[str] = None) -> str:
    label = SCAN_LABEL.get(sid, sid)
    badge = "\u2705 Passed" if gated == 0 else "\u274c Failed"
    counts_rows, _ = _counts_table(findings)

    head = [
        f"## Veracode \u2014 {label}",
        "",
        f"> **{badge}** against threshold `{threshold.raw}`  ",
        f"> {len(findings)} finding(s) total \u00b7 **{gated}** at or above threshold",
        "",
    ] + counts_rows + [""]

    links = []
    if report_url:
        links.append(f'<a href="{report_url}">Full report</a>')
    if run_url:
        links.append(f'<a href="{run_url}">View run</a>')
    footer = ("<sub>Automated by the Veracode severity gate"
              + (" \u00b7 " + " \u00b7 ".join(links) if links else "") + "</sub>")

    if not gated:
        return "\n".join(head + [footer])

    gating = sorted((f for f in findings if threshold.gates(f)),
                    key=lambda x: -x.effective_rank)
    open_block = [
        "<details>",
        "<summary><b>View findings at or above threshold</b></summary>",
        "",
        "| Severity | Type | ID | Finding | Location |",
        "|:--|:--|:--|:--|:--|",
    ]
    close_note_reserve = 240  # room for the "showing N of M" note + close tags
    fixed = (len("\n".join(head)) + 1 + len("\n".join(open_block)) + 1
             + len("</details>") + 1 + len(footer) + 1 + close_note_reserve)
    budget = GH_TEXT_LIMIT - len(_comment_marker(sid)) - 8 - fixed

    all_rows = [_finding_row(f) for f in gating]
    kept, shown = _rows_within_budget(all_rows, max(budget, 0))

    lines = head + open_block + kept
    if shown < len(gating):
        lines.append("")
        tail = "See the full report for the complete list." if report_url \
            else "See the run for the complete list."
        lines.append(f"_Showing the {shown} highest-severity of {len(gating)} "
                     f"findings (GitHub comment size limit). {tail}_")
    lines.append("</details>")
    lines.append("")
    lines.append(footer)
    return "\n".join(lines)


def _comment_body(sid: str, section_md: str) -> str:
    return f"{_comment_marker(sid)}\n{section_md}"


def _gh_request(api: str, method: str, path: str, token: str,
                payload: Optional[dict] = None):
    import urllib.request
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(api.rstrip("/") + path, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read().decode("utf-8") or "null"
        return resp.status, json.loads(raw)


def _find_comment(api: str, repo: str, pr: str, token: str, marker: str):
    page = 1
    while page <= 10:
        _, items = _gh_request(
            api, "GET",
            f"/repos/{repo}/issues/{pr}/comments?per_page=100&page={page}", token)
        if not items:
            break
        for c in items:
            if marker in (c.get("body") or ""):
                return c
        if len(items) < 100:
            break
        page += 1
    return None


def _resolve_pr_number(api: str, repo: str, sha: str, token: str) -> Optional[str]:
    """Find the PR number for a commit SHA, so each scan can resolve the PR on
    its own even when the dispatch does not forward pr_number."""
    try:
        _, items = _gh_request(
            api, "GET", f"/repos/{repo}/commits/{sha}/pulls", token)
    except Exception:  # noqa: BLE001 - best-effort
        return None
    for pr in items or []:
        if pr.get("state") == "open" and pr.get("number"):
            return str(pr["number"])
    if items and items[0].get("number"):
        return str(items[0]["number"])
    return None


def upsert_pr_comment(sid: str, section_md: str) -> bool:
    """Create or update this scan's own sticky PR comment.

    Best-effort: any failure prints a warning and returns False without
    affecting the gate verdict. Reads GH_TOKEN, SCAN_REPO, PR_NUMBER and
    optional GITHUB_API_URL from the environment.
    """
    import time
    import random
    import urllib.error

    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("SCAN_REPO")
    pr = os.environ.get("PR_NUMBER")
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    if not (token and repo):
        print("::warning::PR comment skipped: GH_TOKEN/SCAN_REPO not set.")
        return False
    if not (pr and str(pr).strip().isdigit()):
        # pr_number was not forwarded for this scan; resolve it from the SHA so
        # this scan can still comment independently of the others.
        sha = os.environ.get("HEAD_SHA")
        resolved = _resolve_pr_number(api, repo, sha, token) if sha else None
        if not resolved:
            print("::warning::PR comment skipped: no PR_NUMBER and could not "
                  "resolve a PR from the commit (this run may not be a pull request).")
            return False
        pr = resolved
        print(f"Resolved PR #{pr} from the commit SHA.")

    marker = _comment_marker(sid)
    body = _comment_body(sid, section_md)
    for attempt in range(4):
        try:
            existing = _find_comment(api, repo, pr, token, marker)
            if existing is None:
                _gh_request(api, "POST",
                            f"/repos/{repo}/issues/{pr}/comments", token,
                            {"body": body})
            else:
                _gh_request(api, "PATCH",
                            f"/repos/{repo}/issues/comments/{existing['id']}",
                            token, {"body": body})
            print(f"Updated PR comment for '{sid}'.")
            return True
        except urllib.error.HTTPError as exc:
            if attempt < 3 and exc.code in (403, 409, 422, 500, 502, 503):
                time.sleep(0.4 + random.random() * 0.8)
                continue
            print(f"::warning::Could not update PR comment (HTTP {exc.code}); "
                  f"continuing.")
            return False
        except Exception as exc:  # noqa: BLE001 - best-effort, never fatal
            if attempt < 3:
                time.sleep(0.4 + random.random() * 0.8)
                continue
            print(f"::warning::Could not update PR comment ({exc}); continuing.")
            return False
    return False


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #
def load_findings(mode: str, raw: str, include_outdated: bool) -> List[Finding]:
    if mode == "iac":
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise GateError(f"IaC results are not valid JSON: {exc}.")
        return parse_iac(data)

    if mode == "pipeline":
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise GateError(f"Pipeline results are not valid JSON: {exc}.")
        return parse_pipeline(data)

    stripped = raw.lstrip()
    if stripped[:1] in ("{", "["):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise GateError(f"SCA results are not valid JSON: {exc}.")
        return parse_sca_json(data)

    findings = parse_sca_text(raw, include_outdated=include_outdated)
    reported = parse_sca_summary(raw)
    if reported is not None:
        parsed_vulns = sum(1 for f in findings if f.category == "Vulnerability")
        if parsed_vulns < reported:
            raise GateError(
                f"SCA text report reconciliation failed: parsed {parsed_vulns} "
                f"vulnerability rows but the summary reports {reported}. The "
                f"report format may have changed. Failing closed to avoid "
                f"under-reporting; enable issues to gate on the JSON report.")
    return findings


def run(args: argparse.Namespace) -> int:
    threshold = Threshold(args.threshold)  # validated up front

    if not os.path.exists(args.input):
        msg = f"Results file not found: {args.input}."
        if args.allow_missing:
            print(f"::warning::{msg} Treating as no findings (--allow-missing).")
            return EXIT_PASS
        raise GateError(f"{msg} The scan may not have run. Failing closed; pass "
                        f"--allow-missing to treat this as a pass.")

    with open(args.input, "r", encoding="utf-8", errors="replace") as fh:
        raw = fh.read()
    if not raw.strip():
        raise GateError(f"Results file is empty: {args.input}. Failing closed.")

    findings = load_findings(args.mode, raw, args.include_outdated)
    try:
        correct_file_cases(findings)  # best-effort: fix path case for links
    except Exception:  # noqa: BLE001 - never let link polish affect the gate
        pass
    report, gated = build_report(findings, threshold, args.mode)
    emit(report)

    if args.pr_comment:
        section = build_comment_section(
            args.pr_comment, findings, threshold, gated,
            os.environ.get("RUN_URL"), extract_report_url(raw))
        upsert_pr_comment(args.pr_comment, section)

    if gated and not args.warn_only:
        print(f"\n::error::Veracode {args.mode.upper()} gate failed: {gated} "
              f"finding(s) at or above '{threshold.raw}'.")
        return EXIT_GATED
    return EXIT_PASS


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Veracode severity gate")
    ap.add_argument("--mode", required=True, choices=["iac", "sca", "pipeline"])
    ap.add_argument("--input", required=True, help="Path to the results file")
    ap.add_argument("--threshold", default="medium",
                    help="critical|high|medium|low|info or a CVSS number in [0, 10]")
    ap.add_argument("--include-outdated", action="store_true",
                    help="SCA text mode: also gate on Outdated Library issues")
    ap.add_argument("--warn-only", action="store_true",
                    help="Report but never fail the build")
    ap.add_argument("--allow-missing", action="store_true",
                    help="Treat a missing input file as a pass instead of failing closed")
    ap.add_argument("--pr-comment", choices=["pipeline", "sca", "iac"], default=None,
                    help="Upsert this scan's section in the sticky PR scan-summary "
                         "comment. Reads GH_TOKEN, SCAN_REPO, PR_NUMBER and optional "
                         "RUN_URL/GITHUB_API_URL from the environment.")
    return ap


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except GateError as exc:
        print(f"::error::Veracode {args.mode.upper()} gate could not evaluate: {exc}")
        if getattr(args, "pr_comment", None):
            sid = args.pr_comment
            section = (f"### {SECTION_TITLES.get(sid, sid)}: "
                       f"\u26a0\ufe0f **Could not evaluate**\n{sanitize(str(exc), 300)}")
            try:
                upsert_pr_comment(sid, section)
            except Exception:  # noqa: BLE001 - never let comment I/O mask the error
                pass
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
